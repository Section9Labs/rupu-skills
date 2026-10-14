# graphw00f and graphql-cop — flags, output, interpretation

## graphw00f (dolevf/graphw00f)

GraphQL engine fingerprinter. It sends a sequence of benign but malformed or
edge-case queries (bad operation names, duplicate fields, odd directives,
`queryy {}` typos) and matches the *error message shapes* against known engine
behaviors. No exploit traffic; the differentiator is how each implementation
complains.

### Flags

| Flag | Meaning |
|---|---|
| `-t URL` | Target. Base URL for `-d`, full endpoint URL for `-f` alone. |
| `-d` | Detect mode: probe the built-in endpoint wordlist (`/graphql`, `/api/graphql`, `/graphiql`, `/playground`, `/query`, `/console`, versioned variants, …) and confirm with `{__typename}`. |
| `-f` | Fingerprint mode: identify the engine. Combine `-d -f` to detect then fingerprint in one run. |
| `-w file.txt` | Custom endpoint wordlist for detection (one path per line). |
| `-o out.csv` | Append result row (url, engine, technology, url reference) to CSV. |
| `-H 'Header: value'` | Extra header; repeatable. Use for `Authorization`, custom API keys, cookies. |
| `-T seconds` | Request timeout (default 10). |
| `-p http://127.0.0.1:8080` | HTTP proxy (route through Burp to capture the probes). |
| `-r` | Do not follow redirects. |
| `-l` | List all fingerprintable engines and exit. |
| `-u` | User agent override (where supported by the installed version). |

### Typical runs

```bash
# detect endpoints on a host, then fingerprint whatever answers
python3 main.py -d -f -t https://api.example.com -o graphw00f.csv

# fingerprint a known endpoint behind auth, through Burp
python3 main.py -f -t https://api.example.com/graphql \
  -H 'Authorization: Bearer eyJ...' -p http://127.0.0.1:8080
```

### Output and the engine → defaults pivot

Output names the engine and links to its page in graphw00f's "GraphQL
Threat Matrix". That matrix is the point of fingerprinting — each engine has
different *defaults*, so the engine name predicts what graphql-cop will find
and which exploit paths are open:

| Engine | Introspection default | Field suggestions | Batch (array) | Notes |
|---|---|---|---|---|
| Apollo Server | on (off in prod mode since v4) | on | on | `tracing`/debug plugins leak resolver timings; CSRF-prevention off = form-POST CSRF |
| graphql-yoga | on | on | configurable | Apollo-compatible errors |
| Hasura | on (admin) | on | on | role-based schemas: re-introspect per `x-hasura-role`; admin secret in `x-hasura-admin-secret` |
| graphql-ruby | on | on | on | classic alias/duplication DoS target when `max_depth`/`max_complexity` unset |
| gqlgen (Go) | on | on | off | complexity limits opt-in |
| Hot Chocolate (.NET) | on | on | configurable | detailed errors in dev mode |
| AWS AppSync | on (per API auth) | custom errors | no | API key in `x-api-key`; errors are AppSync-specific |
| Graphene / Ariadne (Python) | on | on | varies | DoS protections are all opt-in middleware |
| Absinthe (Elixir) | on | on | off | complexity analysis opt-in |
| graphql-php / Lighthouse | on | on | on | Lighthouse ships rate limiting but not query cost by default |

Also check the engine against public CVE lists once identified (e.g. known
graphql-php, Hasura, and Apollo advisories) — the engine + version class is
your CVE search key.

## graphql-cop (dolevf/graphql-cop)

Fast misconfiguration auditor — a dozen checks in one run, pure Python.

### Flags

| Flag | Meaning |
|---|---|
| `-t URL` | Target GraphQL endpoint. |
| `-H '{"Authorization": "Bearer x", "Cookie": "s=1"}'` | Headers as a JSON dict. |
| `-o json` | JSON output (default is human text). Always use `json` for parsing. |
| `-x http://127.0.0.1:8080` | Proxy. Note: with graphql-cop, `-x` takes the proxy URL in recent versions; older versions used `--proxy`. Check `-h`. |
| `-T` | Route via Tor (expects local Tor socks). |
| `-f` | Force run even if endpoint doesn't self-identify as GraphQL. |
| `-e test_name` | Exclude specific tests. |
| `-l` | List all tests and exit. |
| `-d` | Debug mode (print requests). |

```bash
python3 graphql-cop.py -t https://api.example.com/graphql -o json \
  -H '{"Authorization": "Bearer eyJ..."}' > reports/graphql-cop.json
```

### Checks and what each result means for exploitation

JSON output is a list of objects: `{"result": true|false, "title": "...",
"description": "...", "impact": "...", "severity": "...", "curl_verify": "..."}`.
Each entry includes a `curl_verify` command — rerun it to confirm and to
capture the `http_exchange` evidence for the finding.

| Check | `result: true` means | Next move |
|---|---|---|
| Introspection | full schema dumpable | `scripts/introspect.py`, map everything |
| Introspection-based circular query | circular fragments in introspection → DoS | nested-DoS PoC (batching-dos.md) |
| Field suggestions | "Did you mean" leaks schema | clairvoyance will work |
| Array-based batching | JSON-array batching executes | batching bypass (batch_build.py `--mode array`) |
| Alias overloading | many aliases execute | OTP/login brute (batch_build.py `--mode alias`) |
| Field duplication | duplicated fields execute | duplication DoS PoC |
| Directive overloading | repeated directives execute | directive DoS PoC |
| GET method query support | queries over GET | CSRF vector; also cache-poisoning angle |
| Mutation over GET | state change via GET | high-value CSRF |
| POST urlencoded support | form-encoded accepted | no-preflight CSRF |
| GraphiQL / IDE | interactive console exposed | use it; finding on its own |
| Tracing / debug mode | resolver paths + timings leak | recon gold; report info disclosure |

Every `true` entry is at minimum an `api:endpoint` note; the DoS/batching/CSRF
entries become findings only after you demonstrate them (section 6 of
SKILL.md) — graphql-cop shows the door is unlocked, you still walk through it.
