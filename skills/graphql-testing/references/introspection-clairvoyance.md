# Schema recovery — introspection, clairvoyance(next), InQL, graphql-path-enum

## The full introspection query

Always try this first, per auth level (anon / low / high) — many servers gate
introspection by role, and Hasura-style servers serve a *different schema per
role*:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name
    ofType { kind name ofType { kind name ofType { kind name
      ofType { kind name } } } } } } }
}
```

`scripts/introspect.py` sends exactly this. A minimal fallback that evades
some naive filters: `{__schema{types{name}}}`.

### Introspection-block bypasses to try before giving up

- **GET instead of POST**: `GET /graphql?query={__schema{types{name}}}` —
  some middlewares only inspect POST bodies.
- **Whitespace/newline after `__schema`**: regex-based blocks match
  `__schema{`; `{__schema\n{types{name}}}` or `{ __schema { ... } }` slips by.
- **Alternate content types**: `application/graphql` body (raw query, no JSON
  wrapper) if the server supports it.
- **Different endpoint path**: `/graphql` blocked but `/api/graphql` or the
  subscription/websocket endpoint not.
- **Older API versions**: `/v1/graphql` may predate the hardening.

## Reading the schema

From `__schema`:

- `queryType.name` / `mutationType.name` / `subscriptionType.name` → find
  those types in `types[]`; their `fields` are the operations.
- Each field's `args` with `type` (unwrap `ofType` chains; `NON_NULL` and
  `LIST` wrap the real named type) are the operation signature.
- `INPUT_OBJECT` types: expand `inputFields` — nested inputs hide the juicy
  arguments (`isAdmin`, `role`, `ownerId`).
- Grep type/field names for: `admin`, `internal`, `debug`, `token`, `secret`,
  `password`, `role`, `permission`, `impersonat`, `payment`, `invoice`.
- Deprecated fields (`isDeprecated: true`) often still resolve and are the
  least-audited code paths.

Visualize with GraphQL Voyager (paste the introspection JSON) to see type
cycles — cycles are your nested-DoS primitives.

## clairvoyance — blind introspection via field suggestions

When introspection is off but field suggestions are on ("Did you mean
`email`?"), the schema is recoverable by brute force. **Install the maintained
fork**: `pip install clairvoyancenext` (the original nikitastupin/clairvoyance
is stale; the fork keeps the same CLI).

```bash
clairvoyance https://api.example.com/graphql \
  -w wordlist.txt \
  -o schema.json \
  -H 'Authorization: Bearer eyJ...' \
  -H 'Cookie: session=abc' \
  -v
```

| Flag | Meaning |
|---|---|
| positional | endpoint URL |
| `-w file` | field-name wordlist (one per line). Without it, a bundled English wordlist is used — always supply a targeted one. |
| `-o schema.json` | output in introspection-JSON format (InQL/Voyager-compatible) |
| `-H 'Name: value'` | header, repeatable |
| `-i schema.json` | resume from / merge into a previous run |
| `-c N` | concurrent requests |
| `-m N` | max retries |
| `-p http://127.0.0.1:8080` | proxy (fork option; original lacked it) |
| `-v` / `-vv` | verbosity |

How it works: it sends queries containing wordlist candidates and wrong
subselections, then regex-parses the error strings — "Did you mean", "Cannot
query field X on type Y", "Field X of type Y must have a selection" — to learn
valid fields, their parent types, and their return types, iterating until the
graph stops growing.

**Coverage is partial and wordlist-bound.** Build the wordlist from:

- the app's JS bundles (`grep -ohrE '"[a-zA-Z_][a-zA-Z0-9_]{2,40}"' bundle.js`,
  plus GraphQL document literals shipped to the client — often whole queries),
- field names observed in HTTP history / mobile app traffic,
- the API's domain nouns (orders, invoices, users…) in camelCase variants,
- generic lists (SecLists `graphql.txt`, common-API-fields lists).

If suggestions are *also* disabled, clairvoyance is blind; fall back to
guessing operations directly from client-side GraphQL documents.

## graphql-path-enum

Given a recovered schema, enumerate how to *reach* a type — useful when the
interesting type isn't exposed as a top-level query:

```bash
graphql-path-enum -i schema.json -t User
# -> query.me -> User
# -> query.search -> SearchResult -> ... -> User
```

Each path is a candidate authorization bypass: the direct query may be
guarded while a nested path to the same type isn't.

## InQL (doyensec/inql)

- **Burp extension (v5)**: load from the BApp store. Point it at the endpoint
  or paste schema JSON; it builds a tree of operations, generates complete
  queries with placeholder arguments (point-and-click → Repeater), and its
  scanner flags common issues. Attacker-friendly even without introspection if
  you feed it the clairvoyance output.
- **Standalone CLI**:

```bash
inql -t https://api.example.com/graphql           # dump schema + generate queries
inql --schema-json-file schema.json               # offline, from recovered schema
```

Output is a directory of `.graphql`/`.txt` files, one generated request per
operation — exactly what you want for the per-operation authorization pass:
replay each file at every privilege level and diff the responses.
