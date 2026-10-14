# Spec → FUZZ templates

How `scripts/spec_to_ffuf.py` (and you, by hand) turn one normalized operation
from `api-spec-discovery` into concrete ffuf tasks.

## Input: the normalized request set

One JSON array, one record per operation. Accepted top-level shapes: a bare array,
or `{"operations":[...]}` / `{"requests":[...]}`. Fields the generator uses
(unknown fields are ignored):

```json
{
  "id": "getOrder",
  "method": "GET",
  "url": "https://api.example.com/v1/orders/{orderId}",
  "headers": {"Authorization": "Bearer eyJ..."},
  "path_params": [{"name": "orderId", "type": "integer", "example": 42}],
  "query_params": [{"name": "status", "type": "string", "example": "open"}],
  "content_type": "application/json",
  "body": {"qty": 1, "note": "x", "address": {"zip": "00000"}}
}
```

`url` may be absolute, or relative with a run-level `--base https://api.example.com`.

## Template rules per fuzz class

### path-segment (route discovery)
Collapse each operation URL to its directory bases (`/v1/`, `/v1/orders/`), dedupe
across operations, append `FUZZ`:

```
-u https://api.example.com/v1/FUZZ -w <routes-wordlist>:FUZZ -recursion -recursion-depth 2
```

One task per unique base, GET, `-mc all -fc 404 -ac`.

### path-id (object enumeration)
For each `{param}` in the path: replace *that* placeholder with `FUZZ`, replace
every *other* placeholder with its `example` (fallback `1`). Wordlist by declared
type: integers → generated `ids.txt` (0–1000 plus edge values `-1`,
`4294967296`, `0001`, `%00`), uuid/string → operator-supplied list of harvested ids.

```
GET /v1/users/{userId}/orders/{orderId}, fuzzing orderId:
-u https://api.example.com/v1/users/1/orders/FUZZ -w reports/ffuf/ids.txt:FUZZ
```

Harvest *real* ids from phase-1 responses and your own account first — a mixed
list of valid-foreign and invalid ids makes the status/size split obvious.

### param-name (hidden parameter discovery)
- GET/DELETE: append `?FUZZ=1` (or `&FUZZ=1` if the operation already has
  documented query params, which stay fixed at example values).
- JSON bodies: inject a new key — `-d '{"FUZZ":"1","qty":1}'`.

Wordlist: `burp-parameter-names.txt` (SecLists) or arjun's wordlist. Hand-off
note: `api-param-discovery` (arjun) does smart chunked name discovery; use ffuf
when you want name×value clusterbomb matrices or non-standard placements
(headers: `-H 'FUZZ: 1'`).

### param-value
Each documented query param in turn gets `FUZZ`, others pinned to examples:

```
-u 'https://api.example.com/v1/orders?status=FUZZ&limit=10' -w values.txt:FUZZ
```

`values.txt` ships type-boundary probes: `0`, `-1`, `9999999999`, `null`, `true`,
`false`, `""`, `"*"`, `"'"`, `"%27"`, `"../"`, `"{{7*7}}"` — anomaly bait, not full
injection payloads (that's `api-injection`'s job once a param reacts).

### body-field (JSON value fuzzing)
For every scalar leaf in the body skeleton, emit one template with that leaf's
value replaced by a **raw** `FUZZ` token (not quoted — quoting lives in the
wordlist so one list covers strings and numbers):

```json
body: {"qty": 1, "address": {"zip": "00000"}}
→ -d '{"qty": FUZZ, "address": {"zip": "00000"}}'      (leaf qty)
→ -d '{"qty": 1, "address": {"zip": FUZZ}}'            (leaf address.zip)
```

Always send `-H 'Content-Type: application/json'`. For integer fields also try the
type-confusion entries in `values.txt` (string where int expected, arrays `[1]`,
objects `{"$gt":""}` for NoSQL-backed APIs).

### method (verb tampering)
One task per unique route (placeholders pinned to examples):

```
-X FUZZ -w reports/ffuf/methods.txt:FUZZ -u https://api.example.com/v1/orders/42
```

`methods.txt`: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, plus junk
(`FOO`) to baseline the 405/501 shape. Filter the dominant 405: `-fc 405`.
A DELETE answering 200 on a documented GET-only route, or a PATCH bypassing a
POST-only auth check, is a direct finding candidate.

## Multi-axis combos worth generating by hand

```
# every harvested user id against every per-user route (clusterbomb)
ffuf -u https://api.example.com/v1/R/UID -w user-routes.txt:R -w ids.txt:UID \
  -mode clusterbomb -mc all -fc 404 -ac

# token_i paired with foreign id_i (pitchfork) — authz matrix seed
ffuf -u https://api.example.com/v1/orders/OID -H 'Authorization: Bearer TOK' \
  -w foreign-order-ids.txt:OID -w victim-tokens.txt:TOK -mode pitchfork
```

## Reading the matrix

For each task, the parser clusters results by (status, length). Interpretation:

| Pattern | Meaning | Next |
|---|---|---|
| path-id: wall of 403, one 200 | accessible foreign object | `api-authorization` (confirm with 2nd identity) |
| path-id: 404s, cluster of 200s | valid id range mapped | enumerate fully, mark endpoints |
| param-name: one name shifts size | live hidden parameter | `api-param-discovery` / `api-injection` |
| param-value/body-field: 500 or `-mt` outlier | parser/injection suspect | `api-injection` with `-od` evidence |
| method: non-405 on undocumented verb | verb tampering | manual verify, then finding |
| body-field: 200 where 422 expected | missing validation / mass assignment lead | try `role`, `is_admin`, `price` keys via param-name on body |
