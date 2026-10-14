# Postman Collection v2.1 → Request Set

How `scripts/parse_spec.py` maps a Postman export onto normalized records, and
what to mine from collections by hand.

## Detection and top-level structure

A v2.x collection is JSON with `info.schema` containing
`.../json/collection/v2.1.0/...` (or `v2.0.0`). Shape:

```json
{
  "info": {"name": "...", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "auth": { ... },               // collection-level default auth
  "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
  "item": [
    {"name": "Orders", "item": [            // folder (nests arbitrarily)
      {"name": "Create order",
       "request": {"method": "POST", "url": {...}, "header": [...],
                    "body": {...}, "auth": {...}},
       "response": [ ... saved example responses ... ]}
    ]}
  ]
}
```

The parser walks the `item[]` tree recursively; every node with `request` is
one operation (folder path becomes `operation_id` prefix and `tags[0]`).

## URL object

`request.url` is a string or:

```json
{"raw": "{{baseUrl}}/v1/orders/:orderId?expand=items",
 "protocol": "https", "host": ["api", "example", "com"], "port": "8443",
 "path": ["v1", "orders", ":orderId"],
 "query": [{"key": "expand", "value": "items", "disabled": false}],
 "variable": [{"key": "orderId", "value": "42"}]}
```

Mapping: `raw` (minus query string) wins when present, else
`protocol://host:port/path` is assembled. `:name` segments are path params,
with example values from `url.variable[]`. `query[]` entries (skip
`disabled: true`) become `query_params`. `url_example` has `:params`
substituted.

## Variables and environments

`{{var}}` placeholders are substituted from, in order: collection
`variable[]`, then an environment export passed with `--env` (shape:
`{"values": [{"key","value","enabled"}]}`), then `--base` for
`{{baseUrl}}`/`{{base_url}}`. Unresolved `{{...}}` names are surfaced in
`unresolved_refs` — supply them or edit the request set.

**Always hunt the environment files.** `*.postman_environment.json` committed
next to a collection routinely contains live tokens, API keys, and internal
hostnames (`{{adminUrl}}`, `{{internalHost}}`). Each distinct host in the
variables is a separate `api:service` asset. Saved example `response[]` blocks
also leak real IDs, tokens, and internal field names — read them.

## Body modes

| `body.mode` | Mapping |
|---|---|
| `raw` | JSON-parse if possible → `body`; `options.raw.language` picks content type |
| `urlencoded` | key/value dict, `application/x-www-form-urlencoded` |
| `formdata` | key/value dict (file entries noted via `src`), `multipart/form-data` |
| `graphql` | `{"query","variables"}` body, `application/json` |
| `file` | placeholder `<file: src>`, `application/octet-stream` |

## Auth

`request.auth` overrides collection `auth`. `type` values: `noauth`, `basic`,
`bearer`, `apikey`, `oauth1`, `oauth2`, `awsv4`, `digest`, `hawk`, `ntlm`.
Parameters live under `auth.<type>` as `[{"key","value"}]` — e.g.
`auth.bearer[0]` with `key: "token"` (the value may be a literal token: harvest
it). `type: noauth` or absent auth at both levels → `no_auth: true` in the
record.

Note: Postman auth reflects what the *client* sends, not what the server
*requires* — a `noauth` request is a lead, confirmed only by replaying it.
Also check `event[]` pre-request scripts (`exec` arrays of JS source): they
often compute HMAC signatures or fetch tokens, revealing the real auth
protocol you must reimplement to drive the API.

## Hand-off

Run `python3 scripts/parse_spec.py collection.json --env env.json -o
reports/api-request-set.json`; the output is format-identical to the OpenAPI
path, so all downstream consumers (ffuf/nuclei/arjun drivers, rupu wiring in
`references/rupu.md`) work unchanged. For the `work-units` split, either
convert the collection to a minimal OpenAPI paths document or dispatch units
grouped by the `resource` field of the request set.
