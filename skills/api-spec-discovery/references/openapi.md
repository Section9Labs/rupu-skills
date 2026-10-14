# OpenAPI / Swagger Parsing Reference

How `scripts/parse_spec.py` interprets the two format generations, and what to
check by hand when the parser flags something.

## Format detection

| Marker | Format |
|---|---|
| `"swagger": "2.0"` | Swagger / OpenAPI 2.0 |
| `"openapi": "3.0.x"` | OpenAPI 3.0 |
| `"openapi": "3.1.x"` | OpenAPI 3.1 (full JSON Schema 2020-12 in schemas) |

## 2.0 ↔ 3.x field map

| Concept | 2.0 | 3.x |
|---|---|---|
| Base URL | `schemes[]` + `host` + `basePath` | `servers[].url` (may be relative, may have `{variables}`) |
| Schemas | `definitions.*` | `components.schemas.*` |
| Request body | parameter with `in: body` (one max, has `schema`) | `requestBody.content.<media-type>.schema` |
| Form body | parameters with `in: formData` + `consumes` | `requestBody.content` with `application/x-www-form-urlencoded` / `multipart/form-data` |
| Media types | top-level/op `consumes` / `produces` | per-operation `content` keys |
| Auth schemes | `securityDefinitions.*` | `components.securitySchemes.*` (adds `http: bearer`, `openIdConnect`) |
| Responses | `responses.<code>.schema` | `responses.<code>.content.<mt>.schema` |
| Parameters | `type`/`format` directly on the param | `schema` object on the param |
| Reusable params/responses | `parameters.*`, `responses.*` (root) | under `components.*` |

Base URL resolution:

- 2.0: `schemes[0] + "://" + host + basePath`. If `host` is absent the spec is
  relative to wherever you fetched it — pass `--base`.
- 3.x: `servers[0].url`, with each `{var}` replaced by
  `variables.<var>.default`. A relative `url` (`"/api/v3"`) must be joined to
  the origin you fetched from — pass `--base https://api.example.com/api/v3`.
- Check `servers[1:]` manually: staging/admin servers listed there are
  additional `api:service` assets (e.g. `https://staging.example.com`).
  Path-item- and operation-level `servers` overrides exist in 3.x; grep the
  raw spec for `"servers"` outside the root to catch them.

## $ref resolution

`$ref` values are JSON Pointers. The parser resolves **local** refs only
(`#/components/schemas/Order`): split on `/`, unescape `~1`→`/` and `~0`→`~`,
walk the document, guard against cycles (a self-referential schema yields `{}`
at the cycle point). Non-local refs — `./models/order.json#/Order`,
`https://example.net/common.yaml#/Thing` — are recorded in `unresolved_refs`
and never fetched. To handle a multi-file spec, bundle it first (e.g.
`redocly bundle` or `swagger-cli bundle` if available on the box) and re-run
the parser on the bundled output.

In 3.1, `$ref` may sit alongside sibling keywords (JSON Schema semantics);
the parser follows the ref and ignores siblings — review manually if a flagged
schema matters.

## Synthesizing a body from a schema

Order of precedence per schema node:

1. `example` → use verbatim; then `default`; then `examples[0]`; then `enum[0]`.
2. `allOf` → synthesize each branch, merge dict results.
3. `oneOf` / `anyOf` → first branch (fuzzing skills should iterate the rest).
4. By `type` (3.1 type arrays: first non-`"null"` entry):
   - `object` → every property synthesized (required and optional — send the
     full shape; mass-assignment testing prunes later).
   - `array` → one synthesized item.
   - `string` → by `format`: `date-time`→`2024-01-01T00:00:00Z`,
     `email`→`user@example.com`, `uuid`→`00000000-0000-4000-8000-000000000000`,
     `uri`→`https://example.com/`, `ipv4`→`192.0.2.10`, `byte`→base64,
     else `"string"`.
   - `integer`/`number` → `minimum` or `1`; `boolean` → `true`.
5. Recursion capped at depth 10.

`readOnly: true` properties are still emitted — sending them is exactly the
mass-assignment probe (API3). `writeOnly` likewise.

## Security

Effective requirement = operation `security` if the key is present (even as
`[]`), else root `security`. Semantics:

- Missing everywhere, or explicit `security: []` → **unauthenticated
  operation** → `no_auth: true`. These are the first probe targets (API2) and
  often undocumented-on-purpose admin/debug routes (API9).
- A requirement list is OR-of-AND: `[{"a":[]},{"b":[]}]` means scheme a OR b;
  `[{"a":[],"b":[]}]` means a AND b.

Scheme descriptor fields the parser emits: `type` (`apiKey`, `http`, `oauth2`,
`openIdConnect`, 2.0 `basic`), `scheme` (`bearer`/`basic` for `http`), `in` +
`param` (for `apiKey`: header/query/cookie and its name), `scopes`. Flag
`apiKey` with `in: query` (keys in URLs/logs) and operations whose OAuth scopes
look broader than the action requires.

## Hand-off hints

- Group records by `resource` — matches how the `work-units` skill splits the
  spec per API resource.
- `path_params` with names like `id`, `userId`, `{orderId}` on
  GET/PUT/DELETE → BOLA candidates (API1).
- Compare `tags`/`description` claims ("admin only", "internal") against the
  declared security — mismatches are findings waiting for verification.
