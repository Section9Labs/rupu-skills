---
name: api-spec-discovery
description: Discover an API's machine-readable definition (OpenAPI/Swagger 2.0 and 3.x, Postman v2.1 collections, GraphQL schema, OIDC/OAuth well-known metadata), parse it with stdlib-only tooling, and normalize every operation into a ready-to-send request set plus rupu work units. Use as phase 1 of the api-testing flow whenever you have an API base URL but no endpoint inventory.
license: Apache-2.0
compatibility: Requires Python 3.8+ and outbound HTTP to the target; yq optional for YAML specs
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Spec Discovery

Turn a bare API base URL into: (1) the service's own definition document, (2) a
normalized request set (one JSON record per operation with a ready-to-send
template), and (3) rupu-ingestible work units + coverage assets. Every other
skill in the api-testing pack reads the artifacts this skill writes under
`reports/`.

## Workflow

### 1. Locate the definition

Probe the common spec locations first — most APIs ship one:

```
python3 scripts/fetch_spec.py https://api.example.com \
    -H "Authorization: Bearer TOKEN" \
    --save reports/spec-raw.json -o reports/spec-probe.json
```

The script probes `/openapi.json`, `/openapi.yaml`, `/swagger.json`,
`/swagger.yaml`, `/v2/api-docs`, `/v3/api-docs` (springdoc),
`/v3/api-docs/swagger-config`, `/api-docs`, `/swagger/v1/swagger.json`,
`/swagger-ui.html`, `/swagger-ui/`, `/docs` + `/redoc` + `/openapi.json`
(FastAPI), `/api-json` (NestJS), `/.well-known/openid-configuration`,
`/.well-known/oauth-authorization-server`, `/graphql`, `/graphql/schema`, and
more. It classifies each hit (OpenAPI 2.0/3.x, Postman, swagger-config,
Swagger-UI HTML page, OIDC metadata, GraphQL endpoint, YAML spec) and saves the
first real spec body with `--save`.

Interpret the output:

- **Direct spec hit** (`openapi-3.x`, `swagger-2.0`, `postman-collection`) —
  proceed to step 3.
- **`swagger-ui` / `redoc` page only** — the script extracts the `url:` /
  `urls: [...]` / `spec-url=` values the UI loads; fetch those next. springdoc's
  `/v3/api-docs/swagger-config` lists every group under `urls[]` — fetch each.
- **`openapi-yaml`** — convert before parsing: `yq -o=json spec.yaml > spec.json`
  (the stdlib has no YAML loader; never use a code-executing one).
- **`oidc-discovery`** — harvest `token_endpoint`, `authorization_endpoint`,
  `jwks_uri`, `registration_endpoint` as additional endpoints; these feed the
  auth-testing skills.
- **`graphql-endpoint`** — run introspection (recipe in
  `references/discovery.md`) and treat the schema as the spec.
- **Nothing hit** — scrape HTML and JS bundles for embedded spec URLs,
  `basePath`, `SwaggerUIBundle({url:...})` / Redoc init, and hardcoded API
  paths; check Postman public documenter links; brute-force spec paths with a
  wordlist. Full playbook: `references/discovery.md`.

### 2. Acquire and sanity-check

Fetch the chosen document with full fidelity and keep the raw copy:

```
curl -skL -A 'Mozilla/5.0' -H 'Accept: application/json' \
     https://api.example.com/v3/api-docs -o reports/spec-raw.json
```

Confirm the format marker: `"swagger": "2.0"` vs `"openapi": "3.0.x"/"3.1.x"`
vs Postman `info.schema` containing `collection/v2.1`. Field-by-field 2.0↔3.x
differences (host/basePath/schemes vs servers[], definitions vs
components/schemas, body/formData params vs requestBody, securityDefinitions vs
components/securitySchemes): `references/openapi.md`. Postman structure:
`references/postman.md`.

### 3. Parse and normalize

```
python3 scripts/parse_spec.py reports/spec-raw.json \
    --base https://api.example.com \
    -o reports/api-request-set.json
```

Handles OpenAPI 2.0, OpenAPI 3.0/3.1, and Postman Collection v2.1 JSON. For
every operation it emits one record:

```json
{"id": "op-0007", "method": "POST", "path": "/v1/orders",
 "url": "https://api.example.com/v1/orders",
 "url_example": "https://api.example.com/v1/orders",
 "resource": "orders", "operation_id": "createOrder",
 "path_params": [], "query_params": [], "header_params": [],
 "headers": {"Content-Type": "application/json", "Accept": "application/json"},
 "body": {"sku": "string", "quantity": 1}, "content_type": "application/json",
 "security": [{"name": "bearerAuth", "type": "http", "scheme": "bearer"}],
 "no_auth": false, "unresolved_refs": [], "tags": ["orders"], "source": "openapi3"}
```

Rules the parser applies (details in `references/openapi.md`):

- Resolves `servers[]` / `scheme+host+basePath` into a full URL; `--base`
  overrides (mandatory when `servers[0].url` is relative, e.g. `/api/v3`).
- Resolves **local** `#/...` `$ref`s only (JSON Pointer, cycle-guarded).
  External/remote refs are recorded verbatim in `unresolved_refs` and never
  fetched.
- Synthesizes a request body from the schema: `example`/`default`/`enum[0]`
  first, else by type/format (`date-time`, `email`, `uuid`, ...), `allOf`
  merged, first branch of `oneOf`/`anyOf`.
- Records the effective security requirement per operation (operation-level
  overrides root-level; an explicit empty `security: []` means **no auth**) and
  sets `no_auth: true` on unauthenticated operations.

### 4. Triage the request set

Read `reports/api-request-set.json` and prioritize:

- `no_auth: true` operations — immediate API2:2023 (broken authentication) and
  API9 (inventory) leads; probe these first.
- State-changing methods (`POST`/`PUT`/`PATCH`/`DELETE`) on resources with
  `{id}`-style path params — BOLA/IDOR candidates for the authz skill.
- Operations whose security scheme is `apiKey` in `query` — keys leak into
  logs/referrers.
- `unresolved_refs` — fetch/convert the referenced files manually if the spec
  is multi-file, re-run the parser on a bundled copy.
- Spec/reality drift: endpoints seen in JS bundles but absent from the spec are
  shadow endpoints — add them to the request set by hand.

### 5. rupu handoff (do this every run)

Full wiring in `references/rupu.md`. In short:

1. Mark the service and every operation as coverage assets with `assets.mark`
   (`api:service` at `mapped`; one `api:endpoint` per record at `mapped`,
   labeled `"POST /v1/orders"`). Follow the imported **`coverage-assets`**
   skill for the tool contract.
2. Split the raw OpenAPI document into per-resource work units with the
   imported **`work-units`** skill:
   `python3 <work-units>/scripts/split.py openapi reports/spec-raw.json -o reports/api-units.json`
   — then fan out with `for_each: "{{ read_file('reports/api-units.json') }}"`
   or `dispatch` one unit per child agent.
3. `reports/api-request-set.json` is the shared artifact: downstream skills
   feed it to ffuf (wordlists from paths/params), nuclei (`-l` URL lists),
   and arjun (parameter mining), and raise endpoint depth to `tested` /
   `exploited` as they go.
4. Any verified issue found while probing (e.g. a `no_auth` operation that
   returns live data) is recorded with `findings.report` per the imported
   **`finding-report`** skill, pinned to the endpoint's `http_route`
   coordinate with an `http_exchange` evidence block.

## Quick recipes

```bash
# springdoc: enumerate all groups, then fetch each
curl -skL https://api.example.com/v3/api-docs/swagger-config | python3 -m json.tool
# ASP.NET Core
curl -skL https://api.example.com/swagger/v1/swagger.json -o spec.json
# FastAPI (UI at /docs, spec at /openapi.json)
http --verify=no GET https://api.example.com/openapi.json
# GraphQL presence check (400 + "Must provide query string" == alive)
curl -sk -X POST https://api.example.com/graphql \
     -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
# YAML spec -> JSON for the parser
yq -o=json openapi.yaml > reports/spec-raw.json
```

## Artifacts

| File | Producer | Consumer |
|---|---|---|
| `reports/spec-probe.json` | `fetch_spec.py -o` | operator triage |
| `reports/spec-raw.json` | `fetch_spec.py --save` / curl | `parse_spec.py`, `work-units split.py openapi` |
| `reports/api-request-set.json` | `parse_spec.py -o` | ffuf/nuclei/arjun drivers, authz + fuzzing skills |
| `reports/api-units.json` | `work-units` `split.py openapi` | rupu `for_each` fan-out / `dispatch` |

## References

- `references/discovery.md` — full location list, JS-bundle scraping, Swagger-UI
  and Redoc parsing, GraphQL introspection, Postman public docs, brute-force.
- `references/openapi.md` — 2.0 vs 3.x field map, $ref resolution, body
  synthesis, security scheme mapping.
- `references/postman.md` — Collection v2.1 → request set mapping, variables,
  environments, auth.
- `references/rupu.md` — asset model, `assets.mark` / `findings.report` wiring,
  work-unit fan-out.
