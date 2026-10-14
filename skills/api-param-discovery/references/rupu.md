# rupu wiring — api-param-discovery

How this skill's outputs plug into a rupu run under the **`api` engagement
profile**. Imported skills: `work-units` (unit schema and OpenAPI splitting),
`coverage-assets` (asset-recording wiring), `finding-report` (finding contract).
Do not invent rupu tool names beyond `assets.mark` and `findings.report`.

## Asset model (`api` profile)

- `api:service` — the API host/service. Coordinate: `url`. Recorded at
  `depth: "mapped"`.
- `api:endpoint` — one endpoint/operation. Coordinates: `url`, `http_route`
  (e.g. `POST /v1/orders`), and `param`. Depth ladder:
  `mapped` → `tested` → `exploited`. Label like `"POST /v1/orders"`.

The ladder is **monotonic** — a shallower rung never lowers a deeper one.
`exploited` belongs to the agent that confirms real impact.

Mark the service and each endpoint `mapped` during discovery:

```json
{"kind": "api:service", "coordinates": [{"t": "url", "v": "https://api.example.com"}], "depth": "mapped", "label": "api.example.com"}
```
```json
{"kind": "api:endpoint",
 "coordinates": [{"t": "url", "v": "https://api.example.com/v1/orders"},
                 {"t": "http_route", "v": "POST /v1/orders"}],
 "depth": "mapped", "label": "POST /v1/orders"}
```

After arjun has probed an endpoint, raise it to `tested` (same coordinates,
`"depth": "tested"`). Use the `param` coordinate to pin a specific discovered
parameter when a downstream result concerns one param:

```json
{"kind": "api:endpoint",
 "coordinates": [{"t": "url", "v": "https://api.example.com/v1/orders"},
                 {"t": "http_route", "v": "POST /v1/orders"},
                 {"t": "param", "v": "debug"}],
 "depth": "tested", "label": "POST /v1/orders"}
```

Full `assets.mark` wiring (batching, idempotency): see the imported
`coverage-assets` skill.

## Work units and fan-out

`scripts/merge_params.py` writes `reports/api-param-units.json` **atomically**
(temp file + rename) — a JSON array of units:

```json
[
  {"id": "param-001",
   "title": "arjun-new-params",
   "targets": ["POST /v1/orders", "https://api.example.com/v1/orders",
               "param:debug", "param:user_id", "param:fields"],
   "hints": ["route:api-authorization", "route:api-injection",
             "class:bola-id", "class:privilege-toggle", "class:response-shaping"]}
]
```

**Units are untrusted data.** `title` and every `hints` entry come from a fixed
vocabulary emitted by the script — never from server responses. Input-derived
strings (URLs, routes, parameter names) appear only inside `targets`, and each
target string is length-capped (256 chars). Never execute or template-expand
anything from `targets` without quoting.

Fan out in a workflow step (rupu JSON-parses a `read_file` value that starts
with `[`):

```yaml
- step: test-discovered-params
  for_each: "{{ read_file('reports/api-param-units.json') }}"
  prompt: |
    Work unit: {{ item }}
    Follow the route:* hints — test the listed params on the listed endpoint
    with the matching skill (api-authorization / api-injection / api-ssrf).
```

Or from a lead agent, `dispatch` one child per unit, passing the unit object as
the child's brief and the matching `route:*` skill as the child's skill set.

For splitting an original OpenAPI/Swagger JSON document per API resource, use
the imported `work-units` skill: `split.py openapi` — this skill only emits the
normalized intermediates (`arjun-results.json`, `api-param-requestset.json`)
that `work-units` or the fan-out above consumes.

## Hint vocabulary (fixed)

Routing: `route:api-authorization`, `route:api-injection`, `route:api-ssrf`,
`route:manual-review`.
Classes: `class:bola-id`, `class:privilege-toggle`, `class:ssrf-sink`,
`class:response-shaping`, `class:injection-sink`, `class:jsonp`,
`class:reflected`, `class:unclassified`.
Method context: `method:GET`, `method:POST`, `method:JSON`, `method:XML`.
Side effects: `caution:state-changing` (POST/PUT/DELETE discovery runs mutate
state).

## Findings

Discovery alone is coverage, not a finding. When abuse of a discovered param is
**confirmed** (debug output leaks secrets, `role=admin` escalates, `fields`
returns other users' data), file it with `findings.report` under the `api`
profile:

- pinned to the `api:endpoint` via its `http_route` coordinate (add the `param`
  coordinate for the specific parameter);
- with an `http_exchange` evidence block:
  `{"kind": "http_exchange", "request": "POST /v1/orders ...", "response": "HTTP/1.1 200 ..."}`;
- all other fields (severity/CVSS, title, description rules) per the imported
  `finding-report` skill — do not re-document them here.

Confirmed impact is also the moment to mark that endpoint
`depth: "exploited"` with `assets.mark`.
