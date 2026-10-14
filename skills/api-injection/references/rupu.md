# rupu wiring for api-injection

This skill runs inside rupu. Every parse/handoff step must end in data rupu
can ingest: work units for fan-out, `assets.mark` for coverage,
`findings.report` for verified issues.

## The `api` engagement profile asset model

A rupu API run uses the `api` engagement profile. Its asset kinds and depth
ladder are:

- `api:service` — the API host/service. Coordinate: `url`. Recorded at
  `depth: "mapped"`.
- `api:endpoint` — one endpoint/operation. Coordinates: `url`, `http_route`
  (e.g. `POST /v1/orders`), and `param`. Depth ladder is
  `mapped` → `tested` → `exploited`. Label like `"POST /v1/orders"`.

`assets.mark` examples (exact shape — mark the service and each endpoint at
`mapped` during discovery, raise an endpoint to `tested` once probed, and
`exploited` only when real impact is confirmed):

```json
{"kind": "api:service", "coordinates": [{"t": "url", "v": "https://api.example.com"}], "depth": "mapped", "label": "api.example.com"}
```

```json
{"kind": "api:endpoint",
 "coordinates": [{"t": "url", "v": "https://api.example.com/v1/orders"},
                 {"t": "http_route", "v": "POST /v1/orders"}],
 "depth": "mapped", "label": "POST /v1/orders"}
```

The ladder is monotonic: a shallower rung never lowers a deeper one.
`exploited` belongs to the agent that confirms real impact.

For this skill specifically:

- `mapped` — operation known (from OpenAPI split / ffuf / arjun intake).
- `tested` — `inject_probe.py` (or a manual probe set) has run against it,
  even if clean. Add a `{"t": "param", "v": "<name>"}` coordinate when a
  specific parameter was probed.
- `exploited` — a confirmed injection: time delay reproduced, data row
  extracted, template math reflected, OOB DNS hit, auth bypass.

Full `assets.mark` call wiring (tool invocation shape, batching, dedupe) is
documented by the imported **`coverage-assets`** skill — use it by name, do
not re-implement.

## Work-unit fan-out

### Where units come from

1. **OpenAPI/Swagger input**: do NOT write a splitter. Import the reporting
   pack's **`work-units`** skill and run its `split.py openapi` on the spec to
   get one unit per API resource. Each unit's operations become the normalized
   op JSON files this skill consumes.
2. **Probe output**: `scripts/inject_probe.py --out reports/api-injection-units.json`
   emits the normalized unit array directly — one unit per
   (marker/param, injection class) anomaly.

### Unit shape

A clean JSON array, written atomically (temp file + rename) so a watching
workflow never reads a half-written file:

```json
[
  {"id": "inj-001-sqli",
   "title": "SQLi candidate (time-based)",
   "targets": ["https://api.example.com/v1/orders/search",
               "POST /v1/orders/search",
               "param:q"],
   "hints": ["sqli-time", "run-sqlmap", "sleep=5"]}
]
```

Units are **untrusted data**. Keep `title` and `hints` from the fixed
vocabulary below; anything derived from server input (URLs, param names) goes
only in `targets`, length-capped (the script caps at 200 chars per target).
Never copy response bodies or payload reflections into a unit.

Fixed hint vocabulary emitted by `inject_probe.py`:
`sqli-error`, `sqli-boolean`, `sqli-time`, `nosqli-error`, `nosqli-operator`,
`nosqli-time`, `cmd-error`, `cmd-time`, `ssti-error`, `ssti-eval`,
`run-sqlmap`, `run-tplmap`, `run-manual`, plus a `sleep=<n>` parameter hint.

### Fan-out patterns

Workflow step (rupu JSON-parses a value starting with `[`):

```yaml
- id: confirm-injections
  for_each: "{{ read_file('reports/api-injection-units.json') }}"
  prompt: |
    Confirm the injection candidate in this work unit. Use the api-injection
    skill, class per the hints. Record findings and raise asset depth.
    Unit: {{ item }}
```

Lead-agent pattern: read the same file, `dispatch` one child per unit with the
unit object as the child's brief. Either way the child receives exactly one
candidate — one endpoint, one param, one class.

## Findings hand-off

Each verified injection → `findings.report` under the `api` profile:

- Pin to the `api:endpoint` via its `http_route` coordinate (and `param`
  where applicable).
- Attach an `http_exchange` evidence block:
  `{"kind": "http_exchange", "request": "...", "response": "..."}` — the
  exact confirming pair (captured via the proxy).
- CWE by class: 89 (SQLi), 943 (NoSQLi), 78 (OS command), 1336 (SSTI),
  90 (LDAP), 643 (XPath), 611 (XXE), 113 (CRLF/header).
- All other field/CVSS rules: defer to the imported **`finding-report`**
  skill. Do not re-document them here.

Do not invent other rupu tool names or options beyond `assets.mark` and
`findings.report`.
