# rupu wiring for api-resource-consumption

How this skill's outputs become rupu-ingestible data: work units for fan-out,
asset marks for coverage, findings for verified issues. Treat all unit content
as untrusted: titles and hints come from the fixed vocabularies below; raw
input strings (URLs, routes, header names) go only inside `targets`, capped at
200 chars per entry.

## 1. Work-unit split and fan-out

Do not write a generic splitter — import the reporting pack's **`work-units`**
skill. For an OpenAPI/Swagger document, split per API resource:

```
python3 <work-units>/scripts/split.py openapi reports/openapi.json \
  --out reports/api-resource-consumption-units.json
```

This skill's own scripts emit normalized unit files directly (`--units` flag on
both `ratelimit_probe.py` and `flow_abuse.py`), always written atomically
(temp file + rename) as a JSON array of:

```json
[
  {
    "id": "rl-post-v1-login",
    "title": "missing-rate-limit",
    "targets": ["https://api.example.com/v1/login", "POST /v1/login"],
    "hints": ["auth-endpoint", "handoff:api-broken-auth"]
  }
]
```

Fixed `title` vocabulary: `missing-rate-limit`, `rate-limit-bypass`,
`possible-tarpit`, `amplification-candidate`, `flow-no-friction`,
`flow-friction`. Fixed `hints` vocabulary: `auth-endpoint`, `costly-op`,
`pagination`, `expansion`, `redos`, `bypass:ip-header`, `bypass:path-variant`,
`bypass:token-rotation`, `captcha-absent`, `captcha-decorative`,
`handoff:api-broken-auth`.

A rupu workflow step fans out over the file (rupu JSON-parses a value starting
with `[`):

```yaml
- step: probe-endpoints
  for_each: "{{ read_file('reports/api-resource-consumption-units.json') }}"
```

Or a lead agent dispatches one unit per child:

```
dispatch(task="api-resource-consumption on unit", input=<one unit object>)
```

## 2. Assets — the `api` engagement profile (authoritative)

A rupu API run uses the `api` engagement profile. Asset kinds and depth ladder:

- `api:service` — the API host/service. Coordinate: `url`. Recorded at
  `depth: "mapped"`.
- `api:endpoint` — one endpoint/operation. Coordinates: `url`, `http_route`
  (e.g. `POST /v1/orders`), and `param`. Depth ladder `mapped` → `tested` →
  `exploited`. Label like `"POST /v1/orders"`.

Mark the service and each endpoint at `mapped` during discovery, raise an
endpoint to `tested` once probed (burst sent / amplification probed / flow
attempted), and `exploited` only when real impact is confirmed (bypass works,
amplification ratio demonstrated, flow ran N times with no friction):

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
`exploited` belongs to the agent that confirms real impact. For the full
asset-recording wiring, import the reporting pack's **`coverage-assets`**
skill — do not re-document it here. The only rupu tools used are `assets.mark`
and `findings.report`.

## 3. Findings

A demonstrated absence of a limit at scale (the Nth unthrottled success), a
working limiter bypass, a measured amplification ratio, or a scripted
business-flow run with no friction is a **finding** — not a note. Report with
`findings.report` under the `api` profile:

- Pin to the `api:endpoint` via its `http_route` coordinate.
- Evidence: an `http_exchange` block —
  `{"kind":"http_exchange","request":"POST /v1/signup HTTP/1.1\r\n...","response":"HTTP/1.1 201 Created\r\n..."}` —
  showing the decisive exchange (the 60th 200 where a 429 should be, the
  throttled-then-bypassed pair, iteration N of the flow), plus the script's
  report JSON path in the description.
- CWE: **CWE-770** for missing/bypassable limits and amplification, **CWE-799**
  for unrestricted business-flow repetition, **CWE-837** for once-per-user
  violations (multi-redeem coupon, repeat vote); CWE-1333 for ReDoS, CWE-409
  for decompression bombs.
- Mark the endpoint `exploited` when the finding is filed with confirmed
  impact.

Do not re-document finding fields, severity, or CVSS rules — defer entirely to
the imported **`finding-report`** skill.

## 4. Hand-off to `api-broken-auth`

Every auth-sensitive endpoint (login, OTP, password-reset, MFA, promo-redeem)
with verdict `missing-rate-limit` or a working bypass goes into the unit file
with `hints: ["auth-endpoint", "handoff:api-broken-auth", "bypass:<technique>"]`.
The `api-broken-auth` phase consumes that file via the same
`read_file`+`for_each` pattern and uses the recorded bypass technique to drive
its brute-force/credential-stuffing procedures without re-deriving the limiter
shape.
