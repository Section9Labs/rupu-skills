# End-to-End Walkthrough — api.example.com

A concrete run of the umbrella flow against a fictional target, showing the
hand-off files each phase writes and the next phase reads. Addresses and names
are documentation examples only. The rupu tool calls referenced here are
specified in `references/rupu.md`.

Working convention: all intermediate artifacts live under `reports/`, written
atomically (write to `reports/.tmp-<name>`, then rename).

---

## Phase 0 — Context

Operator supplies:

- Base URL: `https://api.example.com` (resolves to 203.0.113.10).
- Identity A (user, tenant 1): bearer token in `reports/identities.json`.
- Identity B (user, tenant 2): second bearer token, same file.
- Burp listening on `127.0.0.1:8080`; all tools get `-x http://127.0.0.1:8080`
  or `HTTPS_PROXY=http://127.0.0.1:8080`.

`reports/identities.json`:

```json
{
  "base": "https://api.example.com",
  "identities": [
    {"name": "userA", "header": "Authorization: Bearer eyJhbGciOi...A"},
    {"name": "userB", "header": "Authorization: Bearer eyJhbGciOi...B"}
  ]
}
```

Mark the service immediately:

```json
{"kind": "api:service",
 "coordinates": [{"t": "url", "v": "https://api.example.com"}],
 "depth": "mapped", "label": "api.example.com"}
```

## Phase 1 — Spec discovery → inventory → work units

Quick probe of common spec locations (this skill's helper):

```
python3 scripts/spec_probe.py https://api.example.com -o reports/spec-probe.json
```

Output says `/v3/api-docs` returned 200 with `"openapi": "3.0.1"`. Load
`api-spec-discovery` for the full hunt (JS bundles, Swagger UI config,
Postman); save the normalized spec as `reports/openapi.json`.

Suppose the spec defines 4 resources: `users`, `orders`, `invoices`,
`webhooks` — 23 operations total. Also run `api-param-discovery` (arjun) on
the top GET/POST operations and merge discovered hidden params (e.g. `debug`,
`fields`) back into `reports/openapi.json` as additional parameters.

Mark every operation:

```json
{"kind": "api:endpoint",
 "coordinates": [{"t": "url", "v": "https://api.example.com/v1/orders"},
                 {"t": "http_route", "v": "POST /v1/orders"}],
 "depth": "mapped", "label": "POST /v1/orders"}
```

Split per resource using the reporting pack's `work-units` skill:

```
python3 <work-units-base>/scripts/split.py openapi reports/openapi.json \
  > reports/api-units.json
```

`reports/api-units.json` (shape — one unit per resource, untrusted-data
discipline: fixed-vocabulary titles/hints, raw strings only inside `targets`):

```json
[
  {"id": "api-orders",
   "title": "API resource: orders",
   "targets": ["https://api.example.com/v1/orders",
               "GET /v1/orders", "POST /v1/orders",
               "GET /v1/orders/{orderId}", "DELETE /v1/orders/{orderId}"],
   "hints": ["object-id-paths", "write-operations"]},
  {"id": "api-users", "title": "API resource: users", "targets": ["..."], "hints": ["..."]}
]
```

Hand-off: `reports/api-units.json` → the workflow's `for_each` step, or one
`dispatch` per unit from a lead agent.

## Phase 2 — Surface scan (per unit, parallel)

Each child takes one unit. For the `orders` unit:

- `api-fuzzing` (ffuf): verb fuzz on `/v1/orders/{id}`, version walk
  `/FUZZ/orders` with `v0,v1,v2,v3,beta,internal`, content-type flips.
  Result: `/v2/orders` answers 200 — undocumented newer version (API9 lead).
- `api-nuclei`: exposure + misconfig templates against the host once (not per
  unit). Result: CORS reflects arbitrary `Origin` with credentials on
  `/v1/*` (API8 candidate).

Raise probed endpoints to `tested`. Append machine-readable candidates to
`reports/scan-orders.json` for the deep-test phase; confirmed misconfigs
(reproduced manually through the proxy) go straight to `findings.report`.

## Phase 3 — Authentication

Token is a JWT (`eyJ...`). Load `jwt-attacks`:

```
jwt_tool <tokenA> -M at -t https://api.example.com/v1/users/me \
  -rh "Authorization: Bearer <token>"
jwt_tool <tokenA> -C -d /usr/share/wordlists/rockyou.txt
```

Say the HMAC secret cracks to `secret123`. Forge a token with
`"role": "admin"` and verify `/v1/users/me` reflects it — that's a verified
API2 finding on the token-consuming endpoints, and the forged token is saved
into `reports/identities.json` as identity `forgedAdmin` for phase 4.

## Phase 4 — Authorization (differential)

Load `api-authorization`. For the `orders` unit:

1. As userA: `POST /v1/orders` → order `9123` created.
2. As userB: `GET /v1/orders/9123` → **200 with userA's order**. BOLA.
3. As userB: `DELETE /v1/orders/9123` → 204. BOLA with destructive impact.
4. Mass assignment: `PATCH /v1/orders/9123 {"status":"paid","total":0}` as
   owner → `total` persisted as 0. BOPLA.

Mark `GET /v1/orders/{orderId}` as `exploited` (real cross-tenant data
access confirmed) and report:

```json
{
  "title": "BOLA on GET /v1/orders/{orderId} — cross-tenant order read",
  "asset": {"kind": "api:endpoint",
            "coordinates": [{"t": "http_route", "v": "GET /v1/orders/{orderId}"},
                            {"t": "url", "v": "https://api.example.com/v1/orders/9123"}]},
  "evidence": [{"kind": "http_exchange",
                "request": "GET /v1/orders/9123 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer <userB>\r\n\r\n",
                "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":9123,\"owner\":\"userA\",...}"}]
}
```

(Field rules, severity, CVSS: defer entirely to `finding-report`.)

## Phase 5 — Injection & SSRF

- `api-injection`: `POST /v1/orders` search filter `{"q":"*"}` → sqlmap with
  `-r reports/req-orders-search.txt --level 3 --risk 2 -p q` (marker inside
  the JSON body). No hit here; NoSQL operator test `{"q":{"$ne":null}}`
  returns all orders — logic-level injection, report it.
- `api-ssrf`: the `webhooks` unit has `POST /v1/webhooks {"url": "..."}`.
  Register `https://<id>.oast.example.net` (interactsh) → callback received.
  Escalate: `"url":"http://169.254.169.254/latest/meta-data/"` and read the
  delivery-log endpoint → metadata reflected. API7, `exploited`.

## Phase 6 — Abuse & limits

`api-resource-consumption`: `GET /v1/orders?limit=1000000` returns the full
table in one 180 MB response (API4). The coupon flow in `POST /v1/orders`
accepts the same coupon code in a loop — 200× redemption scripted (API6).
Both reported with the looped-request evidence.

## Phase 7 — GraphQL / gRPC

`POST /graphql` answers on the same host. Load `graphql-testing`:
introspection enabled → dump schema, regenerate operations, rerun the
phase 3–6 discipline against them (new BOLA surface: `node(id:)` global IDs).
No gRPC surface on this target.

## Phase 8 — Close out

- Findings filed: 1×API2 (JWT weak secret), 2×API1 (read + delete BOLA),
  1×API3 (price mass-assignment), 1×API7 (webhook SSRF→metadata), 1×API8
  (CORS), 1×API4, 1×API6, 1×API9 (`/v2` shadow version — fed back as a new
  `api:service`/endpoint set and re-run through phase 1).
- Coverage check: every endpoint in `reports/openapi.json` is at `tested` or
  deeper. The `/v2/orders` discovery spawned a second, smaller run of the
  same flow.

## Artifact map

| File | Written by | Read by |
|---|---|---|
| `reports/identities.json` | operator + phase 3 | phases 2–7 |
| `reports/spec-probe.json` | `scripts/spec_probe.py` | `api-spec-discovery` |
| `reports/openapi.json` | phase 1 (normalized spec) | `work-units`, phases 2–6 |
| `reports/api-units.json` | `work-units split.py openapi` | workflow `for_each` / `dispatch` |
| `reports/scan-<unit>.json` | phase 2 scanners | phases 3–6 deep tests |
| `reports/req-*.txt` | proxy exports | sqlmap `-r`, evidence blocks |
