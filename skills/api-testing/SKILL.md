---
name: api-testing
description: Umbrella methodology for end-to-end API security testing (REST, GraphQL, gRPC) on authorized engagements, structured around the OWASP API Security Top 10 (2023). Routes each phase — spec discovery, surface scanning, authentication, authorization, injection/SSRF, abuse limits, GraphQL/gRPC — to the focused sub-skill that owns it, and wires every phase into rupu via assets.mark, work-unit fan-out, and findings.report. Load this first on any API engagement to plan the run and pick sub-skills.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Security Testing — Domain Umbrella

This is the router for the API testing pack. It defines the end-to-end flow,
names the sub-skill to load for each phase, and specifies the rupu-ingestible
output every phase must end with. Do not re-derive what the sub-skills already
teach — load them by name when their phase begins.

Supporting references:
- `references/owasp-api-top10.md` — every OWASP API Top 10 (2023) category in depth, with the owning sub-skill.
- `references/flow.md` — a full worked walkthrough against `api.example.com`, including the hand-off files between phases.
- `references/rupu.md` — the authoritative rupu wiring: `api` engagement profile asset model, `assets.mark` calls, `work-units` fan-out, `findings.report` hand-off, and a workflow YAML skeleton.

## Request context — set up before anything else

Every phase assumes this context exists. Establish it first:

1. **Base URL(s)** — e.g. `https://api.example.com`, plus any versioned bases
   (`/v1`, `/v2`, `api-staging.example.com`). Record each as an `api:service`
   asset at `depth: "mapped"` as soon as it is confirmed live.
2. **Two identities minimum** — a low-privilege account (user A), a second
   low-privilege account (user B, different tenant/owner where possible), and
   an admin/privileged account if the operator can obtain one. Capture each
   identity's auth material (API key, bearer token, session cookie) into a
   small env file (`reports/identities.json`) so differential tests can swap
   them mechanically. Authorization testing (phase 4) is impossible without at
   least two identities.
3. **Interception proxy for evidence** — run Burp or mitmproxy on
   `127.0.0.1:8080` and route tooling through it (`curl -x
   http://127.0.0.1:8080 -k`, `ffuf -x http://127.0.0.1:8080`,
   `HTTPS_PROXY=http://127.0.0.1:8080`). Every finding needs a verbatim
   request/response pair for its `http_exchange` evidence block; the proxy
   history is where you cut those from.
4. **Common headers** — note required headers up front (`Authorization`,
   `X-Api-Key`, `Content-Type: application/json`, tenant headers like
   `X-Org-Id`) and bake them into every tool invocation.

## The flow — phases in order

Each phase ends by producing rupu-ingestible output: assets marked with
`assets.mark`, a normalized JSON file under `reports/` for fan-out, and/or
findings via `findings.report`. See `references/rupu.md` for the exact shapes.

### Phase 1 — Inventory & spec discovery

Goal: enumerate the full API surface, with or without the vendor's help.

- Load **`api-spec-discovery`**. Hunt for machine-readable specs:
  `/openapi.json`, `/swagger.json`, `/swagger/v1/swagger.json`,
  `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/.well-known/openapi.json`,
  Swagger UI (`/swagger-ui/`, `/swagger-ui.html`), Postman collections,
  GraphQL introspection, and endpoints referenced in JS bundles. The optional
  helper `scripts/spec_probe.py` in this skill does a quick first pass over
  the common locations.
- No spec found? Load **`api-endpoint-brute`** and brute routes with
  kiterunner (`kr scan`) using the routes wordlists; it understands methods
  and request shapes, not just paths.
- For every discovered endpoint, load **`api-param-discovery`** and mine
  hidden parameters with arjun (`arjun -u ... -m GET,POST,JSON`).
- Normalize everything into one inventory: parse the OpenAPI document (or
  synthesize one from brute results) and hand it to the reporting pack's
  **`work-units`** skill: `python3 <work-units>/scripts/split.py openapi
  reports/openapi.json > reports/api-units.json` — one work unit per API
  resource, ready for `for_each` fan-out or per-child `dispatch`.
- Mark the service and every endpoint as assets at `depth: "mapped"` using
  the wiring in the reporting pack's **`coverage-assets`** skill.

Output: `reports/openapi.json` (normalized spec), `reports/api-units.json`
(work units), assets marked `mapped`.

### Phase 2 — Automated surface scan

Goal: cheap breadth before expensive depth. Covers API8 (Security
Misconfiguration) and API9 (Improper Inventory Management).

- Load **`api-fuzzing`**. Drive ffuf from the spec: fuzz path segments,
  verbs, parameter values, and content types per endpoint. Hunt old versions
  (`/v1/` endpoints that still answer when the spec only documents `/v2/`),
  debug routes, and undocumented methods (`OPTIONS`, then try everything the
  `Allow` header admits plus the ones it doesn't).
- Load **`api-nuclei`**. Run nuclei's exposure, misconfiguration, token, and
  DAST template sets against the host and endpoint list. Triage template hits
  into findings only after manual confirmation of the request/response.
- Raise each probed endpoint to `depth: "tested"`.

Output: candidate-issue list per endpoint folded into the work units' `hints`;
confirmed misconfigurations reported via `findings.report`.

### Phase 3 — Authentication

Goal: break how the API decides *who* you are (API2).

- Load **`api-broken-auth`** — missing auth on documented-as-authenticated
  endpoints, API keys in URLs, key brute/stuffing, weak reset flows, auth
  bypass via method/path tricks (`X-HTTP-Method-Override`, trailing-slash,
  case, URL-encoding), and credential handling.
- Tokens are JWTs? Load **`jwt-attacks`** — jwt_tool for `alg:none`, key
  confusion (RS256→HS256), weak HMAC secrets (`-C -d wordlist`), kid/jku/x5u
  injection, claim tampering, expiry handling.
- OAuth2/OIDC in play? Load **`oauth-oidc-testing`** — redirect_uri abuse,
  PKCE downgrade, state omission, token audience/scope confusion, implicit
  flow leaks.

Output: findings pinned to the auth endpoints; working alternate tokens saved
to `reports/identities.json` for phase 4.

### Phase 4 — Authorization (the core of API testing)

Goal: break *what* each identity can touch. This is where most real API
findings live. Load **`api-authorization`** and run multi-identity
differential testing across the whole inventory:

- **BOLA (API1)**: replay user A's object-reading/writing requests with user
  B's token, swapping object IDs. Any 2xx with A's data under B's identity is
  a finding. Test every ID shape: integers, UUIDs, slugs, base64 blobs.
- **BFLA (API5)**: call admin/privileged operations (from the spec, from
  JS bundles, from `/admin` bruting) with a low-privilege token.
- **BOPLA / mass assignment + excessive data exposure (API3)**: diff response
  bodies for fields the client never displays; replay writes with extra
  properties (`"role":"admin"`, `"price":0`, `"is_verified":true`).

Drive it mechanically: for each work unit, enumerate its operations, send each
with every identity, and diff status/body. Confirmed cross-identity access =
`depth: "exploited"` on that endpoint plus a finding.

### Phase 5 — Server-side & input flaws

- Load **`api-injection`** — SQL/NoSQL/command/SSTI injection through JSON
  bodies, query params, headers, and nested object values. sqlmap takes a raw
  request file (`-r req.txt`) with `*` injection markers inside JSON; test
  NoSQL operator injection (`{"$ne": null}`) by hand or with templated ffuf.
- Load **`api-ssrf`** (API7) — every parameter that carries a URL, hostname,
  webhook, callback, file reference, or import source. Confirm with an
  out-of-band listener (interactsh); escalate to internal-range reads
  (169.254.169.254 metadata, internal services on 192.0.2.0/24-style ranges).

### Phase 6 — Abuse & limits

Load **`api-resource-consumption`**:

- **API4 Unrestricted Resource Consumption** — missing rate limits, huge
  `page_size`/`limit` values, pathological payload sizes, expensive export
  endpoints, zip/XML expansion, upload size limits.
- **API6 Unrestricted Access to Sensitive Business Flows** — scripted abuse
  of business-critical flows: checkout, coupon redemption, voting, booking,
  signup. The flaw is that the flow works perfectly, repeated 10,000 times.

### Phase 7 — GraphQL and gRPC

- GraphQL endpoint found (`/graphql`, `/api/graphql`, `/v1/graphql`)? Load
  **`graphql-testing`** — graphw00f engine fingerprinting, introspection dump
  (and clairvoyance when introspection is off), graphql-cop audit, InQL for
  query generation, batching/alias abuse, nested-query DoS, and then rerun
  phases 3–6 against the generated operations.
- gRPC (HTTP/2, `application/grpc`, port patterns)? Load **`grpc-testing`** —
  grpcurl server reflection, service/method enumeration, proto
  reconstruction, method invocation with crafted messages, then the same
  authz/injection discipline per method.

### Phase 8 — Record & report

Every verified issue goes through the reporting pack's **`finding-report`**
skill via `findings.report`, under the `api` profile, pinned to its
`api:endpoint` by the `http_route` coordinate, with an `http_exchange`
evidence block cut verbatim from the proxy history. Do not improvise finding
fields — `finding-report` owns the contract. Final coverage check: every
inventoried endpoint should sit at `tested` or deeper on the asset ladder;
anything still `mapped` is unfinished work, not a clean bill.

## OWASP API Security Top 10 (2023) → skill routing

| # | Category (2023) | Sub-skill(s) | One-line black-box test |
|---|---|---|---|
| API1 | Broken Object Level Authorization | `api-authorization` | Replay user A's `GET /v1/orders/1001` with user B's token; 2xx with A's order = BOLA. |
| API2 | Broken Authentication | `api-broken-auth`, `jwt-attacks`, `oauth-oidc-testing` | Strip/forge the token: no auth header, `alg:none` JWT, expired token, other user's key — does the API still answer? |
| API3 | Broken Object Property Level Authorization | `api-authorization` | Add `"role":"admin"` to a profile PATCH; diff responses for hidden fields (SSNs, internal flags) the UI never shows. |
| API4 | Unrestricted Resource Consumption | `api-resource-consumption` | Request `?limit=1000000`, send a 100 MB body, or hammer an OTP endpoint — no 429, no cap, no cost control. |
| API5 | Broken Function Level Authorization | `api-authorization` | Call `DELETE /v1/users/{id}` or `/admin/*` routes with a plain-user token; verb-swap documented GETs to PUT/DELETE. |
| API6 | Unrestricted Access to Sensitive Business Flows | `api-resource-consumption` | Script the full purchase/coupon/vote flow in a loop; the business logic executes unlimited times with no friction. |
| API7 | Server Side Request Forgery | `api-ssrf` | Point every URL/webhook/import parameter at an interactsh host, then at 169.254.169.254 and internal addresses. |
| API8 | Security Misconfiguration | `api-nuclei`, `api-fuzzing` | nuclei misconfig/exposure templates; verbose stack traces, permissive CORS (`Origin: https://example.net` reflected with credentials), TRACE, missing security headers. |
| API9 | Improper Inventory Management | `api-spec-discovery`, `api-endpoint-brute`, `api-fuzzing` | Hit `/v1/`, `/v2/`, `/beta/`, `/internal/` variants of every documented route; find staging hosts and forgotten debug endpoints. |
| API10 | Unsafe Consumption of APIs | `api-ssrf`, `api-injection` | Poison data the target fetches from third-party/upstream APIs (webhooks, enrichment feeds, redirects it follows) and watch it trust the response blindly. |

## Tools at a glance

| Tool | Phase | Sub-skill |
|---|---|---|
| curl + proxy (Burp/mitmproxy) | all — evidence capture | this skill |
| kiterunner (`kr`) | 1 — route bruteforce | `api-endpoint-brute` |
| arjun | 1 — hidden parameters | `api-param-discovery` |
| ffuf | 2, 9-hunting | `api-fuzzing` |
| nuclei | 2 — templates/DAST | `api-nuclei` |
| jwt_tool | 3 — JWT attacks | `jwt-attacks` |
| sqlmap | 5 — SQL injection | `api-injection` |
| interactsh-client | 5 — OOB SSRF confirm | `api-ssrf` |
| graphw00f, graphql-cop, clairvoyance, InQL | 7 | `graphql-testing` |
| grpcurl | 7 | `grpc-testing` |
| work-units `split.py openapi` | 1 — fan-out | `work-units` (reporting pack) |
| `assets.mark` / `findings.report` | all | `coverage-assets` / `finding-report` (reporting pack) |

## Operating rules for the run

- Spec first, brute second: a parsed OpenAPI document is worth hours of
  blind fuzzing. Spend real effort in phase 1.
- Everything through the proxy. If you can't paste the exact request and
  response, you don't have a finding yet.
- Authorization (phase 4) gets the most time. BOLA is the #1 API bug class
  for a reason — test it against *every* object-bearing operation, not a
  sample.
- Keep the asset ladder honest: `mapped` on discovery, `tested` after you
  actually probed the endpoint, `exploited` only on confirmed real impact.
- Fan out, don't serialize: once `reports/api-units.json` exists, resource
  groups are independent — run phases 2–6 per unit in parallel children
  (`references/rupu.md` shows the `for_each` and `dispatch` patterns).
