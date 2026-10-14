# OWASP API Security Top 10 (2023) — Test Reference

For each category: what it is, why it is API-specific, the concrete black-box
test, and the sub-skill that owns the depth. Load the owning sub-skill before
testing the category seriously; this file is the orientation layer.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**Definition.** The API exposes endpoints that take object identifiers and
fails to verify the caller is allowed to access that specific object.

**Why API-specific.** APIs are object-ID-driven by design: `GET
/v1/orders/{id}` is the canonical API call. Web UIs hide IDs behind sessions;
APIs put them in the URL, body, and headers, so every operation is an
authorization decision the server must make explicitly — and often doesn't.

**Concrete test.** With two identities (A, B):
1. As A, create/own an object and capture its ID from the response.
2. Replay every operation touching that object (`GET`, `PUT`, `PATCH`,
   `DELETE`, sub-resources like `/orders/{id}/invoice`) with B's token.
3. 2xx returning A's data, or a successful mutation, is BOLA. 403 vs 404
   differences also leak object existence.
4. Try all ID encodings: sequential ints (walk ±50), UUIDs (harvest from
   other responses), base64-wrapped IDs (decode, swap, re-encode), composite
   IDs. Also test IDs in bodies and headers, not just paths.

**Owned by:** `api-authorization`.

---

## API2:2023 — Broken Authentication

**Definition.** Authentication mechanisms are implemented incorrectly:
tokens accepted when they shouldn't be, credentials attackable, flows
bypassable.

**Why API-specific.** APIs multiply the auth surface: API keys, JWTs, OAuth
tokens, mTLS, HMAC signatures — often several at once, often with "internal"
endpoints that forgot auth entirely. Machine-to-machine endpoints frequently
skip lockout and MFA.

**Concrete test.**
- Remove the `Authorization` header from every captured authenticated
  request; replay. Note which still answer.
- Expired token, token from a deleted account, token for a different app
  (audience confusion).
- JWT battery (→ `jwt-attacks`): `alg:none`, HS256 with public key as secret,
  weak secret cracking (`jwt_tool -C -d rockyou.txt`), `kid` path traversal /
  SQLi, `jku`/`x5u` pointed at attacker-hosted keys, claim tampering with
  signature stripped.
- Credential endpoints: stuffing/bruting login, OTP, and reset endpoints —
  are there lockouts, is the reset token guessable, is user enumeration
  possible from response diffs?
- Bypass tricks: verb override headers, `/api/v1/Users` vs `/api/v1/users`,
  `//users`, `/users/`, `/users%20`, routing through an unauthenticated
  gateway path.
- OAuth/OIDC (→ `oauth-oidc-testing`): open `redirect_uri`, missing `state`,
  PKCE downgrade, scope escalation on refresh.

**Owned by:** `api-broken-auth`, `jwt-attacks`, `oauth-oidc-testing`.

---

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

**Definition.** The caller is allowed to access the object, but not all of
its *properties* — the API fails at the field level. Merges 2019's "Excessive
Data Exposure" (read side) and "Mass Assignment" (write side).

**Why API-specific.** APIs serialize whole model objects. Filtering is left
to the client, and binding frameworks happily map any JSON key onto any model
property.

**Concrete test.**
- Read side: fetch objects you legitimately own and diff the raw JSON against
  what the official client displays. Internal flags, other users' emails,
  password hashes, tokens in responses = finding.
- Write side: take a legitimate `POST`/`PUT`/`PATCH`, add properties seen in
  the read response or guessed (`role`, `is_admin`, `verified`, `balance`,
  `price`, `owner_id`, `tenant_id`), and check whether they persist on
  re-read. Also try property injection via nested objects and arrays.
- Sparse-fieldset / filter parameters (`?fields=`, `?include=`) sometimes
  unlock hidden properties.

**Owned by:** `api-authorization`.

---

## API4:2023 — Unrestricted Resource Consumption

**Definition.** No effective limits on request rate, payload size, result
size, or operation cost — attackers can exhaust CPU, memory, storage, or
billable third-party quota (SMS, email, compute).

**Why API-specific.** APIs are built for automation; without explicit limits
a single client can request the entire database or trigger a paid SMS 100k
times.

**Concrete test.**
- Pagination abuse: `?limit=1000000`, `?page_size=-1`, deep offsets.
- Payload abuse: multi-MB JSON bodies, deeply nested JSON (1000+ levels),
  huge arrays, zip/XML bombs on upload endpoints, long strings in every
  field.
- Rate: fire 500 requests at auth/OTP/search endpoints — look for 429s,
  per-key quotas, or none. Check whether limits are per-IP only (bypass with
  `X-Forwarded-For`) or per-token.
- Cost amplifiers: export/report/PDF endpoints, image resize, webhook fanout.

**Owned by:** `api-resource-consumption`.

---

## API5:2023 — Broken Function Level Authorization (BFLA)

**Definition.** Authorization is missing at the *function* level: regular
users can call administrative or cross-role operations.

**Why API-specific.** Admin functions in APIs are just other routes —
`/admin/users`, `DELETE /v1/users/{id}` — discoverable from specs, JS
bundles, and route bruting, and often protected only by the client not
showing a button.

**Concrete test.**
- Collect privileged operations: spec `tags: [admin]`, operations your admin
  identity can call, `/admin`/`/internal`/`/manage` bruting, verbs undefined
  in the spec on defined paths.
- Call each with the low-privilege token. 2xx = BFLA.
- Verb tunneling: `POST` with `X-HTTP-Method-Override: DELETE`,
  `_method=DELETE` body field.

**Owned by:** `api-authorization`.

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Definition.** A business-sensitive flow (purchase, booking, referral,
voting, posting) is exposed without anti-automation controls, so scripted
abuse harms the business even though every single request is "valid."

**Why API-specific.** The API *is* the automatable interface; the
vulnerability is the absence of friction (device fingerprinting, CAPTCHAs,
velocity checks) that the web UI might have had.

**Concrete test.**
- Map the flow end-to-end in the proxy (e.g. add-to-cart → apply-coupon →
  checkout). Script it with plain requests, no browser.
- Loop it: redeem the same coupon N times, reserve all inventory, mass-create
  accounts for referral bonuses, scrape full datasets through search.
- Check whether per-step tokens are actually validated, reusable, or
  predictable; whether steps can be skipped or reordered (pay step skipped,
  price set at an earlier step and honored later).

**Owned by:** `api-resource-consumption`.

---

## API7:2023 — Server Side Request Forgery

**Definition.** The API fetches a URL supplied (directly or indirectly) by
the client without validating it, letting the attacker steer server-side
requests to internal or third-party targets.

**Why API-specific.** Modern API features are URL-eating machines: webhooks,
URL-based file imports, link previews, avatar-from-URL, PDF renderers, SSO
metadata fetchers.

**Concrete test.**
- Inventory every parameter whose value is or contains a URL/host/path.
- Blind confirm: set it to an interactsh/collaborator URL; a hit proves the
  server fetched it.
- Escalate: `http://169.254.169.254/latest/meta-data/` (and IMDSv2 variants),
  `http://127.0.0.1:<port>/`, internal hostnames, alternate schemes
  (`file://`, `gopher://` where the client library allows), DNS-rebinding and
  redirect-chaining past denylists, IP-encoding tricks (`http://2130706433/`,
  `http://127.1/`, `http://0/`).

**Owned by:** `api-ssrf`.

---

## API8:2023 — Security Misconfiguration

**Definition.** Any insecure default or missing hardening across the stack:
verbose errors, open cloud storage, permissive CORS, unnecessary HTTP
methods, missing TLS, unpatched components, exposed management endpoints.

**Why API-specific.** API stacks are deep (gateway → service mesh → app →
serverless) and each layer ships its own defaults: actuator endpoints, debug
consoles, GraphQL playgrounds, status pages.

**Concrete test.**
- nuclei `exposures/`, `misconfiguration/`, `default-logins/`, `tokens/`
  template runs against host and endpoints (→ `api-nuclei`).
- CORS: send `Origin: https://example.net` and look for it reflected in
  `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials:
  true`.
- Error verbosity: malformed JSON, wrong types, giant numbers — stack traces
  and framework banners in responses.
- Methods: `OPTIONS` each route, then try `TRACE`, `PUT`, `DELETE`, `PATCH`
  regardless of the `Allow` header.
- Management surfaces: `/actuator/*`, `/metrics`, `/debug/pprof`, `/env`,
  `/console`, Swagger UI itself in prod.

**Owned by:** `api-nuclei`, `api-fuzzing`.

---

## API9:2023 — Improper Inventory Management

**Definition.** The organization doesn't know (or doesn't retire) all its API
hosts and versions: old versions stay reachable, staging mirrors production
data, undocumented endpoints linger.

**Why API-specific.** APIs version explicitly (`/v1`, `/v2`) and multiply
across environments (`api`, `api-dev`, `api-staging`, partner gateways). The
old version keeps the old bugs.

**Concrete test.**
- Version walking: for every documented `/v2/` route, hit `/v1/`, `/v0/`,
  `/v3/`, `/beta/`, `/internal/`, `/legacy/` equivalents.
- Host hunting: `api-dev.example.com`, `api-staging.example.com`,
  `uat-api.example.com` from DNS enumeration; compare auth strictness and
  patch level with production.
- Diff spec vs reality: routes answering that the spec never mentions
  (kiterunner output minus spec paths).
- Old mobile-app versions' endpoints (pull historical APKs' baked-in paths).

**Owned by:** `api-spec-discovery`, `api-endpoint-brute`, `api-fuzzing`.

---

## API10:2023 — Unsafe Consumption of APIs

**Definition.** The target trusts data from third-party/upstream APIs more
than user input: no validation of upstream responses, blindly followed
redirects, injectable data passed into SQL/commands, no size/time limits on
upstream reads.

**Why API-specific.** Modern APIs are composed of other APIs (enrichment,
payments, geolocation, webhooks). The trust boundary with the upstream is
routinely ignored.

**Concrete test.** Black-box angles where you can influence the upstream leg:
- Webhook/callback registration: register your own listener as the
  "third-party," return oversized, slow, redirecting, or injection-laden
  responses, and watch how the target digests them (errors, stored XSS/SQLi
  via upstream data, follow of a redirect to an internal address — SSRF via
  the integration).
- Data you control that an integration will fetch (profile URLs, OpenGraph
  targets, federation/SSO metadata) becomes the carrier for payloads.
- Where the target echoes upstream data into its own responses, test it as an
  injection source like any user input.

**Owned by:** `api-ssrf` (upstream-steering/redirect legs), `api-injection`
(payloads carried through upstream data).
