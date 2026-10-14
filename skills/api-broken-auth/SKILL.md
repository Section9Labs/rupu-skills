---
name: api-broken-auth
description: Test API authentication for OWASP API2:2023 Broken Authentication — API key placement/enforcement/leakage, credential stuffing and password spraying against login endpoints, username enumeration, password-reset and OTP abuse, session-token handling flaws, and auth-stripping/scheme-confusion bypasses. Use in phase 3 of the api-testing flow, once endpoints are mapped; hand JWT internals to jwt-attacks and OAuth/OIDC flows to oauth-oidc-testing.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Broken Authentication (API2:2023)

Attack how the API decides a request is authenticated: API keys, login
credentials, session/reset/OTP tokens, and the acceptance logic itself.
JWT *structure* attacks (alg confusion, key cracking, claim tampering) belong
to the **`jwt-attacks`** skill; OAuth/OIDC *flow* attacks belong to
**`oauth-oidc-testing`**. This skill decides *whether* auth is enforced and
attacks everything that is not a JWT/OAuth internal.

Inputs: the endpoint inventory from discovery (OpenAPI/Swagger JSON, proxy
capture, or recon output) and at least one working authenticated request.
Fan out per resource using the reporting pack's **`work-units`** skill
(`split.py openapi` on the spec); record coverage and findings as described in
`references/rupu.md`.

## Step 0 — Identify the auth scheme

1. Read `components.securitySchemes` in the OpenAPI doc: `apiKey` (note the
   `in:` header/query/cookie and the `name:`), `http: basic`, `http: bearer`,
   `oauth2`, `openIdConnect`.
2. Observe a real authenticated request: which header/query/cookie carries the
   credential? Is the bearer token a JWT (three dot-separated base64url
   segments → route to `jwt-attacks` after this skill's enforcement checks)?
3. Mark the service and every auth-relevant endpoint (`/login`, `/token`,
   `/password-reset`, `/otp/verify`, `/logout`, `/register`) with
   `assets.mark` at `depth: "mapped"` (shapes in `references/rupu.md`).

## Step 1 — Does the API enforce auth at all?

For every mapped endpoint, replay the known-good request **with auth
stripped** and compare status + body length against the authenticated
baseline:

```
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' \
  -H 'X-API-Key: 9f3b2a7c41d6e8f0' https://api.example.com/v1/orders   # baseline
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' \
  https://api.example.com/v1/orders                                    # stripped
```

A `200` with comparable length on the stripped request is a confirmed
missing-auth finding. Also sweep:

- **Other verbs**: auth enforced on `GET` but not `POST`/`DELETE`/`PATCH`,
  or `HEAD`/`OPTIONS` leaking data a `GET` would protect.
- **Legacy/undocumented paths** (overlaps API9): `/v1/` vs `/v2/`, `/v0/`,
  `/api/internal/`, `/mobile/v1/`, `/beta/`, trailing-slash and case variants
  (`/Orders`, `/orders/`), and `.json`/`.xml` suffixes.
- **Scheme confusion**: send the credential in the wrong scheme and see what
  is accepted — `Authorization: Basic <b64>`, `Authorization: <raw-key>`
  (no scheme word), `Authorization: Bearer <api-key>`, duplicate
  `Authorization` headers, and plain `http://` instead of `https://`
  (auth downgrade — does the API answer on 80 at all?).

Raise each probed endpoint to `depth: "tested"`; a stripped request that
returns protected data is `exploited` plus a finding.

## Step 2 — API key attacks

Full detail in `references/api-keys.md`. Run the audit script against the
captured keyed request:

```
python3 scripts/key_audit.py \
  --url https://api.example.com/v1/orders --method GET \
  --key 9f3b2a7c41d6e8f0 --placement header --header-name X-API-Key \
  --header 'Accept: application/json' \
  --out reports/api-broken-auth-key-audit.json \
  --units-out reports/api-broken-auth-key-units.json
```

It replays the request with the key **removed, blank, random, truncated,
case-flipped**, and **moved** between header/query/cookie/`Authorization:
Bearer`, then reports every variant the server still accepts:

- `key-removed` / `key-blank` / `key-random` accepted → the key is
  decorative; auth is not enforced. Confirmed finding.
- `key-truncated` / `key-case-flipped` accepted → partial or
  case-insensitive comparison → the keyspace is brutally smaller than it
  looks; attempt key brute force.
- `moved-to-query` accepted → the key can land in access logs, browser
  history, proxies, and `Referer` headers. Finding (lower severity) and a
  leakage-hunting lead.

Then test **binding and lifecycle** manually:
- Use tenant A's key against tenant B's resources (`GET /v1/orgs/ORG-B/...`)
  — a key not bound to an account/scope is a cross-tenant auth break.
- Replay a key hours/days later and after an in-app "revoke"/"rotate" — no
  expiry or revocation is a finding.
- Hammer one endpoint with the key (reuse `auth_spray.py` with a static
  template) — no 429/throttle means no rate limit on key use.
- Assess entropy: short, sequential (`cust-1041`, `cust-1042`), hex of a
  timestamp, or `md5(email)`-shaped keys are guessable; try adjacent values.

**Hunt leaked keys** in JS bundles and source maps
(`curl -sk https://app.example.com/static/main.js | grep -oiE '(api[_-]?key|x-api-key|apikey)["'"'"':= ]{0,6}[A-Za-z0-9_\-]{8,64}'`),
mobile app packages (`unzip -p app.apk | strings | grep -i api_key`), git
history (`gitleaks detect`, `trufflehog git <repo-url>`), Swagger/Postman
example values, verbose error messages, and web-archive copies of docs. Any
leaked key that works is a confirmed finding — capture the working exchange.

## Step 3 — Credential attacks on login endpoints

Full detail in `references/auth-bypass.md`.

1. **Username enumeration** first: compare status, body, and timing for a
   known-valid vs invalid user with a wrong password; also check
   `/password-reset` ("email sent" vs "no such account") and `/register`
   (duplicate-email error). Differential responses give you a verified user
   list and a finding on their own.
2. **Rate-limit / lockout probe, then stuffing or spraying.** Save the login
   request as a template with `^USER^` / `^PASS^` markers:

```
POST /v1/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"username":"^USER^","password":"^PASS^"}
```

```
# Password spray: one password across all users per round
python3 scripts/auth_spray.py --template login.req --scheme https \
  --users users.txt --passwords seasons.txt --mode spray --delay 0.5 \
  --fail-string 'invalid credentials' \
  --out reports/api-broken-auth-spray.json \
  --units-out reports/api-broken-auth-spray-units.json

# Credential stuffing from breached user:pass pairs
python3 scripts/auth_spray.py --template login.req --scheme https \
  --pairs combos.txt --success-string '"token"'
```

   The script baselines the failure signature with random creds, then
   classifies each attempt as `success` / `possible-success` / `fail` /
   `lockout` / `rate-limited` / `anomaly` from status, length delta,
   match strings, `Retry-After`, and timing. Twenty-plus attempts with no
   429/lockout = **no brute-force protection**, a finding even without a hit.
   A working credential = `exploited` on the login endpoint + finding with
   the full exchange.
3. **Default/weak creds**: `admin:admin`, `admin:password`, vendor defaults
   for any bundled product behind the API (list in `references/auth-bypass.md`).

## Step 4 — Token handling (sessions, reset tokens, OTP)

- **Session/opaque tokens**: log in 3–5 times quickly and diff the tokens —
  sequential/timestamp-derived/low-entropy tokens are forgeable. Confirm the
  token still works **after logout** and **after password change**, from a
  different IP/User-Agent (not bound to client), and past its advertised
  expiry. A token in a URL (`?session=`, `?token=`) is a finding by itself.
- **Password reset**: request several resets for your own account; compare
  tokens for length/charset/sequence. Test reuse (does the token work
  twice?), expiry, and whether the reset link honors attacker-controlled
  `Host:` / `X-Forwarded-Host:` on the reset request (poisoned link →
  account takeover):

```
curl -sk -X POST https://api.example.com/v1/password-reset \
  -H 'Host: evil.example.net' -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com"}'
```

- **OTP/2FA**: a 6-digit OTP is 10^6 values — if `/otp/verify` has no rate
  limit, brute it with `auth_spray.py` (`--passwords otps.txt`, template with
  `^PASS^` as the code). Also test OTP reuse after success, OTP sent in the
  response body, and whether the final auth step can be reached with the OTP
  check skipped (direct call to the post-2FA endpoint).

## Step 5 — Record and hand off

Every parse step ends in rupu-ingestible output — see `references/rupu.md`:

- **Work units**: both scripts write `reports/*-units.json` (atomic, JSON
  array of `{"id","title","targets","hints"}`) for `for_each` fan-out or
  per-unit `dispatch`. For spec-driven fan-out, use the `work-units` skill:
  `split.py openapi` on the Swagger/OpenAPI doc.
- **Coverage**: `assets.mark` every service (`api:service`, `mapped`) and
  endpoint (`api:endpoint`) — `mapped` on discovery, `tested` once probed,
  `exploited` only on confirmed impact. Wiring via the `coverage-assets`
  skill.
- **Findings**: each verified issue (accepted request without valid auth,
  working stuffed/leaked credential, reusable reset token, brute-forced OTP)
  → `findings.report` under the `api` profile, pinned to the endpoint's
  `http_route`, with an `http_exchange` evidence block. Field contract: the
  `finding-report` skill.
- **Hand-offs**: bearer token is a JWT → `jwt-attacks`. `oauth2`/
  `openIdConnect` scheme, `/authorize`, `/token`, consent screens →
  `oauth-oidc-testing`. Unauthenticated shadow endpoints → the API9/inventory
  phase. A working credential or key feeds phase 4 (authorization testing:
  BOLA/BFLA) as the second identity.
