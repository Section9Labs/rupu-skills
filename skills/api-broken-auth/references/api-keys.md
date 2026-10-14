# API Keys — placement, leakage, binding, entropy

## Placement matrix and what each placement risks

| Placement | Example | Risk profile |
|---|---|---|
| Header | `X-API-Key: 9f3b2a7c41d6e8f0` | Safest transport; still logged by some proxies/APMs |
| `Authorization` | `Authorization: Bearer 9f3b2a…` or raw key | Scheme confusion if the server accepts any scheme word |
| Query string | `GET /v1/orders?api_key=9f3b2a…` | Lands in access logs, browser history, CDN/proxy logs, `Referer`, analytics, screenshots |
| Cookie | `Cookie: api_key=9f3b2a…` | CSRF-usable if no SameSite; sent automatically by browsers |
| Body | `{"apiKey":"…"}` | Usually log-safe, but breaks on GET; often duplicated into query by SDKs |

**Always test moving the key.** Many gateways (Kong, AWS API Gateway, Apigee)
check several locations and accept whichever appears first. `key_audit.py`
automates this; manually:

```
# captured as a header — does the query work too?
curl -sk 'https://api.example.com/v1/orders?api_key=9f3b2a7c41d6e8f0'
# captured as a query param — does a header work?
curl -sk -H 'X-API-Key: 9f3b2a7c41d6e8f0' https://api.example.com/v1/orders
# cookie placement
curl -sk -b 'api_key=9f3b2a7c41d6e8f0' https://api.example.com/v1/orders
# raw key / wrong scheme in Authorization
curl -sk -H 'Authorization: 9f3b2a7c41d6e8f0' https://api.example.com/v1/orders
curl -sk -H 'Authorization: Bearer 9f3b2a7c41d6e8f0' https://api.example.com/v1/orders
```

Query acceptance is a finding on its own (log/referrer exposure) and makes
leakage hunting (below) far more likely to pay off.

## Enforcement and comparison weaknesses

Variants `key_audit.py` sends and what acceptance of each means:

- **removed / blank / random** → key never checked; the endpoint is
  effectively unauthenticated. Confirm data exposure, report, mark
  `exploited`.
- **truncated** (`9f3b2a7c41d6e8f` for a 16-char key) → prefix comparison
  (`strncmp`-style). Brute the key prefix-by-prefix: each correct character
  flips the response, reducing a 16^16 space to 16×16 guesses.
- **case-flipped** → case-insensitive comparison halves per-character
  entropy for alphanumeric keys.
- **whitespace/padding tolerated** (`'9f3b2a7c41d6e8f0 '`, `%009f…`) → sloppy
  parsing, often paired with other normalization bugs; test manually.

## Binding: is the key tied to anything?

A key should be bound to one account, one scope, one environment.

- **Tenant swap**: with tenant A's key, request tenant B's resources:
  `GET /v1/orgs/0b2f/users` with A's key. Success = cross-tenant break
  (report here; deeper object-level testing is phase 4 BOLA).
- **Scope escalation**: a "read-only" key issued for `GET` — try `POST`/
  `DELETE` on the same resource.
- **Environment bleed**: a key from `sandbox.example.com` or
  `staging.example.com` accepted by `api.example.com` (and vice versa).
- **Product bleed**: a key issued for one API product accepted by another
  (`/v1/weather` key against `/v1/billing`).

## Lifecycle: expiry, rotation, revocation, rate limits

- Replay the same key over hours/days — no expiry is common and reportable
  when combined with query placement or leakage.
- If the app exposes "rotate key" / "revoke key", do it, then replay the old
  key. Old key still working = broken revocation.
- No rate limit on key use: drive the keyed request through `auth_spray.py`
  with a static template (no markers) and a dummy list — 50+ requests with
  no 429 confirms it; this also enables key brute force when entropy is low.

## Entropy and guessability

Collect several keys (register multiple accounts if self-service):

- **Length/charset**: < 16 chars or digits-only is brute-forceable.
- **Sequential/structured**: `cust-1041`, `cust-1042` → iterate neighbors.
- **Derived**: `md5(email)` (32 hex), `base64(email:timestamp)` (decode it:
  `echo '…' | base64 -d`), UUIDv1 (contains MAC + timestamp — predictable).
- Compare keys character-by-character for fixed prefixes (vendor/env tags
  like `sk_live_`, `pk_test_` tell you what the key unlocks).

## Leakage hunting

- **JS bundles & source maps**:
  ```
  curl -sk https://app.example.com/static/main.js | \
    grep -oiE '(api[_-]?key|x-api-key|apikey|secret)["'"'"':= ]{0,6}[A-Za-z0-9_\-]{8,64}'
  curl -sk https://app.example.com/static/main.js.map | python3 -m json.tool | grep -i key
  ```
- **Mobile apps**: `unzip -p app.apk | strings | grep -iE 'api[_-]?key'`;
  also `res/values/strings.xml` and `assets/` config files after `apktool d`.
- **Git history**: `gitleaks detect -s <repo-dir> -v` or
  `trufflehog git https://git.example.com/org/repo.git --only-verified`.
  Check deleted files: `git log --diff-filter=D --name-only`.
- **Swagger/Postman artifacts**: example values in `/swagger.json`,
  `/openapi.json`, exported Postman collections — vendors frequently ship
  real keys as "examples".
- **Error messages**: trigger 500s (malformed JSON, oversized payloads) and
  read stack traces/config dumps for embedded keys.
- **Web archives**: historical copies of docs pages often contain keys that
  were later scrubbed but never rotated.

Any leaked key is only a finding once it **works** — replay it against a
real endpoint and capture the exchange for the `http_exchange` evidence
block.
