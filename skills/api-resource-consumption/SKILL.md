---
name: api-resource-consumption
description: Tests APIs for OWASP API4:2023 Unrestricted Resource Consumption and API6:2023 Unrestricted Access to Sensitive Business Flows — proves presence/absence of rate limits per IP/token/account/endpoint, bypasses limiters via header rotation and path variants, demonstrates pagination/payload/expensive-op amplification, and scripts sensitive business flows (account farming, coupon/referral fraud, scalping, spam) at scale. Use in phase 6 of the api-testing flow, once endpoints are mapped and authenticated sessions exist.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Resource Consumption & Business-Flow Abuse (API4 / API6)

Phase 6 of the `api-testing` flow. Inputs: the endpoint inventory from discovery
(OpenAPI/Swagger doc or crawled route list) and at least one working credential set
per role. Outputs: findings for missing/bypassable rate limits, amplification
vectors, and automatable business flows — plus a hand-off list of unthrottled
auth endpoints for `api-broken-auth`.

Core discipline: **baseline one request, then show the slope.** Prove the absence
of a control with the minimum volume that makes the absence undeniable (the Nth
success where a limit should have fired, a 50x response-size ratio, 50 scripted
accounts). Do not sustain load past the proof — you are demonstrating that a DoS
or mass-abuse is *possible*, not performing one.

## 0. Select targets and fan out

Split the API surface into per-resource work units using the reporting pack's
`work-units` skill (do not write your own splitter):

```
python3 <work-units>/scripts/split.py openapi reports/openapi.json \
  --out reports/api-resource-consumption-units.json
```

Prioritize units whose operations are: authentication-adjacent (login, OTP,
password-reset, signup), money-adjacent (checkout, coupon, transfer, payout),
notification-sending (SMS/email/push), list/search/export, file upload/download,
or anything with pagination/expansion parameters. Mark the service and every
endpoint you touch with `assets.mark` (`api:service` / `api:endpoint`, depth
`mapped` → `tested` → `exploited`). Wiring, fan-out, and the exact asset shapes:
`references/rupu.md`.

## 1. Rate-limit testing (API4)

Goal per endpoint: answer four questions — does *any* limit exist, what does the
limiter key on (IP / token / account / endpoint / global), when does it fire,
and can it be bypassed?

### 1a. Establish the baseline and burst

```
python3 scripts/ratelimit_probe.py \
  --url https://api.example.com/v1/login --method POST \
  --header 'Content-Type: application/json' \
  --body '{"email":"probe@example.net","password":"wrong-{{i}}"}' \
  --count 60 --concurrency 5 \
  --out reports/rl-login.json --units reports/rl-login-units.json
```

The script sends the burst, records per-request status/latency and every
rate-limit response header (`Retry-After`, `X-RateLimit-*`, `RateLimit-*`),
and reports the first throttle event — or its absence. Read the verdict:

- `no-limit-observed` after 60+ POSTs to a login endpoint = finding (CWE-307/770)
  and a brute-force surface: hand the endpoint to `api-broken-auth`.
- `throttled` with the first-429 index = the limit threshold. Continue to 1b.
- `possible-tarpit` (latency climbing without 429) = a soft limit; raise
  `--count` modestly and confirm whether it ever hard-blocks.

Repeat the burst with a *second token/account* (`--header 'Authorization: Bearer
<other>'`). If the second identity is fresh, the limiter keys on token/account,
not IP — token rotation defeats it. If the second identity is also blocked, it
keys on IP → header spoofing (1b) is the attack.

### 1b. Limit-bypass pass

```
python3 scripts/ratelimit_probe.py --url https://api.example.com/v1/login \
  --method POST --body '...' --count 60 --bypass --out reports/rl-login-bypass.json
```

`--bypass` runs, after the throttle fires, a short burst per technique and
reports which ones restore 2xx/normal responses:

- **Client-IP header rotation**: `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`,
  `True-Client-IP`, `X-Originating-IP`, `CF-Connecting-IP`, `Forwarded:
  for=...`, each with a fresh random IP per request.
- **Path variants** the limiter may not normalize: trailing slash, double slash,
  case-swapped last segment, `/%2e/` segment insertion, appended junk query
  parameter, `%00`/`%20` suffix on the path.
- **Token switch** (if `--alt-token` supplied) to confirm the per-token keying.

Any technique that converts a sustained 429 back into 200s is a limiter bypass
finding on its own (CWE-770 + CWE-290 flavor). Manual follow-ups worth doing by
hand — HTTP/2 multiplexing, method/version-path variants, header-casing tricks —
are in `references/rate-limiting.md`.

### 1c. Classify the auth-sensitive gaps

For every endpoint among {login, OTP verify, password-reset request, MFA code,
promo/coupon redemption} where the verdict is `no-limit-observed` or a bypass
works: record the finding, mark the endpoint `tested` (or `exploited` once a
real brute/abuse is shown), and append it to the hand-off list for
`api-broken-auth` with the working bypass header noted in `hints`.

## 2. Resource amplification (API4)

Prove that one cheap request forces the server to do expensive work. Always
capture the pair (baseline request → baseline time/size, amplified request →
amplified time/size) as the evidence; the ratio is the finding's impact number.

Test, per endpoint class (full payloads and measurement method in
`references/amplification.md`):

- **Pagination abuse**: `?limit=100000`, `?per_page=100000`, `?page_size=-1`,
  `?limit=0`, and *removing* the param entirely. Compare response size and time
  against `limit=10`. A 10 MB / 30 s response from an unauthenticated list
  endpoint is a one-request DoS primitive.
- **Unbounded list/search/export**: search with `*`/empty query, CSV/PDF export
  of a full table, report-generation endpoints. These often bypass pagination
  entirely.
- **Expansion parameters**: wide `?include=`, `?expand=`, `?fields=` values and
  nested expansions (`expand=orders.items.product.reviews`) that trigger N+1
  query storms. Watch latency, not just size.
- **Large/deep request bodies**: multi-MB JSON bodies, 1000-deep nesting,
  100k-element arrays, duplicated keys. Server-side parse time is the cost.
- **Decompression bombs**: gzip-encoded request bodies and zip uploads with
  extreme ratios where uploads are accepted.
- **ReDoS**: endpoints that validate/search with regex — probe with
  `aaaa...aaa!` style catastrophic-backtracking inputs and measure the latency
  curve as input length grows linearly.
- **Costly third-party ops**: anything that sends SMS/email/push, renders a
  PDF/image, or calls a paid upstream per request. Here the rate-limit absence
  *is* the amplification: 60 unthrottled calls to an SMS-OTP endpoint is a
  direct monetary-cost finding. Use `ratelimit_probe.py` on these and report the
  per-call cost dimension.

Mark each endpoint `tested` after probing; `exploited` when an amplification
ratio or cost-per-call abuse is demonstrated with captured evidence.

## 3. Sensitive business-flow abuse (API6)

Identify flows whose *automation at scale* harms the business even though each
individual call is legitimate: bulk purchase/scalping and inventory hoarding
(cart-hold without checkout), mass account creation, coupon/referral/loyalty
farming, review/comment/message flooding, vote or rating manipulation. The
full catalogue, per-flow harm model, and friction checklist are in
`references/business-flows.md`.

For each candidate flow, write a flow template and script it end-to-end N times:

```
python3 scripts/flow_abuse.py --flow flows/signup-referral.json \
  --iterations 50 --delay 0.2 \
  --out reports/flow-signup.json --units reports/flow-signup-units.json
```

The flow file is a JSON sequence of request steps with `{{var}}` substitution
(`{{i}}` iteration counter, `{{rand}}`, `{{uuid}}`, `{{ts}}` builtins) and
regex `extract` rules to carry tokens/IDs between steps — e.g. signup →
verify → redeem-referral. The script reports successes per iteration, status
distribution, and the first point (if any) where friction stopped it; it also
flags captcha/challenge markers in response bodies.

Verdict interpretation:

- `no-friction` across 50 iterations of account-creation + referral-redemption
  = verified API6 finding (CWE-799 / CWE-837): one actor scripted the flow with
  no captcha, no device/velocity check, no per-account or global cap. The 50th
  success is the evidence; mark the flow's endpoints `exploited`.
- `friction-at-N`: record *what* fired (429, captcha marker, account lock) and
  at what N — then attempt the 1b bypasses against the friction point and
  re-run. A friction control that keys on IP and falls to `X-Forwarded-For`
  rotation is still a finding.

## 4. Evidence and reporting

For every verified issue, keep: the burst/flow timeline JSON from the scripts,
one representative raw request/response pair, and the headline number (count of
successes, first-throttle index, amplification ratio, accounts created). Report
with `findings.report` under the `api` profile, pinned to the `api:endpoint`
`http_route` coordinate, with an `http_exchange` evidence block — CWE-770 for
missing/bypassable limits and amplification, CWE-799/CWE-837 for business-flow
abuse. Full contract: the imported `finding-report` skill; wiring and the
hand-off to `api-broken-auth`: `references/rupu.md`.
