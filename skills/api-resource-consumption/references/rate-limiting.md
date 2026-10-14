# Rate-Limit Detection and Bypass (API4:2023)

## 1. Detection methodology

### What a limiter looks like on the wire

| Signal | Meaning |
|---|---|
| `429 Too Many Requests` | Hard limit fired. |
| `Retry-After: <sec or date>` | Window length; log it — it defines the brute-force budget. |
| `X-RateLimit-Limit / -Remaining / -Reset` | Classic GitHub-style headers; `-Remaining` counting down on every request confirms a counter *exists* even before it fires. |
| `RateLimit-Limit / -Remaining / -Reset` | IETF draft form, same semantics. |
| `X-Rate-Limit-*` | Twitter-style variant. |
| `503` + Retry-After | Overload shedding; treat as a soft limit. |
| Latency climbing monotonically, no 4xx | Tarpit / progressive delay. Confirm with a longer burst whether it ever hard-blocks. |
| Silent success with no effect (e.g. OTP "sent" but never arrives) | Shadow limiting. Needs out-of-band verification; note as suspected. |

### Burst design

1. **Baseline**: 3 single requests, 2 s apart. Record median latency and the
   rate-limit headers present.
2. **Burst**: 60 requests (enough to cross any sane per-minute limit on an auth
   endpoint) at concurrency 5. For non-auth endpoints 100–200 is reasonable.
3. **Window probe**: if throttled, wait `Retry-After` (or 60 s) and send 3 more
   to confirm the window resets. Threshold + window = the limiter's shape.
4. Stop as soon as the shape is known. The evidence is the timeline, not
   sustained pressure.

`scripts/ratelimit_probe.py` implements 1–2 and the bypass pass below.

### Determining the limiter key

Run the burst until throttled, then vary exactly one dimension and re-send 5
requests:

| Variation | If requests succeed again, limiter keys on… |
|---|---|
| New `Authorization` token, same IP | token/session |
| Same token, spoofed client-IP header | IP, and trusts proxy headers (bypass!) |
| Different account in the request body (e.g. login `email`) | the targeted account (per-victim lockout — note for `api-broken-auth`: password spraying across accounts evades it) |
| Different endpoint, same host | per-endpoint buckets (distribute the brute across route variants) |
| Nothing helps | global/WAF-level — try transport-level tricks below |

## 2. Bypass catalogue

### 2.1 Client-IP header spoofing

If the limiter keys on client IP and the app sits behind a proxy that it trusts
blindly, inject the "original client IP" yourself. Rotate a fresh random IP per
request in each of:

```
X-Forwarded-For: 203.0.113.7
X-Real-IP: 203.0.113.7
X-Client-IP: 203.0.113.7
True-Client-IP: 203.0.113.7
X-Originating-IP: 203.0.113.7
CF-Connecting-IP: 203.0.113.7
X-Remote-IP: 203.0.113.7
X-Remote-Addr: 203.0.113.7
Client-IP: 203.0.113.7
Forwarded: for=203.0.113.7
X-Forwarded-Host: 203.0.113.7
```

Variants to try if the plain header fails:
- Chained value: `X-Forwarded-For: 203.0.113.7, 198.51.100.1` (some parsers take
  first, some take last — rotate the position that varies).
- Localhost/trusted values: `127.0.0.1`, `::1`, `10.0.0.1` — some stacks exempt
  "internal" IPs from limiting entirely (one static value, no rotation needed).
- IPv6 and encoded forms: `::ffff:203.0.113.7`, `0xCB007107`.
- Duplicate the header twice with different values (front/back disagreement).

### 2.2 Route-normalization gaps

The limiter buckets on the raw path string; the router normalizes. Each variant
below can land in a fresh bucket while hitting the same handler:

```
/v1/login          → /v1/login/
                   → /v1//login
                   → /v1/Login        (case-insensitive routers)
                   → /v1/%2e/login    (dot-segment)
                   → /v1/login%20     /v1/login%00  /v1/login%09
                   → /v1/login?x=1    (query junk; rotate x's value per request)
                   → /./v1/login
```

Also try **version-path rotation** (`/v1/login`, `/v2/login`, `/api/login`,
`/mobile/v1/login`) — legacy routes frequently share the handler but not the
limiter — and **method variants** (`POST` vs `PUT` vs method-override headers
`X-HTTP-Method-Override: POST` on a GET).

### 2.3 Identifier encoding (when the limiter keys on a request value)

Per-account lockouts and per-target OTP limits usually key on the normalized
identifier. Desynchronize the limiter's view from the handler's view:

- Case: `User@example.net` vs `user@example.net`.
- Whitespace / null byte: `user@example.net%00`, `user@example.net ` (trailing
  space), `%0d%0a` suffix.
- Unicode confusables / NFKC tricks: `uѕer@example.net` (Cyrillic s) if the
  backend normalizes but the limiter doesn't (or vice versa).
- Plus-addressing: `user+1@example.net`, `user+2@...` — also the classic mass-
  account trick (see business-flows.md).
- JSON parameter pollution: `{"email":"a@example.net","email":"victim@example.net"}`
  — limiter reads first, handler reads last.

### 2.4 Transport-level

- **HTTP/2 multiplexing**: open one connection, fire dozens of concurrent
  streams. Per-connection limiters and some WAF counters undercount multiplexed
  streams. Outside the stdlib scripts, use:
  `for i in $(seq 1 50); do echo 'https://api.example.com/v1/login'; done | xargs -P1 -n50 curl --http2 -s -o /dev/null -w '%{http_code}\n' --parallel --parallel-max 50`
  or `h2load -n 100 -c 1 -m 50 https://api.example.com/v1/login`.
- **Connection churn**: `Connection: close` per request — some counters reset
  per connection.
- **Token/key rotation**: with self-service signup, mint N API keys and
  round-robin them; a per-token limit of 10/min × 20 tokens = 200/min.
- **Host-header variants**: `Host: api.example.com:443`, absolute-form request
  target — occasionally splits WAF buckets.

## 3. Reading `ratelimit_probe.py` output

The report JSON contains `baseline`, `timeline` (per-request
`{"n","status","ms","rl_headers"}`), `verdict`, and `bypass` (per technique:
`{"technique","sent","ok","throttled","works"}`).

- `verdict: "no-limit-observed"` on an auth-sensitive endpoint → finding
  (CWE-307 + CWE-770) and hand-off to `api-broken-auth`.
- `verdict: "throttled"` + any `bypass[].works == true` → bypass finding; the
  evidence is the throttled request/response followed by the bypassed 200.
- `verdict: "possible-tarpit"` → extend the burst, confirm shape, then decide.
- Always keep the first-throttle index and the `Retry-After`/reset values in the
  finding: they quantify the brute-force budget a real attacker gets.
