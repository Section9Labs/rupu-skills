# OAuth 2.0 / OIDC flows — identification and per-flow test matrix

For each flow: how to recognize it on the wire, the canonical requests, and
the tests that matter most for that flow.

## 1. Authorization code (confidential client)

**Recognize**: browser hits `authorization_endpoint` with
`response_type=code`, no `code_challenge`; backend exchanges at
`token_endpoint` with `client_id` + `client_secret` (Basic auth or body).

```
GET /oauth2/authorize?response_type=code&client_id=webapp
    &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
    &scope=openid%20profile&state=af0ifjsldkj HTTP/1.1
Host: login.example.com
Cookie: session=<authenticated>
```
```
POST /oauth2/token HTTP/1.1
Host: login.example.com
Authorization: Basic d2ViYXBwOnNlY3JldA==
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
```

**Test priority**: redirect_uri tampering (§2 of SKILL.md) → state/CSRF →
code replay → token-endpoint redirect_uri mismatch (exchange with a
*different* redirect_uri than authorize-time; RFC 6749 §4.1.3 requires
exact match) → scope widening at the token endpoint.

## 2. Authorization code + PKCE (public client)

**Recognize**: authorize request carries `code_challenge` +
`code_challenge_method=S256` (or `plain`); token exchange has
`code_verifier` and usually no client secret.

```
GET /oauth2/authorize?response_type=code&client_id=spa
    &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid
    &state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256 HTTP/1.1
```
```
POST /oauth2/token
grant_type=authorization_code&code=...&redirect_uri=...
&client_id=spa&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Test priority**: PKCE downgrade to `plain` → verifier omitted → verifier
wrong value → challenge omitted at authorize but code still exchangeable →
custom-URI / claimed-HTTPS redirect scheme hijack on mobile → state tests
still apply (PKCE does not stop login CSRF; only state/nonce do).

## 3. Implicit (`response_type=token` / `id_token token`)

**Recognize**: token returned directly in the redirect **fragment**; no
token-endpoint call.

```
HTTP/1.1 302 Found
Location: https://app.example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
    &token_type=Bearer&expires_in=3600&state=xyz
```

**Test priority**: is implicit *enabled at all* for a client that uses code
(response_type swap) → redirect_uri tampering (theft is one hop, no
exchange) → Referer/history leakage from the callback page → token
substitution (swap fragment token across users/clients; check `nonce` and
`at_hash` validation on the `id_token`) → missing `expires_in` enforcement.

## 4. Client credentials

**Recognize**: no browser; direct POST.

```
POST /oauth2/token
grant_type=client_credentials&client_id=batch&client_secret=...&scope=api:read
```

**Test priority**: secret recovered from a public artifact (JS bundle, APK,
docker image, git history) → `none`/missing auth accepted → scope
over-request (`scope=api:admin`) → token audience: can this
machine token call user-facing endpoints (confused deputy)?

## 5. Device authorization grant (RFC 8628)

**Recognize**: `device_authorization_endpoint` in metadata; client POSTs
there, gets `device_code` + `user_code` + `verification_uri`, then polls the
token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:device_code`.

**Test priority**: user_code entropy (short numeric codes are brute-forceable
— enumerate `verification_uri` with candidate codes) → phishing viability
(does the consent page show which client/scopes?) → polling with someone
else's device_code → no slow-down enforcement on polling.

## 6. ROPC / password grant

**Recognize**: `grant_type=password` with `username` & `password` in the
token POST.

```
POST /oauth2/token
grant_type=password&client_id=legacy&username=alice@example.com
&password=Winter2024!&scope=openid
```

**Test priority**: enabled at all (deprecated; bypasses MFA and consent) →
usable as a credential-stuffing/spraying oracle (distinct error for bad
user vs bad password?) → which clients may use it (try other client_ids) →
scope ceiling.

## 7. Hybrid (`response_type=code id_token`, `code token`, ...)

**Recognize**: both a `code` and a token/id_token in the fragment.

**Test priority**: all code-flow tests + all implicit tests; additionally
verify the client checks `c_hash` in the id_token binds the code — if not,
code substitution across flows works.

## 8. Refresh tokens (cross-cutting)

```
POST /oauth2/token
grant_type=refresh_token&refresh_token=8xLOxBtZp8&client_id=webapp
```

Tests: old refresh token still valid after use (no rotation) → rotation
without reuse-detection (using a rotated-out token should revoke the whole
chain) → scope widening on refresh → refresh token bound to client? (replay
with a different client_id) → lifetime (does it ever expire?).

## Flow decision cheat-sheet

| Observation | Flow |
|---|---|
| `response_type=code`, `code_challenge` present | code + PKCE |
| `response_type=code`, no challenge, secret at token endpoint | code (confidential) |
| `response_type=token` / `id_token token`, fragment delivery | implicit |
| `code id_token` etc. | hybrid |
| `grant_type=client_credentials` | machine-to-machine |
| `grant_type=password` | ROPC |
| device/user codes + polling | device grant |
