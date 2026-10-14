# OAuth/OIDC attack catalog — precondition / steps / confirm / remediation

Each entry maps to a SKILL.md section. "Confirm" is the evidence to put in
the finding's `http_exchange` block.

---

## A1. redirect_uri — full replacement

- **Precondition**: AS does substring/regex/no validation of redirect_uri.
- **Steps**: authenticated browser loads
  `.../authorize?response_type=code&client_id=webapp&redirect_uri=https%3A%2F%2F203.0.113.50%2Fcb&scope=openid&state=x`.
- **Confirm**: 302 with `Location: https://203.0.113.50/cb?code=...`; code
  lands in attacker HTTP server log; exchange yields tokens.
- **Remediation**: exact string match against pre-registered URIs; reject on
  mismatch; enforce again at the token endpoint.

## A2. redirect_uri — subdomain / suffix confusion

- **Precondition**: validation is "ends with example.com" or "starts with
  https://app.example.com".
- **Steps**: try `https://evil.app.example.com/cb`,
  `https://app.example.com.203.0.113.50/cb`, `https://appxexample.com/cb`
  (if dot treated as wildcard in a regex), `https://app.example.com/cb/../x`,
  `https://app.example.com/cbEXTRA`.
- **Confirm**: 302 to the tampered host/path carrying the code.
- **Remediation**: exact match; no prefix/suffix/regex schemes.

## A3. redirect_uri — @-userinfo and parser differential

- **Precondition**: AS validates with one URL parser, browser resolves with
  another.
- **Steps**: `redirect_uri=https://app.example.com@203.0.113.50/cb`,
  backslash variant `https://app.example.com\@203.0.113.50/cb`, double
  encoding `https%3A%2F%2Fapp.example.com%252F@203.0.113.50/`.
- **Confirm**: browser lands on 203.0.113.50 with the code.
- **Remediation**: canonicalize once, exact match, reject userinfo.

## A4. redirect_uri — open redirect chain on allowed host

- **Precondition**: a registered redirect host has any open redirect or
  attacker-influenced page (OOB redirector, XSS, path on a CDN bucket).
- **Steps**: `redirect_uri=https://app.example.com/redirect?url=https://203.0.113.50/`
  (exact-match may still pass if `?url=` is part of a prefix-matched path, or
  if the registered URI itself is the redirector). For implicit, the fragment
  survives the hop automatically; for code, use `Referer` leakage or a second
  redirect that reflects the query string.
- **Confirm**: code/token observed on attacker host.
- **Remediation**: no open redirects on redirect_uri hosts; exact-match
  including query; `Referrer-Policy: no-referrer` on callback pages.

## A5. redirect_uri — localhost / dev whitelist

- **Precondition**: `http://localhost`/`127.0.0.1` globally allowed (common
  for native apps, RFC 8252), but client is a web app on a victim machine
  where attacker can bind the port, or AS allows arbitrary ports/paths.
- **Steps**: `redirect_uri=http://localhost:8000/cb`, `http://127.0.0.1:1337/cb`.
- **Confirm**: AS 302s to loopback with the code.
- **Remediation**: loopback only for native clients with PKCE; exact path.

## A6. state — missing/not validated (login CSRF)

- **Precondition**: client omits state or accepts callbacks with
  absent/stale state.
- **Steps**: (1) remove `state` from authorize URL → complete flow → client
  accepts callback. (2) deliver `https://app.example.com/cb?code=<attacker's
  own code>` to a victim session.
- **Confirm**: victim session now bound to attacker identity (or attacker
  code consumed in victim session) — show the callback request and the
  authenticated response that follows.
- **Remediation**: per-session random state, verified and single-use;
  OIDC `nonce` additionally.

## A7. PKCE — downgrade to plain

- **Precondition**: `code_challenge_methods_supported` includes `plain`, or
  method parameter unvalidated.
- **Steps**: proxy-rewrite `code_challenge_method=S256` → `plain` and set
  `code_challenge=<the verifier value>`; exchange with
  `code_verifier=<same>`.
- **Confirm**: token endpoint 200 with tokens.
- **Remediation**: S256 only; reject `plain`.

## A8. PKCE — not enforced / verifier ignored

- **Precondition**: AS stores but never checks the challenge, or treats
  PKCE as optional per request rather than per client.
- **Steps**: (a) exchange a PKCE-initiated code with no `code_verifier`;
  (b) exchange with `code_verifier=` 43×`A`; (c) start flow with no
  `code_challenge` for a PKCE client and exchange normally.
- **Confirm**: any of a/b/c returns 200 + tokens.
- **Remediation**: require and verify PKCE for all public clients; bind
  challenge to code; reject missing/incorrect verifier.

## A9. Scope escalation

- **Precondition**: AS grants scopes beyond client registration, or RS
  trusts token scope without checking the client's entitlement; or refresh
  flow honors widened scope.
- **Steps**: authorize with `scope=openid profile admin api:write
  offline_access`; token-exchange/refresh with widened `scope=`;
  introspect result; call a privileged endpoint.
- **Confirm**: `GET /v1/admin/users` → 200 with the escalated token;
  introspection shows the unauthorized scope.
- **Remediation**: validate requested scopes against client registration at
  authorize AND token time; refresh may only narrow scope (RFC 6749 §6).

## A10. Implicit — token in fragment leakage

- **Precondition**: `response_type=token`/`id_token token` honored.
- **Steps**: swap response_type to `token` for the same client_id; harvest
  from browser history/proxy; demonstrate Referer leak from callback page.
- **Confirm**: 302 Location fragment contains `access_token=`; token works
  against the API.
- **Remediation**: disable implicit; code+PKCE everywhere.

## A11. Implicit — token substitution / audience confusion

- **Precondition**: SPA treats any valid access_token as login proof; no
  `at_hash`/`nonce` check; RS skips `aud`/`azp`.
- **Steps**: obtain token for user B / client C; substitute it into user A's
  callback fragment; or present client-C token to client-A's API.
- **Confirm**: session established as the substituted identity; API accepts
  the cross-audience token.
- **Remediation**: validate id_token (`iss`,`aud`,`nonce`,`at_hash`); RS
  must check `aud` and `azp`.

## A12. Authorization-code replay

- **Precondition**: code not single-use, or reuse doesn't revoke issued tokens.
- **Steps**: exchange the same code twice (second attempt within and after
  the 10-minute window).
- **Confirm**: second 200; first token still live afterwards.
- **Remediation**: single-use codes; on reuse revoke all tokens from that code.

## A13. Refresh token — no rotation / no reuse detection

- **Precondition**: public client with long-lived static refresh tokens.
- **Steps**: refresh once, then present the *previous* refresh token again;
  if rotated, present a rotated-out token and check whether the chain is
  revoked.
- **Confirm**: old token still mints access tokens.
- **Remediation**: rotation + reuse-detection with family revocation
  (RFC 9700 / OAuth Security BCP).

## A14. client_secret in public artifact / none auth

- **Precondition**: secret shipped in JS/mobile/container, or token endpoint
  accepts `client_id` alone for a confidential client.
- **Steps**: grep bundles (`grep -rE 'client_secret|clientSecret' dist/`);
  test the secret with `grant_type=client_credentials`; retry omitting it.
- **Confirm**: 200 + token as the client.
- **Remediation**: public clients get no secret (PKCE instead); rotate
  leaked secrets; require private_key_jwt/mTLS for confidential clients.

## A15. Mix-up / confused deputy (multi-IdP, multi-tenant)

- **Precondition**: client talks to >1 AS or AS serves >1 tenant with shared
  keys/issuer handling; client doesn't pin `iss` per flow.
- **Steps**: start a flow against AS-A, answer the callback with a code/token
  from AS-B (attacker-controlled or second tenant); present tenant-B tokens
  to tenant-A APIs sharing a jwks.
- **Confirm**: client exchanges the foreign code at the wrong AS leaking it,
  or RS accepts the cross-tenant token.
- **Remediation**: `iss` parameter on the authorization response (RFC 9207)
  and per-issuer redirect URIs; RS validates `iss`+`aud` strictly.

## A16. Dynamic client registration abuse

- **Precondition**: `registration_endpoint` open (no initial access token).
- **Steps**:
  `curl -sk -X POST .../register -H 'Content-Type: application/json' -d '{"redirect_uris":["https://203.0.113.50/cb"],"client_name":"support-portal","grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}'`
  then run a full flow as that client; also test SSRF via `logo_uri`,
  `jwks_uri`, `sector_identifier_uri` pointing at internal addresses.
- **Confirm**: 201 with client_id; phishing-grade consent page; or SSRF
  callback received.
- **Remediation**: gate registration; validate/fetch metadata URLs safely.
