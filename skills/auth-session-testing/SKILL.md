---
name: auth-session-testing
description: Test authentication and session management (WSTG-ATHN, WSTG-SESS, WSTG-IDNT) — username enumeration, credential stuffing/brute force with hydra and ffuf, auth-flow bypasses, password-reset flaws, JWT attacks with jwt_tool, cookie/session-lifecycle weaknesses, and OAuth/SSO basics. Use whenever a target exposes login, logout, registration, password reset, MFA, remember-me, SSO, or any session-token mechanism.
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: "WSTG-ATHN, WSTG-SESS, WSTG-IDNT"
---

# Authentication & Session Management Testing

Input: login/registration/reset/session endpoints (from crawling, from the operator, or
from a `work-units` fan-out). Output: confirmed weaknesses — valid credentials, auth
bypasses, forgeable or crackable tokens, broken session lifecycle, bad cookie flags —
each recorded as a rupu finding. **Every parse/handoff step below ends in a rupu
output** (work-units JSON array, `assets.mark`, or `findings.report`) — exact JSON
shapes in `references/rupu.md`.

## 0. Map the auth surface

1. Enumerate every auth-relevant route: `/login`, `/logout`, `/register`, `/signup`,
   `/forgot-password`, `/reset`, `/password/change`, `/mfa`, `/oauth/authorize`,
   `/api/auth/*`, `/session`, `/token`. Proxy a full manual walkthrough of
   signup -> login -> use -> logout through Burp or mitmproxy
   (`mitmdump -w auth_flows.mitm "~d example.com"`) so you have every request on file.
2. Capture for later analysis:
   - the exact login request (method, params, failure string, success indicator),
   - every `Set-Cookie` before and after login,
   - any JWT (cookies, `Authorization: Bearer`, localStorage via DOM, URL params),
   - the password-reset email/request/response trio,
   - CSRF token locations and whether they change per request/session.
3. Mark each discovered route with `assets.mark` kind `web:route`, depth `crawled`
   (raise to `tested`/`exploited` as you progress). Emit a work-units array (one unit
   per auth mechanism found: login-bruteforce, reset-flow, jwt, cookies, oauth) and
   hand it to the `work-units` skill for fan-out. Shapes: `references/rupu.md`.

## 1. Credential attacks (WSTG-IDNT-04, WSTG-ATHN-02/03)

Full flag detail, enumeration technique, and lockout/CAPTCHA handling:
`references/credential-attacks.md`.

1. **Username enumeration first.** Compare responses for a known-valid vs invalid
   username on login, reset, AND register (register is usually the leakiest: "email
   already taken"). Differentials to compare: status code, body length, error string,
   redirect target, response time (bcrypt only runs for valid users — a 50–300 ms
   timing gap is a signal). Use ffuf with a username list and match/filter flags:
   ```
   ffuf -w users.txt -u https://example.com/login -X POST \
        -d "user=FUZZ&pass=xxx" -H "Content-Type: application/x-www-form-urlencoded" \
        -mc all -fr "Invalid username or password"
   ```
   Anything that escapes the filter is a differential. Valid usernames -> work units.
2. **Default/weak creds.** Try vendor defaults (admin/admin, admin/password,
   tomcat/s3cret...) against admin panels and framework consoles before brute force.
3. **Password brute force / stuffing** with hydra:
   ```
   hydra -L users.txt -P passwords.txt example.com https-post-form \
     "/login:user=^USER^&pass=^PASS^:F=Invalid username" -t 16 -o hydra.out -I
   ```
   Get the failure string `F=` (or success string `S=`) from your captured login.
   ffuf clusterbomb alternative (JSON output for parsing):
   ```
   ffuf -w users.txt:USERW -w passwords.txt:PASSW -u https://example.com/login \
        -X POST -d "user=USERW&pass=PASSW" -mode clusterbomb -fc 401 -o ffuf.json -of json
   ```
   Alternatives: medusa, patator (fine-grained failure conditions), wpscan for
   WordPress (`wpscan --url https://example.com -U users.txt -P pass.txt`).
4. **Lockout / rate limiting / CAPTCHA** (WSTG-ATHN-03): count attempts until
   lockout; test bypasses — `X-Forwarded-For` rotation, case/encoding variants of the
   username, alternate endpoints (mobile API, XML vs JSON body), per-IP vs per-account
   limits, CAPTCHA parameter removal or replay. No lockout after 20+ failures is
   itself a finding (CWE-307).
5. **Record**: each cracked credential pair -> `findings.report` (scope `endpoint`,
   target_ref the login URL, severity high/critical, WSTG-ATHN-02 or ATHN-03,
   CWE-521/CWE-307, evidence = the successful request/response exchange). Mark the
   login route `exploited`. Use the `finding-report` skill for the write-up.

## 2. Auth-flow flaws (WSTG-ATHN-01/04/05/08, WSTG-ATHZ-01)

Details and payloads: `references/sessions-and-flows.md`.

- **Transport** (WSTG-ATHN-01): does the login form or any credential POST go over
  http://? Does the site redirect http->https *before* credentials are sent? Check
  HSTS. Low/medium finding, trivial evidence.
- **SQLi auth bypass**: `' OR '1'='1'-- -` family in username/password; if the login
  looks injectable, hand the captured request to sqlmap:
  `sqlmap -r login.txt --batch --level=3 --risk=3 --technique=BEUSTQ`.
- **Response manipulation**: proxy the login, flip `{"success":false}` -> `true`,
  `403` -> `200`, strip or alter role fields. mitmproxy addon or Burp Repeater.
- **Forced browsing**: request post-login URLs (`/dashboard`, `/admin`,
  `/api/me`) with no session / an anonymous session. Also HTTP verb switching
  (GET->POST), and path tricks (`/admin/.`, `//admin`, `/ADMIN`).
- **Parameter tampering**: add/flip `admin=true`, `role=admin`, `is_staff=1`,
  `user_id=<other>` on login, registration, and profile-update requests.
- **Remember-me** (WSTG-ATHN-05): decode the persistent cookie — base64 of
  `user:hash`? predictable? Does it survive password change? Check
  `Cache-Control`/`autocomplete` on the login form.
- **Security questions** (WSTG-ATHN-08): guessable answers, unlimited attempts,
  answers enumerable via reset flow.
- **Password reset** (WSTG-ATHN-09 territory): the highest-value flow —
  1. **Host-header poisoning**: send the reset request with
     `Host: attacker.example.net` (and `X-Forwarded-Host`); if the emailed link uses
     it, the token leaks to you when the victim clicks.
  2. **Token predictability**: request several tokens for your own account, diff
     them (timestamp? sequential? md5(email)?). Short/numeric tokens -> brute force
     with ffuf.
  3. **Token leakage**: reset landing page loading third-party resources leaks the
     token in `Referer`.
  4. **Token reuse / no expiry**: use the same token twice; use it after a second
     token was issued; use it after the password already changed.
  5. **User-id tampering**: if the reset-confirm request carries
     `email=`/`user_id=` alongside the token, swap it to another user.

Record every confirmed bypass via `findings.report` (scope `endpoint`, WSTG id +
CWE-287/CWE-640, evidence = the exact exchange that crossed the gate) and mark the
route `exploited`.

## 3. JWT attacks (WSTG-SESS, CWE-345/CWE-347)

Full jwt_tool flags and per-attack walkthroughs: `references/jwt.md`.

1. **Decode every JWT** you capture:
   `python3 scripts/analyze_jwt.py <token> --json jwt_report.json --work-units jwt_wu.json`
   — reports alg, claims, expiry, and flags: alg:none potential, HMAC (crackable)
   vs RSA, missing/absurd `exp`, interesting claims (`role`, `admin`, `kid`, `jku`).
   The `--work-units` array is one unit per attack worth attempting; hand it to the
   `work-units` skill.
2. **Run the playbook** with jwt_tool, replaying each forged token against an
   authenticated endpoint and reading the status/body:
   - Baseline + known exploits: `jwt_tool <token> -t https://example.com/api/me -rh "Authorization: Bearer <token>" -M at`
   - **alg:none**: `jwt_tool <token> -X a` (tries none/None/NONE/nOnE variants).
   - **Weak HMAC secret**: `jwt_tool <token> -C -d rockyou.txt`; on success re-sign
     with `-S hs256 -p "<secret>"` after `-T` tampering claims.
   - **RS256->HS256 key confusion**: grab the public key
     (`/jwks.json`, `/.well-known/jwks.json`, TLS cert) then `jwt_tool <token> -X k -pk public.pem`.
   - **kid injection**: `-I -hc kid -hv "../../dev/null"` + sign HS256 with empty
     key, or SQLi in kid (`-Q`-style payloads); **jku/x5u SSRF**: point them at your
     interactsh host serving your own JWKS, re-sign with your key.
   - **Claim tampering**: `-T` interactive, or `-I -pc role -pv admin`; also strip
     `exp` or set it far future on expired-token endpoints.
3. Any forged token accepted = critical/high finding. Evidence must show the forged
   token, how it was built, and the authenticated response it earned. Record with
   `findings.report` (scope `endpoint`, CWE-347, WSTG-SESS) and mark the API route
   `exploited`.

## 4. Session management (WSTG-SESS-01..10)

Mechanics and full checklists: `references/sessions-and-flows.md`.

1. **Cookie attributes** (WSTG-SESS-02, CWE-614/CWE-1004): run
   ```
   python3 scripts/session_audit.py --response login_response.txt \
       --json session_report.json --work-units sess_wu.json --findings sess_findings.json
   ```
   on captured responses (or feed it a JSON of login/logout pairs — see `--help`).
   It evaluates `Secure`, `HttpOnly`, `SameSite`, `Domain`/`Path` scope, `Expires`/
   `Max-Age`, cookie-name token leakage, and (given pre/post-login pairs) **session
   fixation** — and emits merged JSON, a work-units array of weaknesses to confirm
   manually, and ready-to-submit `findings.report` payloads.
2. **Token entropy** (WSTG-SESS-01): collect 100+ session ids (Burp Sequencer, or a
   loop + the Sequencer live-capture). Patterns to catch by eye: timestamps,
   incrementing counters, base64 of username/IP, short hex. Predictable id -> session
   hijack finding.
3. **Session fixation** (WSTG-SESS-03): note the pre-login session id, log in, check
   whether `Set-Cookie` issued a NEW id. Same id after auth = fixation. Also test:
   does the server accept an id *you* minted/set before login?
4. **Lifecycle** (WSTG-SESS-06/07): after logout, replay an authenticated request
   with the old cookie/JWT — still 200? After password change, do other sessions die?
   Idle/absolute timeout: replay after N minutes. JWTs with no server-side
   revocation fail all of these by construction — demonstrate it.
5. **Concurrent sessions**: log in from two clients; policy (allow/kill-oldest) is
   context-dependent, but silent unlimited concurrency on sensitive apps is reportable.
6. **CSRF** (WSTG-SESS-05) as a session-trust issue: is there a token? Does the
   server actually *validate* it (remove it, blank it, swap another session's token)?
   Is the app relying solely on `SameSite=Lax` (GET-based state changes still work,
   and Lax allows top-level POST within 2 min on some Chrome versions)? Build a PoC
   auto-submit form for any state-changing request that passes without a valid token.

Each confirmed issue -> `findings.report` with scope `endpoint` (scope `host` only
for host-wide ones like missing HSTS), WSTG-SESS id + CWE (384 fixation, 614 Secure,
1004 HttpOnly, 613 expiration, 352 CSRF), evidence = the header/request pairs. The
`session_audit.py --findings` output is pre-shaped for this; finish via the
`finding-report` skill.

## 5. OAuth / SSO (brief — WSTG-ATHZ/SESS boundary)

Checklist in `references/sessions-and-flows.md` §OAuth:
- **redirect_uri**: try full replacement, subdomain/suffix tricks
  (`https://example.com.attacker.example.net`), path traversal
  (`https://example.com/callback/../open-redirect`), open-redirect chaining.
- **state**: absent or not validated -> login CSRF; replay a used state.
- **Implicit flow**: tokens in the URL fragment leak via Referer/history/JS.
- Also: code reuse, PKCE downgrade (drop `code_challenge`), `response_type` mixing.
Deeper SSO/SAML testing is its own engagement track — record what you confirm here
(WSTG-ATHZ, CWE-601 for redirect_uri abuse) and hand remaining leads off as work units.

## Chaining summary

```
routes in ──> §0 map ──assets.mark──> work units (per mechanism) ──work-units skill──>
  §1 creds ──> valid creds ──────────────┐
  §2 flows ──> bypass / reset takeover ──┤
  §3 jwt  ──> forged token ──────────────┼──> findings.report (finding-report skill)
  §4 sess ──> fixation/lifecycle/CSRF ───┤        + assets.mark depth=exploited
  §5 oauth ──> redirect/state issues ────┘
```

Valid creds and forged tokens also feed the authorization-testing track (IDOR,
privilege escalation): emit them as work units with `hints.credentials` /
`hints.token` so the next agent starts authenticated.
