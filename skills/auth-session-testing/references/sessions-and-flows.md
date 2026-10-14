# Sessions, cookies, auth flows, reset, CSRF, OAuth (WSTG-SESS, WSTG-ATHN)

## 1. Cookie attributes (WSTG-SESS-02)

For every `Set-Cookie` that carries session state, check:

| Attribute | Absent means | CWE | Severity (session cookie) |
|---|---|---|---|
| `Secure` | cookie sent over cleartext http → on-path theft | CWE-614 | medium |
| `HttpOnly` | readable by JS → XSS = session theft | CWE-1004 | medium |
| `SameSite` | sent on cross-site requests → CSRF enabler | CWE-1275 | low (contextual) |
| `Expires`/`Max-Age` long or persistent on a session cookie | survives browser close, shared machines | CWE-613 | low |
| `Domain=.example.com` (broad) | leaks to all subdomains incl. takeover-able ones | CWE-1004-adjacent (scoping) | low/medium |
| `Path=/` on a sub-app cookie | leaks across co-hosted apps | — | low |

Also check:
- `__Host-` / `__Secure-` prefixes absent (prefixes enforce Secure + host scoping).
- Cookie VALUE content: base64-decode it — user id, role, email, or a serialized
  blob inside a "session id" is a finding on its own (and a deserialization lead).
- `SameSite=None` without `Secure` is rejected by browsers; `SameSite=Lax` still
  sends cookies on top-level GET navigations — GET-based state changes stay CSRF-able.
- Session id in URL (`;jsessionid=`, `?PHPSESSID=`): WSTG-SESS, CWE-598 — leaks via
  Referer/logs/history.

Run `scripts/session_audit.py` on the captured login response — it grades all of
this and emits findings payloads (see `references/rupu.md`).

## 2. Token entropy and structure (WSTG-SESS-01)

1. Collect 100–500 session ids: Burp Sequencer (live capture on the login response's
   Set-Cookie, then "Analyze now"; read the "overall result" effective entropy and
   char-level analysis), or script a login loop and dump ids.
2. Manual structure checks before trusting entropy stats:
   - length < 16 bytes of randomness → brute-forceable space;
   - base64/hex-decode: timestamps (leading digits increasing per request),
     counters, `md5(username)`, IP fragments;
   - compare two ids issued seconds apart — long shared prefixes = structure.
3. Framework defaults (Django, Rails, express-session, PHP ≥7.1 session ids) are
   fine; hand-rolled ids are where the findings live.
4. Predictable id → demonstrate by predicting/deriving a second session's id.
   Finding: WSTG-SESS-01, CWE-330/CWE-331, high.

## 3. Session fixation (WSTG-SESS-03, CWE-384)

1. GET the login page anonymously; record the pre-auth session id (if any).
2. Log in; diff the post-auth `Set-Cookie`.
3. **Same id** = fixation. Exploit path: attacker sets/plants the id (URL param,
   subdomain cookie-tossing, XSS on a sibling app), victim logs in, attacker's copy
   is now authenticated.
4. Stronger variant: set an arbitrary cookie value yourself
   (`Cookie: SESSIONID=vulture-fixed-0001`), then log in — does the server *adopt*
   your value into an authenticated session?
5. Also verify rotation on privilege change (user → admin su, MFA step-up).

`session_audit.py --pairs` automates the diff when given pre/post-login exchanges.

## 4. Session lifecycle (WSTG-SESS-06/07, CWE-613)

- **Logout invalidation**: capture an authenticated request, log out, replay the
  request with the old cookie/JWT. 200 + data = server-side session not destroyed.
  (Client-side-only logout — cookie deleted but still valid — is the common failure.)
- **Password change**: change password in session A; is session B (other browser)
  still alive? Should die (session riding after credential theft).
- **Idle timeout**: replay after 15/30/60 min idle. **Absolute timeout**: replay a
  day-old session. No timeout on a sensitive app = low/medium.
- **JWT-specific**: stateless JWTs cannot be revoked without a server-side list —
  demonstrate the logged-out JWT still working and report it (CWE-613).
- **Concurrent sessions**: two parallel logins, both alive, no notification —
  info/low, context-dependent.

## 5. CSRF (WSTG-SESS-05, CWE-352)

For each state-changing request (POST/PUT/DELETE, and any state-changing GET):
1. Is there an anti-CSRF token (hidden field, custom header, double-submit cookie)?
2. **Validation tests** — resend the request with:
   - token removed entirely;
   - token blank (`csrf=`);
   - token from a DIFFERENT session (your second account);
   - token with last char changed;
   - method flipped POST→GET (some frameworks skip CSRF checks on GET);
   - `Content-Type` changed to `text/plain` (dodges preflight AND some middleware).
3. If only `SameSite` protects it: Lax still allows top-level GET (and some Chrome
   builds allow top-level POST within 2 minutes of cookie creation); subdomain XSS
   or an open sibling app also bypasses it. Sole-reliance = reportable, low/medium.
4. PoC for any pass-through:
   ```html
   <form action="https://example.com/account/email" method="POST" id="f">
     <input name="email" value="attacker@example.net"></form>
   <script>document.getElementById('f').submit()</script>
   ```
   Load from a second origin, confirm the change landed. Evidence = PoC + the
   successful exchange. For JSON APIs, test whether form-encoded/text-plain bodies
   are also accepted (if not, and no CORS misconfig exists, CSRF may be moot).

## 6. Auth-flow details (WSTG-ATHN-01/04/05/08)

### Credentials over unencrypted channel (ATHN-01, CWE-319)
- Login form served over http, or posting to http, or http→https redirect only
  AFTER the form page loaded (SSLstrip window). Check `Strict-Transport-Security`
  header, preload status, and mixed content on the login page.

### Auth bypass (ATHN-04, CWE-287/CWE-288)
- **SQLi**: `' OR '1'='1'-- -`, `admin'-- -`, `') OR 1=1--` in user and pass fields;
  on hit, hand the request file to sqlmap:
  `sqlmap -r login.txt --batch --level=3 --risk=3 --technique=BEUSTQ`.
- **NoSQL**: `user[$ne]=x&pass[$ne]=x` (form), `{"user":{"$ne":null},"pass":{"$ne":null}}`
  (JSON), `$regex` for char-by-char password extraction.
- **Response manipulation**: intercept the login RESPONSE; flip `success:false→true`,
  `403→200`, `"role":"user"→"admin"`. mitmproxy one-liner addon:
  ```python
  from mitmproxy import http
  def response(flow: http.HTTPFlow):
      if "/api/login" in flow.request.path and flow.response:
          flow.response.text = flow.response.text.replace('"success":false','"success":true')
  ```
  run: `mitmdump -s addon.py "~d example.com"`. Only a finding if subsequent requests
  are honored server-side — verify the session actually works.
- **Forced browsing**: hit `/dashboard`, `/admin`, `/api/users/me` with no cookie;
  verb switch GET↔POST↔HEAD; path mangling `/admin/.`, `//admin//`, `/Admin`,
  `/admin;.css`, `/admin%2f`, `..;/admin` (Tomcat).
- **Parameter tampering**: add `admin=true`, `role=admin`, `debug=1`, `is_staff=1`
  to login/registration/profile bodies; mass-assignment on registration
  (`{"email":"...","role":"admin"}`) is WSTG-ATHZ-adjacent but tested here.
- **MFA bypass**: submit the post-MFA request directly (skip the OTP step), reuse an
  old OTP, response-manipulate the OTP check, null/000000 codes, backup-code brute
  (rate limits?), remember-this-device cookie forgery.

### Remember-me and cached credentials (ATHN-05/06, CWE-539)
- Decode the persistent cookie: base64 of `user:md5(pass)` and similar DIY schemes
  = critical offline-crack target. Does it rotate? Survive password change? Expire?
- `autocomplete="off"` on password inputs (low/info), `Cache-Control: no-store` on
  pages containing credentials or tokens, back-button access to authed pages after
  logout (bfcache).

### Security questions (ATHN-08, CWE-640)
- Publicly researchable answers, small answer spaces (colors, cities), unlimited
  attempts, questions enumerable without auth, answers echoed back in the flow.

## 7. Password reset (CWE-640) — full checklist

1. **Host-header poisoning**: request a reset with `Host: attacker.example.net`;
   also `X-Forwarded-Host`, `X-Host`, duplicate Host headers, absolute-URI request
   line. If the mailed link embeds your host → token exfil on victim click.
   Critical. Confirm with your own account + interactsh/your listener as the host.
2. **Token analysis**: request 3+ tokens for your account rapidly; diff. Timestamp,
   epoch-ms, sequential, uuid-v1 (time-ordered), short numeric (6 digits = ffuf
   brute: `ffuf -w digits.txt -u "https://example.com/reset?token=FUZZ" -fc 404 -rate 50`).
3. **Leakage**: token in the reset-page URL + third-party scripts/analytics on that
   page → Referer leak. Token echoed into the HTML/JSON response of the *request*
   step (some apps return it!). Token in a 302 Location visible to JS.
4. **Reuse/expiry**: use twice; use after newer token issued (old one should die);
   use after successful password change; 24h+ validity windows.
5. **Parameter tampering on confirm**: if confirm = `POST /reset {token, email, new_password}`,
   swap `email` to the victim's — some apps validate the token but reset the account
   in `email`. Also array params (`email[]=you&email[]=victim` — some mailers send
   to both), and comma-separated emails on the request step.
6. **Cross-account token**: does a token for user A reset user B when combined with
   B's id? Does the token encode the user (decode it)?
Severity: full account takeover of arbitrary users = critical; own-account quirks
= medium.

## 8. OAuth / SSO quick checklist (CWE-601, CWE-352)

Flow recap: client → `/authorize?response_type=code&client_id=...&redirect_uri=...&state=...`
→ consent → redirect to `redirect_uri?code=...&state=...` → backend swaps code for token.

- **redirect_uri**: full replacement (`https://198.51.100.10/`); subdomain
  (`https://evil.example.com` if wildcard-validated); suffix confusion
  (`https://example.com.attacker.example.net`); path traversal
  (`https://example.com/callback/../redirect?u=...`); open redirect ON the allowed
  domain chained to exfil the code; `redirect_uri` double-up (two params, parsers
  disagree); encoded tricks (`%2F%2E%2E`, `%252F`). A leaked `code` + no PKCE +
  guessable/absent client_secret = account takeover.
- **state**: absent → login CSRF (attacker binds their account/session to victim);
  static or reusable state → same; state not checked on the callback.
- **Implicit flow** (`response_type=token`): access token in the URL fragment —
  history, Referer (if the page then navigates), JS on the landing page. Flag the
  flow's existence; modern guidance is code+PKCE only.
- **code**: reuse a consumed code (should 400); long-lived codes; code for client A
  redeemed by client B (client confusion).
- **PKCE downgrade**: omit `code_challenge` — does the server still accept?
- **IdP response spoofing / aud confusion**: a token minted for another client
  accepted by this backend (`aud` unchecked) — overlaps with JWT attack 7.

Deeper SAML/OIDC testing (XML signature wrapping, assertion replay, IdP-initiated
flows) is its own track — emit remaining leads as work units for an SSO-focused
agent rather than half-testing them here.

## 9. Handoff (rupu — see `references/rupu.md` for shapes)

- Every confirmed item → `findings.report`, scope `endpoint`, target_ref = the
  affected URL, WSTG id + CWE from the tables above, evidence containing the exact
  HTTP exchange (and PoC where applicable).
- Routes exercised → `assets.mark` depth `tested`; confirmed → `exploited`.
- Unconfirmed leads (suspicious token structure, possible reset tamper, OAuth
  oddities) → work-units array via the `work-units` skill; record coverage via the
  `coverage-assets` skill; write final narratives via the `finding-report` skill.
