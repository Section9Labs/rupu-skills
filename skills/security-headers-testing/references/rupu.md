# rupu wiring — security-headers-testing

Every parse/handoff step ends in one of: a **work-units JSON array**, **`assets.mark`**
calls, or **`findings.report`**. `scripts/analyze_headers.py` emits all three shapes
directly (`--work-units`, `--findings`, and per-URL asset records in its report).

## 1. Work units (fan-out over gaps)

`analyze_headers.py --work-units gaps.json` writes a clean JSON array (first char `[`)
— directly consumable by a rupu workflow `for_each:` (file value read via `read_file`
and JSON-parsed) or by a lead agent `dispatch`ing one child per element. Merge/split
multi-URL batches with the shared **`work-units`** skill.

```json
[
  {
    "id": "hdr-csp-unsafe-inline-example.com",
    "title": "CSP allows 'unsafe-inline' on https://example.com/ - verify XSS enablement",
    "targets": ["https://example.com/"],
    "hints": {
      "check": "content-security-policy",
      "status": "weak",
      "value": "default-src 'self'; script-src 'self' 'unsafe-inline' *.googleapis.com",
      "next": "attempt allowlist bypass (ajax.googleapis.com AngularJS gadget); hand to xss skill"
    }
  },
  {
    "id": "hdr-clickjacking-example.com-account",
    "title": "No XFO/frame-ancestors on /account - build clickjacking PoC",
    "targets": ["https://example.com/account"],
    "hints": {"check": "frameable", "next": "analyze_headers.py --poc poc.html, open, screenshot"}
  },
  {
    "id": "hdr-cors-handoff-example.com",
    "title": "ACAO reflects Origin - run cors-testing skill",
    "targets": ["https://example.com/api/v1/me"],
    "hints": {"check": "cors", "next": "cors-testing skill (Corsy battery)"}
  }
]
```

Hand CORS units to the `cors-testing` skill, reflected-`Location` (`crlf-candidate`)
units to the `open-redirect-testing` skill, CSP-bypass units to the XSS skill.

## 2. Assets — `assets.mark`

Each URL this pass analyzes has been actively probed for configuration weaknesses =>
depth `tested` (not just `mapped`). Record via the shared **`coverage-assets`** skill:

```json
{"kind": "web:site",
 "coordinates": [{"t": "url", "v": "https://example.com"}],
 "label": "https://example.com",
 "depth": "tested"}
```

```json
{"kind": "web:route",
 "coordinates": [{"t": "url", "v": "https://example.com"},
                 {"t": "http_route", "v": "/account"}],
 "label": "GET /account (security headers + cookies graded)",
 "depth": "tested"}
```

A route where you *demonstrated* the gap (clickjacking PoC rendered, CSP bypass
loaded a gadget, cookie exfil PoC fired) moves to `"depth": "exploited"`.

## 3. Findings — `findings.report`

`analyze_headers.py --findings findings.json` writes an array of ready payloads, one
per non-ok check (review, de-dupe site-wide items into one host-scope finding, attach
PoC artifacts, then submit via the shared **`finding-report`** skill). The `web`
profile completeness checks need: route/url pin, an HTTP exchange in evidence, and an
OWASP-or-CWE classification — the script satisfies all three by embedding the raw
response header block.

```json
{
  "title": "Session cookie set without HttpOnly and SameSite",
  "scope": "endpoint",
  "target_ref": "https://example.com/login",
  "severity": "medium",
  "classification": {"cwe": "CWE-1004", "owasp": "WSTG-SESS-02"},
  "evidence": {
    "rationale": "The session cookie is readable by JavaScript (no HttpOnly) and sent on cross-site requests (no SameSite), enabling session theft via any XSS and CSRF respectively.",
    "http_exchange": "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/\r\nContent-Security-Policy: ...\r\n...",
    "artifacts": ["report.json"]
  }
}
```

Site-wide example (host scope — use only for gaps true of the whole origin):

```json
{
  "title": "Strict-Transport-Security not set on any response",
  "scope": "host",
  "target_ref": "https://example.com",
  "severity": "medium",
  "classification": {"cwe": "CWE-319", "owasp": "WSTG-CONF-07"},
  "evidence": {
    "rationale": "No HSTS on the HTTPS origin; the HTTP->HTTPS 301 hop remains strippable on every first visit.",
    "http_exchange": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 200 OK\r\nServer: nginx\r\n(no Strict-Transport-Security header)",
    "artifacts": ["report.json"]
  }
}
```

Severity ladder used by the script (override on review):

| Check | Default severity |
|---|---|
| CSP missing/bypassable on injectable app | medium |
| HSTS missing (login origin) / max-age=0 | medium |
| Clickjacking (PoC rendered, state-changing page) | medium (high if irreversible action) |
| Session cookie missing HttpOnly/Secure/SameSite | medium |
| nosniff missing on upload/API route | medium |
| Cache-Control missing on sensitive response | medium |
| nosniff/Referrer-Policy/HSTS-weak elsewhere | low |
| Permissions-Policy absent, banner leaks, X-XSS-Protection | info |

## 4. Step wiring summary

| SKILL.md step | rupu output |
|---|---|
| §1 capture (curl/nuclei/nikto parse) | URLs -> `assets.mark` depth `tested`; nuclei JSONL -> work units |
| §2 analyzer run | `--work-units` array -> `work-units` skill; `-o` report artifact |
| §3 header grading | `--findings` payloads -> `finding-report` skill |
| §4 cookies + clickjacking PoC | PoC confirmed -> `findings.report` + depth `exploited` |
| §5 CRLF pointer | `crlf-candidate` work unit -> `open-redirect-testing` skill |
| §6 report | de-duped `findings.report` submissions |
