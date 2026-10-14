# rupu wiring — open-redirect-testing

Every parse/handoff step ends in a work-units JSON array, `assets.mark` calls, or
a `findings.report` call. `scripts/parse_oralyzer.py` emits all three payload shapes.

## 1. Work units

`parse_oralyzer.py --candidates ... --work-units units.json` (step 1 fan-out) and
`parse_oralyzer.py -i oralyzer.json --work-units units.json` (step 5 follow-up
fan-out) both write a clean JSON array file whose **first character is `[`** —
rupu `for_each:` JSON-parses it (read via the `read_file` tool), or a lead agent
reads it and `dispatch`es one child per element. Normalize/split with the shared
`work-units` skill.

```json
[
  {
    "id": "redir-example.com-login-next",
    "title": "Open-redirect candidate: next @ https://example.com/login",
    "targets": ["https://example.com/login?next=FUZZ"],
    "hints": {
      "param": "next",
      "vuln_class": "open-redirect",
      "cwe": "CWE-601",
      "wstg": "WSTG-CLNT-04",
      "type": "javascript",
      "next_step": "js-type hit: test string breakout for DOM XSS escalation"
    }
  }
]
```

(`hints.type` present only on post-scan units; values `header|javascript|meta|crlf`.)

## 2. Assets

`assets.mark` with the `web` profile kinds (prefix `web:`), per the shared
`coverage-assets` skill. Depth rung actually reached:
`mapped` (candidate listed) → `crawled` (found by crawler/--discover) →
`tested` (payload set fired, clean) → `exploited` (confirmed redirect/CRLF).

```json
{"kind": "web:route",
 "coordinates": [{"t":"url","v":"https://example.com"},
                 {"t":"http_route","v":"/login"},
                 {"t":"param","v":"next"}],
 "label": "/login?next=", "depth": "tested"}
```

Also mark the parent once: `{"kind":"web:site","coordinates":[{"t":"url","v":"https://example.com"}],"label":"https://example.com","depth":"mapped"}`.

## 3. Findings

`parse_oralyzer.py --findings findings.json` writes an array of ready
`findings.report` payloads — submit each through the shared `finding-report`
skill. The `web` profile completeness checks need: pinned route/url
(`scope:endpoint` + `target_ref`), an HTTP exchange in evidence, and an
OWASP-or-CWE classification.

Open redirect (header type):

```json
{
  "title": "Open redirect via next parameter on /login",
  "scope": "endpoint",
  "target_ref": "https://example.com/login?next=",
  "severity": "medium",
  "classification": {"cwe": "CWE-601", "wstg": "WSTG-CLNT-04"},
  "evidence": {
    "rationale": "The next parameter is reflected unvalidated into the Location header; payload //evil.example.net/ yields a 302 off-origin redirect (CWE-601). Mechanism: header.",
    "request": "GET /login?next=%2F%2Fevil.example.net%2F HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "response": "HTTP/1.1 302 Found\r\nLocation: //evil.example.net/\r\n..."
  }
}
```

CRLF (raise severity):

```json
{
  "title": "CRLF injection / response splitting via next parameter on /login",
  "scope": "endpoint",
  "target_ref": "https://example.com/login?next=",
  "severity": "high",
  "classification": {"cwe": "CWE-113", "wstg": "WSTG-INPV-15"},
  "evidence": {
    "rationale": "%0d%0a in the next parameter terminates the Location header and injects Set-Cookie: crlf=injected, which the server emits as a real header (CWE-113): attacker-controlled cookies/headers on the trusted origin.",
    "request": "GET /login?next=/account%0d%0aSet-Cookie:%20crlf=injected HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "response": "HTTP/1.1 302 Found\r\nLocation: /account\r\nSet-Cookie: crlf=injected\r\n..."
  }
}
```

Severity map (script default, override per context):

| Result | Severity |
|---|---|
| Header/JS/meta open redirect | medium |
| Open redirect on OAuth `redirect_uri` / SSO flow | high (token leak) |
| CRLF header injection | high |
| CRLF body split rendering script | high (report as CRLF→XSS) |
| `javascript:` accepted into a JS sink | reclassify as XSS (CWE-79) |

## Step-by-step wiring summary

| Methodology step | rupu output |
|---|---|
| 1. Candidate harvest | work-units array → `work-units` skill; `assets.mark` route `mapped`/`crawled` |
| 2–3. Manual payloads / CRLF | confirmed → `findings.report` + `assets.mark` `exploited`; clean → `tested` |
| 4. Oralyzer run parse | `parse_oralyzer.py` → merged JSON + work-units + findings array |
| 5. Hand off | findings via `finding-report` skill; escalation units (DOM-XSS, OAuth) via `work-units` skill |
