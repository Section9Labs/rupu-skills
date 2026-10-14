# rupu wiring — cors-testing

Every parse/handoff step ends in a work-units JSON array, `assets.mark` calls, or
a `findings.report` call. `scripts/parse_cors.py` emits all three payload shapes.

## 1. Work units

`parse_cors.py --work-units units.json` writes a clean JSON array file whose
**first character is `[`** so a rupu workflow `for_each:` can JSON-parse it (read
via the `read_file` tool), or a lead agent can read it and `dispatch` one child per
element (e.g. "build the PoC + authed retest" per hit). Normalize/split with the
shared `work-units` skill.

```json
[
  {
    "id": "cors-example.com-api-user-reflect_origin",
    "title": "CORS misconfig: reflect_origin @ https://example.com/api/user",
    "targets": ["https://example.com/api/user"],
    "hints": {
      "misconfig_type": "reflect_origin",
      "origin_reflected": "https://evil.example.net",
      "credentials": "true",
      "vuln_class": "cors-misconfiguration",
      "cwe": "CWE-942",
      "wstg": "WSTG-CLNT-07",
      "next_step": "authed verify with session cookie; build credentialed-fetch PoC; capture exfiltrated body"
    }
  }
]
```

## 2. Assets

`assets.mark` with the `web` profile kinds (prefix `web:`), conventions per the
shared `coverage-assets` skill. Depth rung actually reached: `mapped` (listed) →
`crawled` (found by crawler) → `tested` (Origin matrix fired, clean) →
`exploited` (confirmed credentialed cross-origin read).

```json
{"kind": "web:site", "coordinates": [{"t":"url","v":"https://example.com"}],
 "label": "https://example.com", "depth": "mapped"}

{"kind": "web:route",
 "coordinates": [{"t":"url","v":"https://example.com"},
                 {"t":"http_route","v":"/api/user"}],
 "label": "/api/user", "depth": "tested"}
```

(No `param` coordinate — the injected input is the `Origin` header; note that in
the label or finding instead.)

## 3. Findings

`parse_cors.py --findings findings.json` writes an array of ready
`findings.report` payloads — submit each via the shared `finding-report` skill.
The `web` profile completeness checks need all three of: pinned route/url
(`scope:endpoint` + `target_ref`), an HTTP exchange in evidence, and an
OWASP-or-CWE classification.

```json
{
  "title": "CORS misconfiguration: arbitrary origin reflected with credentials on /api/user",
  "scope": "endpoint",
  "target_ref": "https://example.com/api/user",
  "severity": "high",
  "classification": {"cwe": "CWE-942", "wstg": "WSTG-CLNT-07"},
  "evidence": {
    "rationale": "The endpoint reflects any Origin into Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true, so any attacker page can read the authenticated response of /api/user with a credentialed fetch (CWE-942 / CWE-346). Verified: Origin https://evil.example.net echoed with ACAC true on an authenticated request.",
    "request": "GET /api/user HTTP/1.1\r\nHost: example.com\r\nOrigin: https://evil.example.net\r\nCookie: session=[REDACTED]\r\n\r\n",
    "response": "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.example.net\r\nAccess-Control-Allow-Credentials: true\r\n...\r\n\r\n{\"email\":\"user@example.com\", ...}"
  }
}
```

Severity (script defaults; adjust for data sensitivity):

| Condition | Severity |
|---|---|
| attacker-satisfiable origin (reflection / null / regex bypass) + `ACAC: true` | high |
| subdomain trust + ACAC (needs subdomain XSS/takeover) | medium |
| HTTP-origin trust on HTTPS + ACAC (needs MitM) | medium |
| reflection without ACAC on sensitive data | medium |
| wildcard `*` / reflection on public data, no creds | low |
| broken/invalid ACAO value | info |

Include CWE-346 (origin validation error) alongside CWE-942 in the rationale text;
the `classification.cwe` field carries CWE-942.

## Step-by-step wiring summary

| Methodology step | rupu output |
|---|---|
| 1. Target selection parse | `assets.mark` web:route `mapped`/`crawled`; optional candidate work-units array via `work-units` skill |
| 2. Manual Origin matrix | hit → feed to parse_cors `--confirmed` path → finding; clean → `assets.mark` `tested` |
| 3. Corsy/CORScanner parse | `parse_cors.py` → merged JSON + work-units array + findings array |
| 4. PoC verification | exfil proof appended to evidence → `findings.report` via `finding-report` skill + `assets.mark` `exploited` |
