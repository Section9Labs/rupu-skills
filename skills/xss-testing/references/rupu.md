# rupu wiring for xss-testing

Every parse/handoff step in this skill ends in one of three rupu-ingestible outputs:
a **work-units JSON array**, **`assets.mark`** calls, or a **`findings.report`** call.
`scripts/parse_dalfox.py` emits all three shapes from dalfox output.

Shared skills to use by name (do not re-implement):
- `work-units` — canonical splitter/normalizer; hand it any work-units array this skill emits.
- `coverage-assets` — conventions for recording assets via `assets.mark`.
- `finding-report` — writing a complete finding via `findings.report`.

## 1. Work units (fan-out)

A clean JSON **array** file whose first character is `[` — rupu's `for_each:` JSON-parses
such a file (read via `read_file`), and a lead agent can `dispatch` one child per element.

One unit per injection point (URL + param), e.g. from `parse_dalfox.py --work-units units.json`
or from normalized kxss hits:

```json
[
  {
    "id": "xss-example.com-search-q",
    "title": "XSS candidate: q on /search (inHTML, type V)",
    "targets": ["https://example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"],
    "hints": {
      "param": "q",
      "type": "V",
      "context": "inHTML-URL",
      "payload": "<img src=x onerror=alert(1)>",
      "evidence": "48 line: <p>Results for <img src=x onerror=alert(1)></p>",
      "cwe": "CWE-79",
      "method": "GET",
      "next": "verify PoC in browser, capture exchange, report via finding-report"
    }
  }
]
```

kxss-stage units carry `hints.unfiltered` (e.g. `"\" ' < >"`) and
`hints.next: "dalfox scan <url> -p <param> -f json"` instead.

## 2. Assets — `assets.mark`

Use the built-in `web` profile kinds (profile-namespaced: prefix `web:`).
Depth ladder: `mapped` → `crawled` → `tested` → `exploited`. Mark the rung actually reached:
- corpus URL merely collected/probed → site `mapped`, route `crawled`
- param fuzzed by kxss/dalfox/XSStrike → route `tested`
- dalfox `type:V` or manually confirmed execution → route `exploited`

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "label": "https://example.com",
  "depth": "mapped"
}
```

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://example.com"},
    {"t": "http_route", "v": "/search"},
    {"t": "param", "v": "q"}
  ],
  "label": "GET /search?q= (XSS tested)",
  "depth": "exploited"
}
```

(`param` coordinate optional — include it when a specific parameter was tested.)

## 3. Findings — `findings.report`

Web XSS findings use scope `endpoint` with `target_ref` = the affected PoC URL
(scope `host` only for host-wide issues — rarely applies to XSS). The `web` profile
completeness checks require all three of: finding pinned to a route/URL, an HTTP exchange
in evidence, and an OWASP-or-CWE classification.

```json
{
  "scope": "endpoint",
  "target_ref": "https://example.com/search?q=%3Cimg+src%3Dx+onerror%3Dalert(document.domain)%3E",
  "title": "Reflected XSS in 'q' parameter of /search",
  "severity": "high",
  "classification": {"owasp": "WSTG-INPV-01", "cwe": "CWE-79"},
  "evidence": {
    "rationale": "Parameter 'q' is reflected unencoded into the HTML body (context inHTML). The payload <img src=x onerror=alert(document.domain)> executes in the victim browser; dalfox headless verification observed the dialog (type V). Any user following a crafted link executes attacker JavaScript in the example.com origin.",
    "request": "GET /search?q=%3Cimg+src%3Dx+onerror%3Dalert(document.domain)%3E HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n",
    "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n...<p>Results for <img src=x onerror=alert(document.domain)></p>..."
  }
}
```

Classification by variant:
- Reflected → `WSTG-INPV-01`, CWE-79, severity **high** (medium if execution needs unusual
  preconditions, e.g. CSP blocks execution but reflection is unencoded).
- Stored → `WSTG-INPV-02`, CWE-79, **high** (critical if it renders in admin/privileged views).
- DOM → `WSTG-CLNT-01`, CWE-79, **high**.
- Blind (OOB-confirmed) → `WSTG-INPV-02`, CWE-79, **high/critical** — include the interactsh
  interaction (timestamp, remote address, request) as the "response" side of the exchange.
- Prototype pollution → CWE-1321 (plus CWE-79 if it yields execution).

`parse_dalfox.py --findings findings.json` pre-fills these payloads from dalfox evidence;
review severity and rationale, replace the synthesized request/response with the captured
exchange (HAR via `--har-file-path`, or proxy capture) when available, then submit each via
the `finding-report` skill.

## 4. Step-by-step wiring recap

| Methodology step | rupu output |
|---|---|
| Corpus collection (gau/katana) | `assets.mark` sites `mapped`, routes `crawled` |
| kxss/Gxss reflection discovery | work-units array (one per reflecting URL+param) → `work-units` skill; routes `tested` |
| dalfox scan parsed by `parse_dalfox.py` | work-units array + `findings.report` payloads + `assets.mark` routes `tested`/`exploited` |
| XSStrike analysis + manual confirmation | `findings.report` via `finding-report` skill; route `exploited` |
| Stored/blind confirmation (interactsh) | `findings.report` with OOB interaction evidence; route `exploited` |
