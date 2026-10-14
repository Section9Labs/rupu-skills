# rupu wiring for the owasp-zap skill

Every parse/handoff step in this skill ends by producing one of three
rupu-ingestible outputs: a **work-units JSON array**, **`assets.mark`** calls,
or a **`findings.report`** call. This file shows the exact shapes. Related
shared skills (import by name, do not re-implement): `work-units` (canonical
splitter/normalizer for the arrays below), `coverage-assets` (asset recording
conventions), `finding-report` (writing a complete finding).

## 1. Work units (fan-out)

`scripts/zap_scan.py --work-units wu.json` and
`scripts/parse_zap_report.py report.json --work-units wu.json` write a clean
JSON **array** whose first character is `[`. rupu's `for_each:` JSON-parses a
file value that begins with `[` (read via the `read_file` tool); a lead agent
reads the same file and `dispatch`es one child per element. One unit per
distinct alert type (pluginId + name):

```json
[
  {
    "id": "zap-40018-sql-injection",
    "title": "SQL Injection (ZAP plugin 40018, risk High)",
    "targets": [
      "https://app.example.com/item?id=1",
      "https://app.example.com/search?q=x"
    ],
    "hints": {
      "pluginId": "40018",
      "alert": "SQL Injection",
      "risk": "High",
      "confidence": "Medium",
      "cweid": "89",
      "wascid": "19",
      "params": "id,q",
      "sample_attack": "1 AND 1=1 --",
      "next_tool": "sqlmap -u <target> -p <param> --batch"
    }
  }
]
```

Hand the normalized array to the `work-units` skill, then fan out
(`for_each:` over the file, or dispatch one child per element). Typical
children: sqlmap for SQLi units, dalfox for XSS units, manual replay for
everything else.

## 2. Assets — `assets.mark` (web profile kinds, prefix `web:`)

Depth ladder: `mapped` -> `crawled` -> `tested` -> `exploited`. Mark the rung
actually reached.

Scan started against a site (probed/mapped):

```json
{"kind": "web:site", "label": "https://app.example.com",
 "coordinates": [{"t": "url", "v": "https://app.example.com"}],
 "depth": "mapped"}
```

Route discovered by the spider (crawled):

```json
{"kind": "web:route", "label": "GET /search?q=",
 "coordinates": [
   {"t": "url", "v": "https://app.example.com"},
   {"t": "http_route", "v": "/search"},
   {"t": "param", "v": "q"}
 ],
 "depth": "crawled"}
```

Route the active scanner attacked: same shape, `"depth": "tested"`. Route
behind a confirmed/reproduced alert: `"depth": "exploited"`. The `param`
coordinate is optional — omit it for parameterless routes.

## 3. Findings — `findings.report`

One call per confirmed alert instance. Both scripts emit ready payloads
(`--findings findings.json`, a JSON array of these objects); review/confirm
High-risk active-scan alerts by replaying `attack` before reporting. The web
profile's completeness checks require all three of: the finding pinned to a
route/url, an HTTP exchange in evidence, and an OWASP-or-CWE classification.

```json
{
  "title": "SQL Injection in 'id' parameter",
  "scope": "endpoint",
  "target_ref": "https://app.example.com/item?id=1",
  "severity": "high",
  "classification": {"cwe": "CWE-89", "owasp": "WSTG-INPV-05"},
  "evidence": {
    "rationale": "ZAP active scan plugin 40018 (confidence Medium): the 'id' parameter is concatenated into a SQL query. Boolean payloads produced differential responses, establishing injectable input (CWE-89).",
    "http_exchange": "GET /item?id=1%20AND%201%3D1%20-- HTTP/1.1\nHost: app.example.com\n\nHTTP/1.1 200 OK\n...evidence fragment: 'You have an error in your SQL syntax'",
    "attack": "1 AND 1=1 --",
    "response_evidence": "You have an error in your SQL syntax",
    "zap": {"pluginId": "40018", "risk": "High", "confidence": "Medium", "wascid": "19"},
    "solution": "Use parameterized queries."
  }
}
```

Rules:
- `scope` is `endpoint` with `target_ref` = the affected URL. Use `host` only
  for genuinely host-wide issues (e.g. missing HSTS on every response).
- `severity` maps from ZAP risk: High->`high`, Medium->`medium`, Low->`low`,
  Informational->`info`. Upgrade to `critical` only on operator judgment
  (e.g. confirmed RCE/auth-bypass impact).
- `evidence.rationale` states the weakness and the evidence establishing it;
  `http_exchange` carries the request/response material (ZAP's `attack` +
  `evidence` fields reconstructed into the exchange).
- Classification: always `CWE-<cweid>` from the alert; add the matching WSTG
  id (WSTG-INPV-05 SQLi, WSTG-INPV-01/02 XSS, WSTG-SESS-02 cookie attrs,
  WSTG-CONF-07 HSTS, WSTG-INPV-12 traversal, WSTG-INPV-19 SSRF, ...). Either
  satisfies the completeness check; include both when known.

Record each verified issue via the `finding-report` skill using these
payloads.

## 4. Step-by-step wiring in the methodology

| Methodology step | rupu output |
|---|---|
| Daemon/AF/packaged scan launched against a target | `assets.mark` `web:site` depth `mapped` |
| Spider / AJAX spider finished (URL list from `/JSON/core/view/urls/` or the Sites tree) | `assets.mark` `web:route` depth `crawled` per route |
| Active scan completed over a route | `assets.mark` `web:route` depth `tested` |
| Alerts parsed (`zap_scan.py` / `parse_zap_report.py`) | work-units array -> `work-units` skill -> fan-out |
| Alert confirmed by replay | `assets.mark` depth `exploited` + `findings.report` via `finding-report` skill |
