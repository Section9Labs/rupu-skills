# rupu Wiring — file-upload-testing

Every parse/handoff step in this skill ends in one of three rupu outputs:
a work-units JSON array file, `assets.mark` calls, or a `findings.report`
call. Exact shapes below.

## 1. Work units (fan-out over upload variants)

`scripts/gen_upload_payloads.py --work-units upload_units.json` writes a
clean JSON **array** (first character `[`) so rupu `for_each:` can JSON-parse
it directly (via `read_file`) and a lead agent can `dispatch` one child per
element. Normalize/split large arrays with the shared `work-units` skill.

Element shape:

```json
[
  {
    "id": "upload-php-double-ext",
    "title": "Upload shell.php.jpg (double extension) to /profile/avatar",
    "targets": ["https://192.0.2.10/profile/avatar"],
    "hints": {
      "field": "file",
      "filename": "shell.php.jpg",
      "part_content_type": "image/jpeg",
      "payload_file": "payloads/shell.php.jpg",
      "bypass": "double-extension",
      "verify": "GET stored URL with ?c=id, expect uid= in body",
      "wstg": "WSTG-BUSL-09",
      "cwe": "CWE-434"
    }
  }
]
```

A workflow consumes it as:

```yaml
- for_each:
    file: upload_units.json
    as: unit
  steps:
    - run: attempt upload per {{unit.hints}}
```

## 2. Assets (`assets.mark`, web profile kinds)

Mark the rung actually reached on the depth ladder
`mapped -> crawled -> tested -> exploited`.

Upload endpoint discovered/baselined:

```json
{
  "kind": "web:route",
  "label": "avatar upload",
  "coordinates": [
    {"t": "url", "v": "https://192.0.2.10"},
    {"t": "http_route", "v": "/profile/avatar"},
    {"t": "param", "v": "file"}
  ],
  "depth": "crawled"
}
```

Storage directory located → kind `web:route`, route `/uploads/`, depth
`mapped`. Bypass corpus run against the endpoint → re-mark depth `tested`.
Webshell executed → re-mark depth `exploited`. The parent site is
`{"kind":"web:site","label":"https://192.0.2.10","coordinates":[{"t":"url","v":"https://192.0.2.10"}],"depth":"mapped"}`.

## 3. Findings (`findings.report`)

Built by `scripts/report_upload_finding.py -o finding.json`; submit via the
shared `finding-report` skill. Satisfy all three `web`-profile completeness
checks: pinned route/url, HTTP exchange in evidence, OWASP-or-CWE class.

```json
{
  "title": "Unrestricted file upload to RCE via double extension",
  "scope": "endpoint",
  "target_ref": "https://192.0.2.10/uploads/shell.php.jpg",
  "severity": "critical",
  "classification": {"wstg": "WSTG-BUSL-09", "cwe": "CWE-434"},
  "evidence": {
    "rationale": "The avatar upload accepts shell.php.jpg with Content-Type image/jpeg; Apache AddHandler executes it as PHP. GET /uploads/shell.php.jpg?c=id returned uid=33(www-data), proving arbitrary command execution (CWE-434 / WSTG-BUSL-09).",
    "http_exchanges": [
      {"name": "upload", "request": "<raw multipart POST>", "response": "<201 + stored URL>"},
      {"name": "execution", "request": "GET /uploads/shell.php.jpg?c=id HTTP/1.1 ...", "response": "HTTP/1.1 200 OK ... uid=33(www-data) ..."}
    ]
  }
}
```

Severity guide: command execution → `critical`; shell stored but execution
blocked / zip-slip arbitrary write → `high`; SVG stored XSS → `medium`;
validation bypass with benign impact only → `low`.

Scope is `endpoint` with `target_ref` = the affected URL; use scope `host`
only for host-wide issues (e.g. an upload dir shared across all vhosts).
