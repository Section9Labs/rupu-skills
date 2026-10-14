# rupu wiring for parameter-discovery

Every parse/handoff step in this skill ends in one of three rupu-ingestible
outputs: a **work-units JSON array**, **`assets.mark`** calls, or a
**`findings.report`** call. `scripts/parse_arjun.py` emits the first two as
files; findings are reported directly when a fuzz run itself proves a bug.

Shared skills to import by name (same rupu-skills library — do not reimplement):

- `work-units` — canonical work-unit splitter/normalizer. Hand it the array
  from `--work-units` before fan-out.
- `coverage-assets` — records assets; feed it the `--assets` payloads.
- `finding-report` — writes a complete finding; use it for anything verified
  during param discovery.

## 1. Work units (fan-out)

`parse_arjun.py --work-units param-work-units.json` writes a clean JSON
**array** whose first character is `[`, so a rupu workflow `for_each:` can
JSON-parse the file (read via the `read_file` tool), or a lead agent can read
it and `dispatch` one child per element. One unit per endpoint+method:

```json
[
  {
    "id": "param-c1a2b3d4",
    "title": "https://example.com/api/profile [GET] 3 params",
    "targets": ["https://example.com/api/profile"],
    "hints": {
      "method": "GET",
      "params": ["id", "debug", "fields"],
      "lead": {
        "id": "idor",
        "debug": "debug-toggle",
        "fields": "none"
      },
      "source": "arjun"
    }
  }
]
```

`hints.lead` pre-classifies each param (idor / ssrf-redirect / injection /
lfi-ssti / debug-toggle / cmdi / none) from the name-pattern table in
SKILL.md so the dispatched child starts with the right test. Hand the array
to the `work-units` skill to normalize/split, then fan out to the injection,
IDOR, SSRF, open-redirect, and LFI/SSTI skills.

## 2. Assets (`assets.mark`)

Use the built-in `web` engagement profile kinds (profile-namespaced: prefix
`web:`). One mark per discovered parameter, depth `tested` (the endpoint was
fuzzed and the param confirmed):

```json
{
  "kind": "web:route",
  "label": "/api/profile?id (GET)",
  "coordinates": [
    {"t": "url", "v": "https://example.com/api/profile"},
    {"t": "http_route", "v": "/api/profile"},
    {"t": "param", "v": "id"}
  ],
  "depth": "tested"
}
```

Endpoints fuzzed with **zero** params found still get a route mark at
`tested` (coverage record, no `param` coordinate):

```json
{
  "kind": "web:route",
  "label": "/healthz (GET)",
  "coordinates": [
    {"t": "url", "v": "https://example.com/healthz"},
    {"t": "http_route", "v": "/healthz"}
  ],
  "depth": "tested"
}
```

If this skill ran against a host not yet recorded, also mark the site:

```json
{
  "kind": "web:site",
  "label": "https://example.com",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "depth": "mapped"
}
```

Depth ladder reminder: `mapped` → `crawled` → `tested` → `exploited`. Mark the
rung actually reached. If a downstream skill exploits a param you found, it
re-marks that route at `exploited`; you mark `tested` here. Record all of the
above via the `coverage-assets` skill (the `--assets` file from the parser is
a JSON array of exactly these payloads).

## 3. Findings (`findings.report`)

When a discovery run itself verifies a vulnerability (e.g. `?debug=1` dumps
environment secrets, `?redirect=` reflects into a 302 Location), report it
immediately via the `finding-report` skill — scope `endpoint`, `target_ref`
the affected URL, and satisfy the `web` profile completeness checks: pinned
route/url, HTTP exchange in evidence, OWASP-or-CWE classification.

```json
{
  "title": "Hidden 'debug' parameter exposes stack trace and env secrets",
  "scope": "endpoint",
  "target_ref": "https://example.com/api/profile?debug=1",
  "severity": "high",
  "classification": "CWE-489",
  "evidence": {
    "rationale": "The undocumented GET parameter 'debug' (found via arjun differential analysis, 'based on: body length') switches the endpoint into verbose error mode. With debug=1 the response includes a full Python traceback and the DATABASE_URL environment variable, exposing credentials. Baseline response without the param is 4312 bytes / no trace.",
    "http_exchange": "GET /api/profile?debug=1 HTTP/1.1\nHost: example.com\n\nHTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\nTraceback (most recent call last):\n  File \"app.py\", line 88, in profile\n...\nDATABASE_URL=postgres://app:S3cret@192.0.2.15:5432/prod"
  }
}
```

Severity is one of `info|low|medium|high|critical`. Classify by OWASP (WSTG
id or Top-10, e.g. `WSTG-INFO-04`, `A05:2021`) or CWE. Use scope `host` only
for host-wide issues — param findings are per-endpoint.

## Step → output map

| methodology step | rupu output |
|---|---|
| SKILL.md step 4 (parse/merge) | `--work-units` array → `work-units` skill → fan-out |
| SKILL.md step 4 (parse/merge) | `--assets` array → `coverage-assets` skill (`web:route` @ `tested`) |
| any run that proves a bug | `findings.report` via `finding-report` skill |
