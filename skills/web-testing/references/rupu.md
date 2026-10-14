# rupu wiring for the web-testing umbrella

This pack runs inside rupu. Every parse/handoff step in the umbrella (and in every
sub-skill) ends by producing one of exactly three outputs:

1. a **work-units JSON array** (fan-out input for `for_each:` / `dispatch`),
2. **`assets.mark`** calls (coverage ledger),
3. a **`findings.report`** call (verified issue).

Shared skills to import by name — do NOT re-invent them:

- **`work-units`** — the canonical work-unit splitter/normalizer. Hand it every
  raw array you produce; it dedupes, slugs ids, and chunks for dispatch.
- **`coverage-assets`** — the asset-recording discipline (`assets.mark`, depth
  ladder, final coverage sweep).
- **`finding-report`** — the complete finding shape and the `web` profile's
  completeness checks.

## 1. Work-units JSON array

A clean JSON ARRAY file whose **first character is `[`** — rupu's `for_each:`
JSON-parses a file value beginning with `[` (read via the `read_file` tool), and
a lead agent reads the same file and `dispatch`es one child per element.

Element shape:

```json
[
  {
    "id": "route-example-com-login-username",
    "title": "Test https://example.com/login (param: username)",
    "targets": ["https://example.com/login"],
    "hints": {
      "site": "https://example.com",
      "path": "/login",
      "params": "username,password",
      "methods": "GET,POST",
      "tech": "nginx,php,wordpress",
      "waf": "none",
      "classes": "sqli,xss,auth",
      "source": "web-crawling"
    }
  }
]
```

Rules: `targets` is a list of URLs/hosts the child should act on; `hints` is a
flat string-valued object that carries routing context (tech → which vuln skills
to prioritize, `classes` → which to run). Keep one route (or one site, in the
probe phase) per element so fan-out granularity is right.

Per-phase arrays this umbrella expects:

| Phase | Producer skill | Array content |
|---|---|---|
| 2.1 | `http-probing` | live sites (one element per base URL, tech/WAF in hints) |
| 2.2 | `web-crawling` | routes per site |
| 2.3 | `content-discovery` | brute-forced routes / vhosts |
| 2.4 | `parameter-discovery` | route+param sets |
| 3 | `nuclei` | unconfirmed matches to re-verify manually |
| 6–9 | vuln skills | suspected-but-unconfirmed leads |
| 10 | umbrella | residual untested routes (resume file) |

## 2. Merging recon output: `merge_inventory.py`

The glue between recon and testing:

```
python3 scripts/merge_inventory.py \
    out/httpx-sites.json out/katana-routes.json \
    out/ffuf-routes.json out/arjun-params.json \
    --inventory out/inventory.json \
    --work-units out/routes-to-test.json \
    --assets out/assets-mark.json
```

- Accepts any mix of work-unit arrays, plain JSON URL arrays, and newline URL
  lists. Dedupes by (site, path, method), unions params/tech/sources.
- `--inventory` → normalized `{"sites": [...], "routes": [...], "tech": [...]}`.
- `--work-units` → the master routes-to-test array (first char `[`) for
  `for_each:`/`dispatch`. Normalize further with the `work-units` skill if needed.
- `--assets` → ready-to-send `assets.mark` payloads for every site and route at
  the correct depth (site → `mapped`, crawled route → `crawled`; pass
  `--default-depth` to override).

## 3. Assets: `assets.mark` (built-in `web` profile)

Kinds are profile-namespaced — prefix with `web:`.

Site:

```json
{"kind": "web:site",
 "label": "https://example.com (nginx, php, wordpress)",
 "coordinates": [{"t": "url", "v": "https://example.com"}],
 "depth": "mapped"}
```

Route (param coordinate optional):

```json
{"kind": "web:route",
 "label": "https://example.com/login [username]",
 "coordinates": [
   {"t": "url", "v": "https://example.com"},
   {"t": "http_route", "v": "/login"},
   {"t": "param", "v": "username"}
 ],
 "depth": "tested"}
```

Depth ladder — mark the rung actually reached, never higher:

| depth | earned when |
|---|---|
| `mapped` | site probed / confirmed live (`http-probing`) |
| `crawled` | route found by crawling/brute-force (`web-crawling`, `content-discovery`) |
| `tested` | route fuzzed or vuln-tested (Phases 3–8), even if clean |
| `exploited` | issue confirmed/exploited on the route (Phase 9) |

Re-mark upward as work progresses; the final Phase-10 sweep makes the ladder
reflect reality. This is the engagement's coverage proof — see `coverage-assets`.

## 4. Findings: `findings.report`

For web issues use scope `endpoint` with `target_ref` = the affected URL; scope
`host` only for host-wide issues (TLS config, server version). Severity:
info|low|medium|high|critical.

```json
{"title": "SQL injection in id parameter of /product",
 "scope": "endpoint",
 "target_ref": "https://example.com/product?id=1",
 "severity": "high",
 "classification": "WSTG-INPV-05 / CWE-89",
 "evidence": {
   "rationale": "The id parameter is concatenated into a SQL query. Boolean payloads id=1 AND 1=1 vs id=1 AND 1=2 produce differing pages; sqlmap confirmed MySQL UNION injection and dumped the current user.",
   "exchange": "GET /product?id=1%20AND%201=2 HTTP/1.1\nHost: example.com\n...\n\nHTTP/1.1 200 OK\nContent-Length: 1289\n...<empty product list>...",
   "tool_output": "sqlmap: parameter 'id' is vulnerable (UNION query, 4 columns); backend: MySQL 8.0"
 }}
```

The `web` profile's completeness checks require all three of:
1. finding pinned to a route/URL (`target_ref`),
2. an HTTP request/response exchange in evidence,
3. an OWASP (WSTG id / Top-10) or CWE classification.

Use the `finding-report` skill for the full field-by-field shape.

## 5. Illustrative rupu workflow sketch

```yaml
# web-testing engagement spine (illustrative)
workflow: web-assessment
steps:

  - id: probe
    skill: http-probing
    args:
      targets: ["example.com", "192.0.2.10", "192.0.2.0/24"]
      work_units: out/live-sites.json      # [ {site elements} ]

  - id: crawl
    for_each: { file: out/live-sites.json }   # read_file -> JSON array
    skill: web-crawling
    args:
      target: "{{ item.targets[0] }}"
      work_units: "out/routes-{{ item.id }}.json"

  - id: discover
    for_each: { file: out/live-sites.json }
    skill: content-discovery
    args:
      target: "{{ item.targets[0] }}"
      work_units: "out/brute-{{ item.id }}.json"

  - id: params
    for_each: { file: out/live-sites.json }
    skill: parameter-discovery
    args:
      target: "{{ item.targets[0] }}"
      work_units: "out/params-{{ item.id }}.json"

  - id: merge
    run: >
      python3 skills/web-testing/scripts/merge_inventory.py
      out/live-sites.json out/routes-*.json out/brute-*.json out/params-*.json
      --inventory out/inventory.json
      --work-units out/routes-to-test.json
      --assets out/assets-mark.json
    # then: emit each payload in out/assets-mark.json via assets.mark

  - id: config-sweep
    for_each: { file: out/live-sites.json }
    skill: nuclei            # plus nikto-scan, tls-testing, security-headers-testing
    args:
      target: "{{ item.targets[0] }}"
      work_units: "out/nuclei-confirm-{{ item.id }}.json"

  - id: vuln-test
    for_each: { file: out/routes-to-test.json }
    dispatch: vuln-tester            # one child agent per route
    prompt: >
      Load the sub-skills named in hints.classes (default:
      sqli-testing, xss-testing, command-injection-testing, path-traversal-testing,
      ssrf-testing, ssti-testing, cors-testing, open-redirect-testing)
      and test {{ item.targets[0] }} with params {{ item.hints.params }}.
      Mark the route tested via assets.mark; report confirmed issues via
      findings.report (finding-report skill); emit unconfirmed leads as a
      work-units array.

  - id: auth-authz
    skill: auth-session-testing      # then access-control-testing with the sessions
    args: { inventory: out/inventory.json }

  - id: collect
    run: finalize                     # Phase 10: final assets.mark depth sweep,
                                      # findings already reported inline,
                                      # residual leads -> out/resume-units.json
```

A lead agent variant replaces the `for_each:` steps with: read the array file,
`dispatch` one child per element, pass the element as the child's brief, require
each child to end with the three rupu outputs.

## 6. Per-step checklist (apply at EVERY parse/handoff)

- Parsed tool output? → wrote/updated a work-units array for whatever the next
  phase fans out over.
- Discovered a site or route? → `assets.mark` at the earned depth rung.
- Confirmed an issue with a reproduced exchange? → `findings.report` meeting all
  three `web`-profile completeness checks.
- Finished a phase? → anything suspected-but-unconfirmed is in a work-units
  array, not lost.
