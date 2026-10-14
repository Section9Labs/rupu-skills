# rupu wiring for web-crawling

Every parse/handoff step in this skill ends by producing one of:
a work-units JSON array, `assets.mark` calls, or a `findings.report` call.

## 1. Work units (fan-out)

`scripts/urls_to_work_units.py` emits a clean JSON ARRAY file whose first
character is `[`. rupu's `for_each:` JSON-parses such a file (read via the
`read_file` tool); a lead agent reads the same file and `dispatch`es one child
per element. Hand the normalized array to the **`work-units`** skill (the
canonical work-unit splitter/normalizer) rather than re-inventing splitting.

Element shape:

```json
[
  {
    "id": "crawl-example.com",
    "title": "Test crawled surface of example.com (42 URLs, 17 params)",
    "targets": [
      "https://example.com/search?q=1",
      "https://example.com/item?id=5&sort=asc"
    ],
    "hints": {
      "host": "example.com",
      "params": ["q", "id", "sort"],
      "source": "web-crawling",
      "paths_file": "inventory/paths.txt"
    }
  }
]
```

- `--group host`: one unit per host — good for dispatching per-site vuln agents.
- `--group route`: one unit per distinct (host, path) with params — good for
  `for_each:` over fuzz targets (xss-testing / sqli-testing / ssrf-testing).

## 2. Assets (`assets.mark`)

Use the built-in `web` engagement profile kinds (profile-namespaced → prefix
`web:`). Record coverage via the **`coverage-assets`** skill.

Site (the base URL you crawled):

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "label": "https://example.com",
  "depth": "crawled"
}
```

Route found by crawling (param coordinates optional, one per param name):

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://example.com"},
    {"t": "http_route", "v": "/search"},
    {"t": "param", "v": "q"}
  ],
  "label": "/search?q=",
  "depth": "crawled"
}
```

Depth ladder: `mapped` → `crawled` → `tested` → `exploited`. Mark the rung
actually reached: this skill produces `crawled` (sites you merely probed stay
`mapped`); downstream fuzzing skills re-mark `tested`, confirmed exploitation
re-marks `exploited`.

`scripts/urls_to_work_units.py --assets assets-marks.json` writes a JSON array
of ready `assets.mark` payloads — iterate it and call `assets.mark` once per
element.

## 3. Findings (`findings.report`)

Crawling sometimes directly surfaces issues (exposed `.git/`, `/.env`, backup
files, debug endpoints, secrets/keys inside crawled JS, directory listings).
Verify with a raw HTTP request, then record via the **`finding-report`** skill.
Satisfy all three `web` profile completeness checks: pinned to a route/url,
HTTP exchange in evidence, OWASP-or-CWE classification.

```json
{
  "scope": "endpoint",
  "target_ref": "https://example.com/.git/config",
  "title": "Exposed .git repository metadata",
  "severity": "high",
  "classification": "CWE-538 / WSTG-CONF-04",
  "evidence": {
    "rationale": "The VCS metadata directory is web-accessible, allowing full source reconstruction; GET /.git/config returns the repository config, establishing exposure.",
    "request": "GET /.git/config HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n[core]\n\trepositoryformatversion = 0\n..."
  }
}
```

Use scope `host` only for host-wide issues; crawl findings are almost always
scope `endpoint` with `target_ref` = the affected URL.

## Step-by-step wiring summary

| Methodology step | rupu output |
|---|---|
| katana / hakrawler / gospider / gau / waybackurls parse (`merge_urls.py`) | `assets.mark` `web:site` depth `crawled` for each crawled base URL |
| inventory split (`urls_to_work_units.py`) | work-units array + `assets.mark` `web:route` depth `crawled` per route |
| anything verified during crawl triage | `findings.report` scope `endpoint` |
| handoff to parameter/content/vuln skills | the work-units array via the `work-units` skill |
