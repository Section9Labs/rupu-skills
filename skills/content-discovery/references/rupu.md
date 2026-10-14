# rupu wiring for content-discovery

Every parse/handoff step in this skill ends in one of three rupu-ingestible
outputs: a work-units JSON array, `assets.mark` calls, or a `findings.report`
call. `scripts/parse_discovery.py` emits the first two ready-made.

## 1. Work units (fan-out)

`parse_discovery.py --work-units units.json` writes a clean JSON **array**
whose first character is `[`. rupu's workflow `for_each:` JSON-parses a file
value that begins with `[` (read via the `read_file` tool); a lead agent reads
the same file and `dispatch`es one child per element. Normalize/split the
array with the shared `work-units` skill before fan-out.

Element shape:

```json
[
  {
    "id": "cd-192-0-2-10-0001",
    "title": "Probe discovered route /admin/ on https://192.0.2.10",
    "targets": ["https://192.0.2.10/admin/"],
    "hints": {
      "category": "admin",
      "status": "401",
      "length": "312",
      "source": "ffuf",
      "redirect": "",
      "next": "auth-testing"
    }
  },
  {
    "id": "cd-192-0-2-10-0002",
    "title": "New virtual host dev.example.com on 192.0.2.10",
    "targets": ["https://dev.example.com/"],
    "hints": {
      "category": "vhost",
      "status": "200",
      "source": "gobuster-vhost",
      "next": "recon-and-crawl"
    }
  }
]
```

All `hints` values are strings. `hints.category` is one of
`admin|upload|api|backup|config|vhost|other`; `hints.next` suggests the
follow-on skill.

## 2. Assets (`assets.mark`)

Record every discovered route and vhost using the `coverage-assets` skill with
the `web` profile kinds (prefix `web:`). `parse_discovery.py --assets
assets.json` emits a JSON array of ready payloads:

Route found by brute force (reached rung: `mapped`):

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://192.0.2.10"},
    {"t": "http_route", "v": "/admin/"}
  ],
  "label": "/admin/ [401]",
  "depth": "mapped"
}
```

Route with a parameter (gobuster fuzz / ffuf GET fuzzing):

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://192.0.2.10"},
    {"t": "http_route", "v": "/index.php"},
    {"t": "param", "v": "page"}
  ],
  "label": "/index.php?page= [200]",
  "depth": "mapped"
}
```

New virtual host (a whole new site):

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://dev.example.com"}],
  "label": "https://dev.example.com (vhost of 192.0.2.10)",
  "depth": "mapped"
}
```

Depth ladder — mark the rung actually reached:

- `mapped` — route/vhost discovered by brute force (this skill's default).
- `crawled` — route subsequently crawled.
- `tested` — route fuzzed / vuln-tested by a follow-on skill.
- `exploited` — issue confirmed/exploited on the route.

When a follow-on skill advances a route, re-mark the same coordinates at the
higher rung.

## 3. Findings (`findings.report`)

When discovery itself verifies an issue (exposed `.env` with credentials,
readable `.git/`, directory listing, open admin console), report it
immediately via the `finding-report` skill. Web issues use scope `endpoint`
with `target_ref` = affected URL (scope `host` only for host-wide issues).
Satisfy all three `web`-profile completeness checks: pinned route/URL, HTTP
exchange in evidence, OWASP-or-CWE classification.

```json
{
  "title": "Exposed environment file disclosing database credentials",
  "scope": "endpoint",
  "target_ref": "https://192.0.2.10/.env",
  "severity": "high",
  "classification": "CWE-538 / WSTG-CONF-04",
  "evidence": {
    "rationale": "The application serves its dotenv configuration file at /.env. The response body contains DB_HOST, DB_USERNAME and DB_PASSWORD values valid for the backing database, giving any unauthenticated client working credentials. Weakness: file and directory information exposure (CWE-538), insecure file/dir configuration (WSTG-CONF-04).",
    "http_exchange": "GET /.env HTTP/1.1\nHost: 192.0.2.10\nUser-Agent: Mozilla/5.0\n\nHTTP/1.1 200 OK\nContent-Type: application/octet-stream\nContent-Length: 143\n\nAPP_ENV=production\nDB_HOST=203.0.113.5\nDB_USERNAME=appuser\nDB_PASSWORD=S3cr3tP@ss\n"
  }
}
```

After reporting, re-mark the route's asset at depth `exploited` (confirmed)
or `tested` (probed, not confirmed).

## Step-by-step wiring summary

| Methodology step | rupu output |
|---|---|
| Step 1-3 raw tool runs | none (raw files on disk) |
| Step 4 parse/merge | `--assets` → `assets.mark` per route/vhost (`mapped`); `--work-units` → JSON array for `for_each:`/`dispatch` via the `work-units` skill |
| Step 5 chaining | each verified issue → `findings.report` via `finding-report`; follow-on skills re-mark assets at `tested`/`exploited` |
