# rupu wiring for nikto-scan

Every parse/handoff step ends in one of three rupu-ingestible outputs: a
**work-units JSON array**, **`assets.mark`** calls, or a **`findings.report`**
call. `scripts/parse_nikto.py` emits the first and drafts the third. Shared
skills referenced by name — do not re-invent them:

- `work-units` — canonical splitter/normalizer; hand it every array this skill emits.
- `coverage-assets` — asset recording conventions behind `assets.mark`.
- `finding-report` — writing a complete finding behind `findings.report`.

## 1. Work units (fan-out)

Clean JSON **array** file, first character `[`. rupu `for_each:` JSON-parses
it (read via the `read_file` tool); a lead agent reads the same file and
`dispatch`es one child per element. One unit per nikto/wapiti finding worth
manual confirmation:

```json
[
  {
    "id": "nikto-192-0-2-10-server-status",
    "title": "Confirm: /server-status accessible (Apache mod_status exposed)",
    "targets": ["https://192.0.2.10/server-status"],
    "hints": {
      "tool": "nikto", "nikto_id": "OSVDB-561", "method": "GET",
      "msg": "/server-status: This reveals Apache information.",
      "confirm": "GET the path; a 200 with scoreboard HTML confirms"
    }
  },
  {
    "id": "wapiti-192-0-2-10-sqli-product-id",
    "title": "Exploit: SQL injection in /product.php param id",
    "targets": ["https://192.0.2.10/product.php"],
    "hints": {"tool": "wapiti", "module": "sql", "parameter": "id",
              "wstg": "WSTG-INPV-05",
              "curl": "curl \"https://192.0.2.10/product.php?id=1%27\""}
  }
]
```

Generate: `python3 scripts/parse_nikto.py out.json --work-units units.json`,
then hand the normalized array to the `work-units` skill.

## 2. assets.mark

`web` profile kinds (prefix `web:`), depth ladder
`mapped -> crawled -> tested -> exploited`. Nikto/wapiti actively probed the
target, so the scanned site is `tested`; routes they flagged are `tested`;
routes wapiti merely crawled are `crawled`; anything you then exploited is
`exploited`.

```json
{"kind": "web:site", "label": "https://192.0.2.10 (Apache/2.4.29, nikto baseline)",
 "coordinates": [{"t": "url", "v": "https://192.0.2.10"}], "depth": "tested"}
```

```json
{"kind": "web:route", "label": "Apache server-status exposed",
 "coordinates": [{"t": "url", "v": "https://192.0.2.10"},
                  {"t": "http_route", "v": "/server-status"}],
 "depth": "tested"}
```

Wapiti parameter finding (param coordinate from its `parameter` field):

```json
{"kind": "web:route", "label": "SQLi candidate: /product.php?id=",
 "coordinates": [{"t": "url", "v": "https://192.0.2.10"},
                  {"t": "http_route", "v": "/product.php"},
                  {"t": "param", "v": "id"}],
 "depth": "tested"}
```

Follow the `coverage-assets` skill for the calls.

## 3. findings.report — CONFIRMED items only

Nikto and wapiti false-positive heavily: replay first, report second. Scope
`endpoint` with `target_ref` = the affected URL; scope `host` only for
host-wide issues (outdated server version, TRACE enabled server-wide). The
`web` profile completeness checks require: finding pinned to a route/url, an
HTTP exchange in evidence, and an OWASP (WSTG/Top-10) or CWE classification —
satisfy all three.

```json
{
  "title": "Apache mod_status scoreboard exposed at /server-status",
  "scope": "endpoint",
  "target_ref": "https://192.0.2.10/server-status",
  "severity": "medium",
  "classification": "CWE-200 / OWASP A05:2021 / WSTG-INFO-02",
  "evidence": {
    "rationale": "nikto flagged /server-status; manual replay returns the live Apache scoreboard including internal client IPs and request URIs — information disclosure to unauthenticated users.",
    "http_exchange": "GET /server-status HTTP/1.1\nHost: 192.0.2.10\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><head><title>Apache Status</title>...",
    "references": ["https://httpd.apache.org/docs/2.4/mod/mod_status.html"]
  }
}
```

Wapiti findings arrive with `http_request` and `wstg` fields — paste the
request plus your captured response as the exchange, and the WSTG id as the
classification.

Heuristic severity used by `parse_nikto.py` drafts (operator overrides):
command exec / shell / upload-writable → `critical`; SQLi / traversal with
read / exposed VCS or `.env` / creds in backup → `high`; XSS / server-status /
default consoles reachable → `medium`; default files, banner/version info,
missing headers → `low`/`info`. Submit via the `finding-report` skill.
