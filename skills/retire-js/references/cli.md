# Retire.js CLI reference

## Core flags

| Flag | Meaning |
|---|---|
| `--path <dir>` | Directory to scan (default: current directory). |
| `--outputformat <fmt>` | `text` (default), `json`, `cyclonedx` (XML SBOM), `cyclonedx-json`, `depcheck` (OWASP Dependency-Check XML bridge). |
| `--outputpath <file>` | Write the report to a file instead of stdout. |
| `--severity <level>` | Minimum severity that triggers the failure exit code: `low` \| `medium` \| `high` \| `critical`. Lower-severity findings are still listed. |
| `--exitwith <code>` | Exit code to use when vulnerabilities are found (default `13`). Lets CI distinguish "findings" from "tool crashed". |
| `--ignore <paths/components>` | Comma-separated paths or component names to skip (repeatable in practice via commas). |
| `--ignorefile <file>` | JSON ignore file, conventionally `.retireignore.json` (schema below). |
| `--deep` | Scan files that would otherwise be skipped (slower, more thorough on odd layouts). |
| `--ext <list>` | Comma-separated extra file extensions to treat as scannable (e.g. `js,mjs,html`). |
| `--verbose` | Show files scanned, components with no known vulns, and debug detail. |
| `--includemeta` | Include metadata/detection info in output. |
| `--colors` / `--nocolors` | Force/disable ANSI colors in text output. |

## Scope flags (legacy v1/v2; v3+ is JS-file focused)

| Flag | Meaning |
|---|---|
| `--js` | Scan only JavaScript files (skip node_modules/package.json analysis). |
| `--node` | Scan only Node packages. |
| `--jspath <dir>` | Separate root for the JS-file scan. |
| `--nodepath <dir>` | Separate root for the Node package scan. |

On Retire.js v3+ there is no node-tree scanner; it still reads
`package.json`/`node_modules` library files it encounters as JS content, but
the dependency-graph job belongs to osv-scanner / grype / dependency-check.

## Vulnerability database flags

| Flag | Meaning |
|---|---|
| `--jsrepo <url|file>` | Use a custom vulnerability repository (mirror or extended repo) instead of the default `jsrepository-v4.json` from the Retire.js GitHub. |
| `--nocache` | Do not use the local cache of the vuln repo — force re-download (i.e. update definitions). |
| `--cachedir <dir>` | Cache location (default `~/.retire-cache/`). |
| `--cacheduration <sec>` | How long the cached repo is considered fresh. |
| `--insecure` | Allow TLS connections with invalid/intercepted certificates when fetching the repo. |
| `--proxy <url>` | HTTP(S) proxy for repo download, e.g. `--proxy http://198.51.100.7:8080`. |

## `.retireignore.json` schema

A JSON **array** of ignore rules. Each rule matches by `path` or by
`component` (optionally with `version`), and should carry a `justification`:

```json
[
  { "path": "static/vendor/legacy/", "justification": "dead code, removed next sprint" },
  { "component": "jquery", "version": "1.8.1", "justification": "accepted risk FP-1234" },
  { "component": "lodash", "identifiers": { "CVE": ["CVE-2019-10744"] },
    "justification": "prototype pollution sink not reachable" }
]
```

Rules with `identifiers` waive only the matching advisory for that component;
rules with just `component` waive the whole component; `path` rules waive
everything under that path prefix.

## JSON output anatomy (v3/v4)

```json
{
  "version": "5.2.4",
  "start": "2024-01-01T00:00:00.000Z",
  "data": [
    {
      "file": "static/vendor/jquery.min.js",
      "results": [
        {
          "component": "jquery",
          "version": "1.8.1",
          "detection": "filecontent",
          "vulnerabilities": [
            {
              "severity": "medium",
              "identifiers": {
                "CVE": ["CVE-2012-6708"],
                "issue": "11290",
                "summary": "Selector interpreted as HTML",
                "githubID": "GHSA-2pqj-h3vj-pqgw"
              },
              "info": ["https://bugs.jquery.com/ticket/11290"],
              "below": "1.9.0",
              "atOrAbove": "1.0.0"
            }
          ]
        }
      ]
    }
  ],
  "messages": [],
  "errors": []
}
```

Very old Retire.js versions emit the `data` array as the top-level JSON value;
`scripts/retirejs_to_workunits.py` handles both shapes.

`detection` values: `filename` (name pattern), `filecontent` (regex/signature
in the file body), `hash` (exact content hash of a known release) — `hash` and
`filecontent` are the high-confidence ones for minified vendored libs.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities at/above `--severity`. |
| `13` (or `--exitwith`) | Vulnerabilities found. |
| anything else | Tool/configuration error (bad path, repo download failure, etc.). |

— vulture (fuchsia-pavilion)
