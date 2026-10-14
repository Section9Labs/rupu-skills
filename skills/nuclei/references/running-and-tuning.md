# nuclei — flag reference and JSONL output dictionary

Current as of nuclei v3.x. Confirm oddities with `nuclei -h` and per-group help
(`nuclei -h` shows groups; `nuclei -hc` config help).

## Input

| Flag | Meaning |
|---|---|
| `-u, -target <url>` | single target; repeatable |
| `-l, -list <file>` | file of targets, one per line (URLs with scheme preferred; bare hosts get probed) |
| `-resume <file>` | resume an interrupted scan from its resume file |
| `-sa, -scan-all-ips` | scan all DNS A/AAAA records of a host |
| `-iv, -ip-version 4,6` | IP versions to scan |
| `-eh, -exclude-hosts` | exclude hosts/CIDRs from input |

Feed httpx output: `httpx -l hosts.txt -silent | nuclei -je out.jsonl` or save
URLs to a file and use `-l`.

## Template selection

| Flag | Meaning |
|---|---|
| `-t, -templates <path>` | template file or directory; repeatable; also remote URLs and `-tu` template URL lists |
| `-w, -workflows <path>` | workflow file/dir |
| `-tags <t1,t2>` | run templates carrying ANY of these tags |
| `-etags, -et` | `-etags` excludes by tag; `-et, -exclude-templates` excludes by path |
| `-s, -severity info,low,medium,high,critical,unknown` | include by severity |
| `-es, -exclude-severity` | exclude by severity |
| `-a, -author <name>` | include by template author |
| `-itags, -include-tags` | force-include tags that are excluded by default (e.g. `dos`, `fuzz`) |
| `-it, -include-templates` | force-include default-excluded templates |
| `-tc, -template-condition '<dsl>'` | arbitrary metadata DSL, e.g. `contains(tags,'cve') && severity=='critical'` |
| `-id, -template-id <id,...>` | run specific template IDs |
| `-nt, -new-templates` | only templates added in the latest release |
| `-pt, -type http,dns,tcp,ssl,headless,code,javascript` | by protocol type |
| `-as, -automatic-scan` | wappalyzer tech-detect, then run tag-matched templates |
| `-tl` | list all loaded templates and exit |
| `-td, -template-display` | print template content — **NOT tech-detect** (that's httpx's `-td`) |
| `-validate` | parse/lint selected templates and exit |

Default exclusions: templates tagged `dos`, `fuzz` (DAST) and `code`/`headless`
protocol templates don't run unless enabled (`-dast`, `-headless`, `-code`,
`-itags`).

## Updates

| Flag | Meaning |
|---|---|
| `-update` | self-update the nuclei binary |
| `-ut, -update-templates` | update nuclei-templates repo |
| `-ud, -update-template-dir` | custom template directory |
| `-duc, -disable-update-check` | no update banner |

## Rate limiting / concurrency

| Flag | Default | Meaning |
|---|---|---|
| `-rl, -rate-limit` | 150 | max requests/second (global) |
| `-rlm, -rate-limit-minute` | — | per-minute alternative |
| `-c, -concurrency` | 25 | templates executed in parallel |
| `-bs, -bulk-size` | 25 | hosts processed in parallel per template |
| `-timeout` | 10 | seconds per request |
| `-retries` | 1 | retries on failure |
| `-mhe, -max-host-error` | 30 | skip host after N errors |
| `-ss, -scan-strategy auto|host-spray|template-spray` | auto | iteration order |

Loud/fast: `-rl 500 -c 50 -bs 50`. Fragile target: `-rl 20 -c 10 -bs 5 -timeout 15`.

## Requests / auth / network

| Flag | Meaning |
|---|---|
| `-H, -header "Name: value"` | custom header/cookie; repeatable |
| `-V, -var name=value` | template variable; repeatable |
| `-r, -resolvers <file>` | custom DNS resolvers |
| `-proxy http://127.0.0.1:8080` | route via proxy (Burp inspection of what nuclei sends) |
| `-fr, -follow-redirects` / `-fhr` (same host) / `-mr` max redirects | redirect control |
| `-dialer-timeout`, `-dialer-keep-alive` | low-level tuning |
| `-sr, -system-resolvers` | fallback to OS resolver |
| `-rsr, -restrict-local-network-access` | off by default — nuclei WILL hit internal IPs via SSRF-style templates unless set |
| `-headless` | enable headless browser templates (Chrome required); `-sb` show browser, `-lha` listen address |
| `-dast` | enable fuzzing templates (deprecated alias: `-fuzz`) |
| `-code` | enable code-protocol templates |
| `-env-vars` | allow `{{env.VAR}}` expansion in templates |

## Interactsh (OOB)

| Flag | Meaning |
|---|---|
| (default) | public oast.* servers used automatically for `{{interactsh-url}}` templates |
| `-iserver, -interactsh-server <url>` | self-hosted interactsh server |
| `-itoken, -interactsh-token` | auth token for it |
| `-interactions-cache-size`, `-interactions-eviction`, `-interactions-poll-duration`, `-interactions-cooldown-period` | polling tuning (raise cooldown for slow blind callbacks) |
| `-ni, -no-interactsh` | disable OOB entirely (blind templates become no-ops) |

## Output

| Flag | Meaning |
|---|---|
| `-o <file>` | plain-text findings |
| `-jsonl, -j` | JSON Lines on stdout — the machine-readable form; **there is no `-json`** |
| `-je, -jsonl-export <file>` | JSON Lines to file (use this; keeps stdout clean) |
| `-irr, -include-rr` / `-omit-raw` | include/omit raw request+response in JSON (included by default in `-je` for matches) |
| `-me, -markdown-export <dir>` | per-finding markdown report dir |
| `-se, -sarif-export <file>` | SARIF |
| `-silent` | findings only, no banner/progress |
| `-stats` / `-si <sec>` | periodic progress stats |
| `-v`, `-debug`, `-debug-req`, `-debug-resp` | verbosity ladder; `-debug` dumps full req/resp — use when confirming a single template |
| `-ms, -matcher-status` | also report match-failure status |
| `-rdb, -report-db` | dedupe DB across runs |

## JSONL output fields

One object per match:

```json
{
  "template-id": "CVE-2021-44228",
  "template-path": "/root/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml",
  "info": {
    "name": "Apache Log4j2 Remote Code Injection",
    "author": ["melbadry9"],
    "tags": ["cve", "cve2021", "rce", "oast", "log4j"],
    "severity": "critical",
    "description": "...",
    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "classification": {
      "cve-id": ["cve-2021-44228"],
      "cwe-id": ["cwe-917"],
      "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "cvss-score": 10
    }
  },
  "type": "http",
  "host": "https://192.0.2.10",
  "matched-at": "https://192.0.2.10/login",
  "extracted-results": ["dns-interaction-id"],
  "request": "GET /login HTTP/1.1\r\nHost: 192.0.2.10\r\n...",
  "response": "HTTP/1.1 200 OK\r\n...",
  "ip": "192.0.2.10",
  "timestamp": "2025-06-01T12:00:00Z",
  "matcher-name": "dns-interaction",
  "matcher-status": true,
  "curl-command": "curl -X GET ... 'https://192.0.2.10/login'"
}
```

Field notes:

- `matched-at` is the exact URL (incl. path/port) where the match fired — pin
  findings and `web:route` assets here. `host` is the input target.
- `matcher-name` disambiguates multi-matcher templates (which check hit).
- `extracted-results` carries extractor output: version strings for tech
  templates, leaked tokens/paths for exposures. For tech routing, read
  `template-id` (e.g. `wordpress-detect`, `tech-detect`) + `extracted-results`.
- `curl-command` reproduces the matching request — the fastest manual
  confirmation path.
- Interactsh matches include an `interaction` object (protocol, remote address,
  raw request) proving the OOB callback.

## Triage workflow

1. `jq -r 'select(.info.severity=="critical" or .info.severity=="high")' nuclei.jsonl`
   (or use `scripts/parse_nuclei.py`) — confirm each via `curl-command` or a
   single-template `-debug` re-run.
2. Medium exposures (panels, `.git`, backups, debug endpoints): fetch the
   matched URL, extract creds/secrets/data, escalate.
3. Info tech-detect: build the tech map, route to `cms-testing` /
   `tls-testing` / manual skills.
4. Every parse step ends in rupu output — see `references/rupu.md`.
