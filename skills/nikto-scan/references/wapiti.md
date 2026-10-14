# wapiti deep-dive

Wapiti 3.x: black-box web vulnerability scanner — crawls, then actively
injects into every discovered parameter/form. The active-DAST complement to
nikto's signature sweep.

## Core run

```
wapiti -u https://192.0.2.10/ -f json -o wapiti.json
wapiti -u https://192.0.2.10/app/ --scope folder -d 5 \
  -m "sql,xss,exec,file,ssrf,xxe,crlf,redirect,upload,csrf,timesql" \
  --max-links-per-page 200 --tasks 32 -f json -o wapiti.json --flush-session
```

- `-u <url>` base URL (required). Session state persists per target in
  `~/.wapiti/`; `--flush-session` to restart clean, `--resume-crawl` /
  `--skip-crawl` to reuse a previous crawl.
- `-d`/`--depth` crawl depth; `--max-links-per-page`, `--max-files-per-dir`,
  `--max-scan-time <seconds>`, `--max-attack-time` per module.
- `--tasks <n>` concurrent requests (default 32 in recent versions).
- `-p http://127.0.0.1:8080` proxy (also socks5://); `--verify-ssl 0`;
  `--timeout <s>`; `-H 'Header: value'` repeatable; `-A <user-agent>`.

## Scope (`--scope`)

| value | crawl boundary |
|-------|----------------|
| `url` | only the given URL |
| `page` | the page and its query variations |
| `folder` | everything under the starting folder (default) |
| `domain` | whole domain incl. subdomains |
| `punk` | every link found, on any domain (dangerous breadth) |

Exclusions: `-x`/`--exclude <url-pattern>` (repeatable, wildcards; always
exclude logout links on authenticated scans).

## Modules (`-m`)

`--list-modules` for the current set. Common ones: `backup`, `brute_login_form`,
`buster`, `cookieflags`, `crlf`, `csp`, `csrf`, `exec` (command injection),
`file` (path traversal / inclusion), `htaccess`, `http_headers`, `ldap`,
`log4shell`, `methods`, `nikto` (yes — wapiti has a nikto-DB module),
`permanentxss`, `redirect`, `shellshock`, `spring4shell`, `sql` (error-based),
`ssl`, `ssrf`, `takeover`, `timesql` (time-based blind SQLi), `upload`,
`wp_enum`, `xss`, `xxe`.

Selection grammar: `-m "sql,xss,exec"` exact set; `-m "common"` the default
bundle; subtract with a minus: `-m "common,-brute_login_form"`; `-m "all"`
everything (slow). `--dump-scan-report` / `--store-session` manage state.

Note on `ssrf` and `xxe`: full confirmation uses the wapiti3 external
endpoint (`--external-endpoint`, `--internal-endpoint`) for out-of-band
callbacks — set your own collaborator-style listener there.

## Authentication

```
# HTTP-level auth:
wapiti -u https://192.0.2.10/ -a 'user%password' --auth-method basic   # digest|ntlm
# Form login (wapiti logs in and keeps the session):
wapiti -u https://192.0.2.10/ --form-url https://192.0.2.10/login \
  --form-data 'username=admin&password=Winter2024!'
# Or bring cookies:
wapiti -u https://192.0.2.10/ -H 'Cookie: PHPSESSID=abcd1234'
wapiti-getcookie -u https://192.0.2.10/login -c cookies.json   # interactive helper
wapiti -u https://192.0.2.10/ -c cookies.json
```

Always pair auth with `-x` on the logout URL or the crawler kills its session.

## Report (`-f json -o wapiti.json`)

JSON schema (what to parse):

```json
{"classifications": {"SQL Injection": {"desc": "...", "sol": "...",
                     "ref": {"CWE-89": "https://cwe.mitre.org/..."}}},
 "vulnerabilities": {
   "SQL Injection": [
     {"method": "GET", "path": "/product.php", "info": "SQL Injection via parameter id",
      "parameter": "id", "level": 1, "module": "sql",
      "http_request": "GET /product.php?id=1%27 HTTP/1.1\nHost: 192.0.2.10\n...",
      "curl_command": "curl \"https://192.0.2.10/product.php?id=1%27\"",
      "wstg": ["WSTG-INPV-05"]}
   ],
   "Cross Site Scripting": [], "...": []
 },
 "anomalies": {"Internal Server Error": [...], "Resource consumption": [...]},
 "additionals": {"Fingerprint web technology": [...]},
 "infos": {"target": "https://192.0.2.10/", "date": "...", "crawled_pages_nbr": 142}}
```

Gold: each vulnerability entry carries `http_request` (ready-made evidence
exchange for `findings.report`), `parameter` (ready-made `param` coordinate
for `assets.mark` `web:route`), and `wstg` ids (ready-made classification).
`anomalies` (500s, timeouts) are leads, not findings — feed them to manual
testing. Other formats: `-f html -o report_dir/` (directory), `txt`, `xml`,
`csv`.

## Division of labor vs nikto

| | nikto | wapiti |
|---|---|---|
| known/default/dangerous files | strong (signature DB) | weak (`buster`/`backup` modules only) |
| server banner / outdated software | strong | partial (`http_headers`) |
| parameter injection (SQLi/XSS/exec/traversal) | token checks only | strong (its core purpose) |
| crawling | none | yes |
| auth-session scanning | basic auth only | full form-session support |

Run nikto first (fast, breadth), then wapiti on the same host with auth if
available. A route flagged by both is top of the triage queue.
