# rupu wiring for sqli-testing

Every parse/handoff step in this skill ends in one of three rupu-ingestible outputs:
a **work-units JSON array**, **`assets.mark`** calls, or a **`findings.report`** call.
`scripts/parse_sqlmap.py` emits ready-made payloads for all three.

Shared skills to import by name (same rupu-skills library — do not re-implement):

- `work-units` — canonical work-unit splitter/normalizer. Hand it the array emitted by
  `parse_sqlmap.py --work-units`.
- `coverage-assets` — records assets; feed it the `assets.json` payloads below.
- `finding-report` — writes a complete finding; feed it the `findings.json` payloads below.

## 1. Work units (fan-out)

A clean JSON **array** file whose first character is `[`. rupu's `for_each:` JSON-parses a
file value beginning with `[` (read via the `read_file` tool); a lead agent reads the same
file and `dispatch`es one child per element. One unit per injectable parameter still to
exploit/dump:

```json
[
  {
    "id": "sqli-192.0.2.10-id-get",
    "title": "Exploit SQLi: parameter 'id' (GET) at https://192.0.2.10/item.php",
    "targets": ["https://192.0.2.10/item.php?id=1"],
    "hints": {
      "param": "id",
      "place": "GET",
      "techniques": "boolean-based blind; time-based blind",
      "dbms": "MySQL >= 5.0.12",
      "payload": "id=1 AND 4321=4321",
      "next": "sqlmap -u 'https://192.0.2.10/item.php?id=1' -p id --batch --dbms='MySQL >= 5.0.12' --technique=BEUSTQ --dbs"
    }
  }
]
```

Produce with:

```
python3 scripts/parse_sqlmap.py --output-dir <sqlmap-out>/<host> --work-units work-units.json
```

Then: "hand the normalized array to the `work-units` skill", and fan out via workflow
`for_each:` or lead-agent `dispatch`.

## 2. Assets — `assets.mark`

Use the `web` engagement profile kinds (profile-namespaced, prefix `web:`). Depth ladder:
`mapped` → `crawled` → `tested` → `exploited`; mark the rung actually reached.

Site (probed/mapped):

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://192.0.2.10"}],
  "label": "https://192.0.2.10",
  "depth": "mapped"
}
```

Route with a confirmed injection (we ran payloads through it successfully → `exploited`):

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://192.0.2.10"},
    {"t": "http_route", "v": "/item.php"},
    {"t": "param", "v": "id"}
  ],
  "label": "SQLi: id (GET) /item.php — MySQL",
  "depth": "exploited"
}
```

Routes/parameters sqlmap tested but found **not** injectable: same shape, `depth: "tested"` —
this records negative coverage. Record all of these via the `coverage-assets` skill.

## 3. Findings — `findings.report`

One per confirmed injection point. Web issues use scope `endpoint` with `target_ref` the
affected URL (scope `host` only for host-wide issues). Severity: `high` baseline for SQLi;
`critical` when stacked queries confirmed, `--is-dba` true, sensitive data dumped, or
os-shell obtained. The `web` profile completeness checks require all three of: finding pinned
to a route/url, an HTTP exchange in evidence, an OWASP-or-CWE classification.

```json
{
  "title": "SQL injection in 'id' (GET) at https://192.0.2.10/item.php",
  "scope": "endpoint",
  "target_ref": "https://192.0.2.10/item.php?id=1",
  "severity": "high",
  "classification": {"owasp": "WSTG-INPV-05", "cwe": "CWE-89"},
  "evidence": {
    "rationale": "Parameter 'id' (GET) is injectable: boolean-based blind (payload: id=1 AND 4321=4321) and time-based blind (id=1 AND SLEEP(5), +5.0s). Back-end DBMS fingerprinted as MySQL >= 5.0.12. Databases enumerated: appdb, information_schema; dump of appdb.users (142 rows: username, password, email) demonstrates full read access to application data.",
    "http_exchange": "GET /item.php?id=1%20AND%204321%3D4321 HTTP/1.1\r\nHost: 192.0.2.10\r\nCookie: PHPSESSID=...\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5120\r\n\r\n...product page rendered (TRUE)...\r\n---\r\nGET /item.php?id=1%20AND%204321%3D4322 HTTP/1.1\r\n...\r\nHTTP/1.1 200 OK\r\nContent-Length: 1240\r\n\r\n...empty result (FALSE)..."
  }
}
```

NoSQL variant: same shape, `classification: {"owasp": "WSTG-INPV-05", "cwe": "CWE-943"}`,
exchange showing the `$ne`/`$regex` request and the bypassed/affected response.

`parse_sqlmap.py --findings findings.json` emits these with a reconstructed sample exchange
from the sqlmap payload; **replace/augment `evidence.http_exchange` with the real pair
captured in the proxy** (run sqlmap with `--proxy=http://127.0.0.1:8080` or `-v 4 -t traffic.txt`
to have it on hand), then file each via the `finding-report` skill.

## 4. Step-by-step wiring in the methodology

| Methodology step | rupu output |
|---|---|
| Manual probe confirms target reaches SQL | `assets.mark` route `tested` (or `exploited` if confirmed) |
| sqlmap detection run finishes | `parse_sqlmap.py` → work-units array → `work-units` skill → fan-out |
| sqlmap run tested params found clean | `assets.mark` route `tested` (negative coverage) |
| Injection confirmed | `assets.mark` route `exploited` + `findings.report` via `finding-report` skill |
| Data dumped / os-shell obtained | update finding severity → `critical`, add dump/shell evidence to the same finding |
| NoSQL bypass confirmed | `assets.mark` route `exploited` + finding with CWE-943 |

No parse step ends without one of these outputs.
