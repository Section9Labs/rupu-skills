# Worked example — one complete full-profile finding

Scenario: grey-box API assessment of `shop.example.com` (resolving to
203.0.113.20), source repository available. The product-search endpoint
`GET /api/v1/search` interpolates the `q` parameter into a SQL string.
Confirmed with manual boolean injection, then dumped the `users` table with
sqlmap; stacked queries work, so data can be modified or destroyed.

CVSS derivation (see `references/cvss.md`):
AV:N (public HTTPS endpoint) · AC:L (single request, no preconditions) ·
PR:N (no authentication) · UI:N (attacker alone) · S:U (impact confined to the
storefront's own PostgreSQL, same security authority) · C:H (full read of all
tables incl. credentials) · I:H (stacked `UPDATE`/`INSERT` arbitrary rows) ·
A:H (stacked `DROP TABLE` destroys the service's data).

```
$ python3 scripts/cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
9.8	CRITICAL	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

The complete `findings.report` call (profile `full`, engagement `api` profile
active). This validates against `urn:rupu:schema:finding-report:v1` and passes
`python3 scripts/check_report.py` — note what is absent: no `verification`, no
evidence `sha256`, artifacts carry only `path`.

```json
{
  "scope": "shop-api-assessment",
  "tags": ["sqli", "api", "unauthenticated"],
  "asset": {
    "kind": "api:endpoint",
    "coordinates": [
      { "t": "url", "v": "https://shop.example.com" },
      { "t": "http_route", "v": { "method": "GET", "path": "/api/v1/search" } },
      { "t": "param", "v": "q" }
    ],
    "label": "shop.example.com GET /api/v1/search?q"
  },
  "report": {
    "title": "Unauthenticated SQL injection in the product-search `q` parameter on shop.example.com (GET /api/v1/search)",
    "ownership": {
      "owner": "Storefront Platform Team (per CODEOWNERS of storefront-api)",
      "product": "Example Shop storefront API",
      "affected_component": "GET /api/v1/search — product search handler, `q` query parameter",
      "source_repository": "https://git.example.com/shop/storefront-api#src/api/search.py"
    },
    "tickets": "None Provided",
    "rating": {
      "impact": "Critical",
      "likelihood": "High",
      "risk_rating": "Critical",
      "risk_factor": "Critical",
      "cvss_v3": "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
    },
    "category": "Injection",
    "attack_vector": "Remote, unauthenticated, no user interaction: a single crafted GET request to the public HTTPS endpoint https://shop.example.com/api/v1/search (203.0.113.20:443).",
    "cwe": ["CWE-89"],
    "description": "The product-search endpoint `GET /api/v1/search` builds its SQL statement by interpolating the attacker-controlled `q` query parameter directly into the query text (f-string in `search_handler()`, `src/api/search.py:41-44`) instead of binding it as a parameter. Any `'` in `q` terminates the string literal and the remainder is parsed as SQL by the backing PostgreSQL database. The endpoint requires no authentication, and the database driver executes stacked statements, so the injection is read-write.\n\nCVSS rationale: AV:N (public endpoint), AC:L (one request, no preconditions), PR:N (anonymous), UI:N, S:U (impact confined to the storefront's own database — same security authority), C:H/I:H/A:H (full read, arbitrary write, and destructive `DROP` via stacked queries).",
    "impact": "An anonymous internet attacker can read the entire storefront database — including the `users` table with 48,112 rows of email addresses and bcrypt password hashes, and the `orders` table with customer PII — by sending crafted search requests. Because stacked queries execute, the attacker can also modify prices, insert admin accounts, or `DROP` tables, destroying service data. Concretely: dump `users` → crack weak bcrypt hashes offline → authenticate to `/admin` as a recovered staff account, achieving full application takeover.",
    "location": {
      "input": "`q` query parameter of `GET https://shop.example.com/api/v1/search` (203.0.113.20:443, TLS).",
      "output": "SQL statement executed against the storefront PostgreSQL database (`products`, `users`, `orders` tables); results reflected in the JSON response body."
    },
    "root_cause": "`search_handler()` in `src/api/search.py` interpolates the raw `q` request parameter into the SQL text with an f-string (`f\"... WHERE name LIKE '%{q}%'\"`) instead of passing it as a bound parameter to `cur.execute`, so attacker input is parsed as SQL.",
    "call_chain": [
      {
        "label": "GET /api/v1/search route (FastAPI router)",
        "role": "source",
        "file": "src/api/routes.py",
        "lines": [18, 18],
        "gate": "authentication",
        "passes_because": "the route is registered on the public, unauthenticated router"
      },
      {
        "label": "search_handler(q)",
        "role": "hop",
        "file": "src/api/search.py",
        "lines": [37, 44],
        "gate": "input validation",
        "passes_because": "no sanitization or length check is applied to q"
      },
      {
        "label": "cur.execute(query) — SQL text containing raw q",
        "role": "sink",
        "file": "src/api/search.py",
        "lines": [44, 44]
      }
    ],
    "evidence": [
      {
        "claim": "The q parameter is interpolated into the SQL statement text without parameterization.",
        "file": "src/api/search.py",
        "lines": [41, 44],
        "excerpt": "query = f\"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'\"\ncur.execute(query)",
        "lang": "python"
      },
      {
        "claim": "A boolean-based payload alters query logic: q=widget' AND '1'='1 returns the same result set as q=widget, while q=widget' AND '1'='2 returns an empty set, proving the quote breaks into SQL context.",
        "artifact": "poc/boolean_probe.txt"
      },
      {
        "claim": "The full users table (48,112 rows: id, email, password bcrypt hashes) was dumped via the injection without any authentication.",
        "artifact": "poc/sqlmap_users_dump.csv"
      }
    ],
    "blocks": [
      {
        "kind": "http_exchange",
        "request": "GET /api/v1/search?q=widget%27%20AND%20%271%27%3D%271 HTTP/1.1\nHost: shop.example.com\nAccept: application/json\n\n",
        "response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{\"id\":17,\"name\":\"widget pro\",\"price\":19.99}, …same 23 rows as the benign query…]"
      }
    ],
    "remediation": "1. Bind user input instead of interpolating it: pass `q` as a parameter to `cur.execute` (`cur.execute(sql, (f\"%{q}%\",))`) in `search_handler()` — this is the complete fix.\n2. Defense in depth: run the API's database role with least privilege (no DDL, no access to `users.password`), and disable multi-statement execution on the driver connection.\n3. Audit the repository for the same pattern (`grep -rn 'f\"SELECT' src/`); the CI/CD detection below automates this.",
    "recommended_patch": {
      "diff": "--- a/src/api/search.py\n+++ b/src/api/search.py\n@@ -41,4 +41,4 @@ def search_handler(q: str):\n-    query = f\"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'\"\n-    cur.execute(query)\n+    query = \"SELECT id, name, price FROM products WHERE name LIKE %s\"\n+    cur.execute(query, (f\"%{q}%\",))\n",
      "notes": "psycopg2 `%s` placeholder binding; the wildcard wrapping moves into the bound value so the pattern semantics are unchanged. Equivalent for SQLAlchemy: `text(\"... LIKE :pat\").bindparams(pat=f\"%{q}%\")`."
    },
    "ci_cd_detection": {
      "stage": "pre-merge",
      "body": "Semgrep rule (semgrep --config sqli-fstring.yml --error):\n\n```yaml\nrules:\n  - id: python-sqli-fstring-execute\n    patterns:\n      - pattern: $CUR.execute(f\"...\")\n    message: SQL built with an f-string reaches execute(); bind parameters instead.\n    languages: [python]\n    severity: ERROR\n```",
      "command": "semgrep --config ci/semgrep/sqli-fstring.yml --error src/",
      "expect": "semgrep exits non-zero and reports python-sqli-fstring-execute on any f-string SQL reaching execute(), failing the merge."
    },
    "regression_test": {
      "body": "import requests\n\nBASE = \"https://shop.example.com\"\n\ndef test_search_q_not_injectable():\n    true_q = requests.get(BASE + \"/api/v1/search\", params={\"q\": \"widget' AND '1'='1\"}).json()\n    false_q = requests.get(BASE + \"/api/v1/search\", params={\"q\": \"widget' AND '1'='2\"}).json()\n    benign = requests.get(BASE + \"/api/v1/search\", params={\"q\": \"widget' AND '1'='1\"})  # literal string, no products match\n    # On a patched build the quoted payloads are literal search strings: both return [].\n    assert true_q == false_q == [], \"boolean payloads changed query logic: q is injectable\"\n",
      "command": "pytest tests/security/test_search_sqli.py -q",
      "expect_vulnerable": "AssertionError: boolean payloads changed query logic — the '1'='1 variant returns the full widget result set while '1'='2 returns [].",
      "expect_patched": "1 passed — both payloads are treated as literal search strings and return []."
    },
    "replication_steps": [
      "Baseline: curl -s 'https://shop.example.com/api/v1/search?q=widget' — HTTP 200, JSON array of 23 products.",
      "Boolean TRUE probe: curl -s 'https://shop.example.com/api/v1/search?q=widget%27%20AND%20%271%27%3D%271' — identical 23-row result set (payload executed as SQL).",
      "Boolean FALSE probe: curl -s 'https://shop.example.com/api/v1/search?q=widget%27%20AND%20%271%27%3D%272' — empty array []. The TRUE/FALSE differential confirms injection.",
      "Dump credentials: sqlmap -u 'https://shop.example.com/api/v1/search?q=widget' -p q --batch --level 2 --dump -T users — writes the users table (48,112 rows) to CSV; saved as poc/sqlmap_users_dump.csv.",
      "Confirm write capability (stacked queries): sqlmap -u 'https://shop.example.com/api/v1/search?q=widget' -p q --batch --sql-query \"INSERT INTO products(name,price) VALUES('rupu-poc-marker',0.01)\" then curl -s 'https://shop.example.com/api/v1/search?q=rupu-poc-marker' — the marker row is returned, proving INSERT executes."
    ],
    "cross_references": "None",
    "references": "- CWE-89: Improper Neutralization of Special Elements used in an SQL Command — https://cwe.mitre.org/data/definitions/89.html\n- OWASP Top 10 2021 A03: Injection — https://owasp.org/Top10/A03_2021-Injection/\n- OWASP WSTG-INPV-05: Testing for SQL Injection — https://owasp.org/www-project-web-security-testing-guide/\n- FIRST CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document",
    "artifacts": [
      { "path": "poc/boolean_probe.txt" },
      { "path": "poc/sqlmap_users_dump.csv" }
    ],
    "classifications": [
      { "system": "OWASP", "id": "A03:2021" },
      { "system": "CWE", "id": "CWE-89" }
    ]
  }
}
```

Why this passes the `api` profile's completeness checks: the asset locator has
an `http_route` (`endpoint_identified`) and the report carries an
`http_exchange` block (`evidence_has_exchange`). The `classifications` entries
additionally satisfy OWASP/CWE taxonomy expectations.

After recording, rupu returns a `fnd_` id. A follow-up finding (e.g. "weak
bcrypt cost factor permits offline cracking of dumped hashes") would set
`cross_references: [{"finding_id": "<that id>", "relation": "prerequisite",
"note": "hashes obtained via this SQL injection"}]`.
