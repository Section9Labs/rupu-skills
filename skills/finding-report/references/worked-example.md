# Worked Example — A Complete Finding, Section by Section

All data below is invented for illustration. Target: `portal.example.com`
(203.0.113.20), tested from 203.0.113.9. The finding is first written out as
prose (the methodology sections from [SKILL.md](../SKILL.md)), then shown as the
single rupu `findings.report` call.

---

## 1. Title

**Unauthenticated user-data export via `GET /api/v1/export/users` on portal.example.com**

Not "Broken Access Control" (class name), not "Sensitive data exposure in the
API" (which API? which endpoint?). The title names the feature (the user-export
endpoint) and the target (portal.example.com).

## 2. Affected asset / locator

- **Product**: Acme Customer Portal v2.8.1
- **Owner**: Portal Platform Team (named in the engagement brief; otherwise this would be `Unknown`)
- **Affected component**: `portal-api` service — route `GET /api/v1/export/users`
- **Source repository**: `git.example.com/acme/portal-api` @ `src/routes/export.py`
- **Location / input**: `GET https://portal.example.com/api/v1/export/users?format=csv`
  — the `format` query parameter selects `csv` or `json`; no authentication
  material of any kind is required.
- **Location / output**: HTTP 200 response body containing one row per
  registered user: `user_id, email, full_name, phone, bcrypt_password_hash,
  last_login_ip`. Downstream, the same data feeds the nightly BI export, so the
  endpoint mirrors the full `users` table (14,382 rows at test time).

## 3. Severity

- **Impact: High** — full disclosure of all customer PII plus password hashes;
  no integrity or availability effect.
- **Likelihood: High** — endpoint is Internet-reachable, requires no account,
  and is trivially discoverable (it appears in the portal's public JS bundle).
- **Risk rating: High** (High impact × High likelihood). **Risk factor: High.**
- **CVSS v3.1: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)** — High.

Per-metric rationale (every choice tied to evidence):

| Metric | Choice | Because |
|---|---|---|
| AV | N | Exploited from 203.0.113.9 over the public Internet with one HTTPS request (Evidence E1) |
| AC | L | Deterministic; the same request succeeded on every attempt, no race or special condition |
| PR | N | No cookie, token, or header was sent (Evidence E1 shows the raw request) |
| UI | N | No victim action involved |
| S | U | Disclosure stays within the portal's own security authority; no other component is crossed |
| C | H | The complete `users` table is exposed, including password hashes — total confidentiality loss for that component (Evidence E2) |
| I | N | The endpoint is read-only; no write path demonstrated |
| A | N | No availability effect observed |

Score computed with the FIRST CVSS v3.1 calculator; 7.5 maps to **High**
(7.0–8.9), consistent with the qualitative rating. Offline password cracking of
the exposed bcrypt hashes could escalate to account takeover — that chain is
discussed under Impact but, per the scoring rule, is **not** folded into I/C
here because it is a follow-on attack.

## 4. Root cause

The route handler `export_users()` in `src/routes/export.py` (lines 27–41) is
registered without the `@require_auth` decorator that every other `/api/v1/*`
route uses; the module-level assumption that `register_api_routes()` applies
authentication globally is wrong — it only applies it to routes registered
through `api_route()`, and `export_users()` is registered via a raw
`app.add_url_rule()` call added in commit `9f3c2ab`.

(Note: "the endpoint returns user data without auth" is the symptom; the
missing decorator on a raw route registration is the defect.)

## 5. Description, impact, attack scenario

**Description** (fact layer):

> The `portal-api` service on portal.example.com exposes
> `GET /api/v1/export/users`, an administrative bulk-export feature. Every
> other route under `/api/v1/` enforces a session or bearer token via the
> `@require_auth` decorator; this route is registered directly with
> `app.add_url_rule()` and performs no authentication or authorization check
> (Evidence E3). An anonymous HTTP GET returns the full contents of the
> `users` table in CSV or JSON (Evidence E1, E2). The endpoint URL is present
> in the publicly served JavaScript bundle `main.3f1a.js`, so it is
> discoverable without source access (Evidence E4).

**Impact** (labeled inference allowed):

> Any Internet user can download the complete customer dataset: 14,382 records
> containing names, email addresses, phone numbers, bcrypt password hashes, and
> last-login IPs. Direct consequences: large-scale PII breach with regulatory
> exposure (GDPR Art. 33/34 notification), credential-stuffing and targeted
> phishing against the customer base, and — by inference — offline cracking of
> weak passwords from the exposed hashes leading to account takeover on the
> portal and on any service where customers reuse passwords.

**Attack scenario**: an attacker finds the endpoint path in the public JS
bundle (or by wordlist probing), issues one unauthenticated GET, and exfiltrates
the full user table in under a second. No account, no interaction, no exploit
development.

**Attack vector** (summary line): Remote, unauthenticated HTTPS GET to a
public endpoint; no user interaction required.

## 6. Call chain

1. **source** — `GET /api/v1/export/users` (external HTTPS entry),
   `src/app.py:88` `app.add_url_rule("/api/v1/export/users", view_func=export_users)` —
   gate: *authentication middleware* — passes because this registration
   bypasses `api_route()`, the only place `@require_auth` is attached.
2. **hop** — `export_users()` at `src/routes/export.py:27–41` — no gate;
   reads `format` from the query string and calls the exporter.
3. **sink** — `dump_all_users()` at `src/services/export_service.py:12–30` —
   executes `SELECT * FROM users` and serializes every column, including
   `password_hash`, into the HTTP response.

## 7. Reproduction / proof of concept

Tested against portal-api commit `9f3c2ab` (v2.8.1) on 2025-06-01.

1. `export TARGET=https://portal.example.com   # 203.0.113.20`
2. Confirm the control case — authenticated routes reject anonymous requests:
   `curl -sk -o /dev/null -w '%{http_code}\n' "$TARGET/api/v1/profile"` → prints `401`.
3. Trigger the issue:
   `curl -sk "$TARGET/api/v1/export/users?format=csv" -o users.csv -w '%{http_code}\n'` → prints `200`.
4. Verify the content:
   `head -3 users.csv` and `wc -l users.csv`.
5. **Success looks like**: `users.csv` begins with the header
   `user_id,email,full_name,phone,password_hash,last_login_ip` followed by real
   user rows (14,383 lines total at test time), returned without any
   authentication material in the request.

## 8. Evidence (one claim per entry)

**E1 — claim**: "The endpoint returns HTTP 200 to a request carrying no
authentication material." (`lang: http`, artifact `poc/export_poc.sh`)

```
GET /api/v1/export/users?format=csv HTTP/1.1
Host: portal.example.com

HTTP/1.1 200 OK
Content-Type: text/csv
Content-Length: 1948211
```

**E2 — claim**: "The response body contains PII and password hashes for users
other than any test account." (artifact `poc/users_head.txt`, redacted sample)

```
user_id,email,full_name,phone,password_hash,last_login_ip
1001,a.ortiz@example.com,Ana Ortiz,+1-555-0142,$2b$12$u1Qx…<redacted>,203.0.113.77
1002,b.khan@example.com,Bilal Khan,+1-555-0177,$2b$12$rT9k…<redacted>,203.0.113.81
…
```

**E3 — claim**: "The route is registered without the authentication decorator
used by all sibling routes." (`file: src/app.py`, `lines: [86, 88]`, `lang: python`)

```python
# all other routes: api_route("/api/v1/...", require_auth=True)
app.add_url_rule("/api/v1/export/users",
                 view_func=export_users)   # no @require_auth
```

**E4 — claim**: "The endpoint path is discoverable in the publicly served JS
bundle." (artifact `poc/js_grep.txt`)

```
$ curl -sk $TARGET/static/main.3f1a.js | grep -o '/api/v1/export/users'
/api/v1/export/users
```

**Artifacts**: `poc/export_poc.sh`, `poc/users_head.txt` (first 3 lines only,
hashes truncated), `poc/js_grep.txt`.

## 9. Remediation

**Prose**: (1) Register `export_users` through `api_route()` with
`require_auth=True` and an explicit `admin` role check — bulk export is an
administrative function. (2) Stop serializing `password_hash` and
`last_login_ip` in any export; exports should use an explicit column allowlist.
(3) Interim mitigation until deploy: block `GET /api/v1/export/users` for
unauthenticated clients at the edge proxy. (4) Rotate credentials: force a
password reset for all users, since hashes must be treated as exposed.

**Recommended patch** (minimal unified diff):

```diff
--- a/src/app.py
+++ b/src/app.py
@@ -85,4 +85,4 @@ def register_api_routes(app):
-    app.add_url_rule("/api/v1/export/users",
-                     view_func=export_users)
+    api_route(app, "/api/v1/export/users",
+              view_func=export_users, require_auth=True, roles=["admin"])
--- a/src/services/export_service.py
+++ b/src/services/export_service.py
@@ -12,7 +12,8 @@ def dump_all_users():
-    rows = db.execute("SELECT * FROM users")
+    rows = db.execute(
+        "SELECT user_id, email, full_name, phone FROM users")
```

Notes: the second hunk removes `password_hash` and `last_login_ip` from the
export regardless of caller — defense in depth independent of the auth fix.

**CI/CD detection** (stage: pre-merge; expect: semgrep exits non-zero and the
job fails when any route bypasses `api_route()`):

```yaml
# .semgrep/raw-route-registration.yml
rules:
  - id: raw-route-registration-bypasses-auth
    languages: [python]
    severity: ERROR
    message: >
      Route registered with app.add_url_rule() bypasses the authentication
      wrapper. Register API routes via api_route() instead.
    pattern: $APP.add_url_rule(...)
    paths:
      include: ["src/"]
```

Command: `semgrep --config .semgrep/raw-route-registration.yml --error src/`

**Regression test** (deterministic; fails on vulnerable build, passes on patched):

```python
# tests/test_export_requires_auth.py
def test_export_users_rejects_anonymous(client):
    r = client.get("/api/v1/export/users?format=csv")
    assert r.status_code == 401, (
        f"expected 401 for anonymous export, got {r.status_code}")
    assert b"password_hash" not in r.data
```

- Command: `pytest tests/test_export_requires_auth.py -q`
- Expect on vulnerable build: `AssertionError: expected 401 for anonymous export, got 200` — **1 failed**
- Expect on patched build: `1 passed`

## 10. References, tickets, cross-links, verification

- CWE-306: Missing Authentication for Critical Function (primary); CWE-359: Exposure of Private Personal Information.
- OWASP Top 10 2021 — A01: Broken Access Control; OWASP API Security Top 10 — API2: Broken Authentication.
- No CVE: first-party code, not a third-party component.
- Tickets: **None Provided** (none mentioned in the evidence or brief — do not invent one).
- Cross-references: sibling finding `fnd_8c21e7` ("Verbose stack traces on portal.example.com") — same service, lower severity.
- Verification: **confirmed** — replication steps 1–5 executed successfully on 2025-06-01.

---

## The same finding as one rupu `findings.report` call

```json
{
  "title": "Unauthenticated user-data export via GET /api/v1/export/users on portal.example.com",
  "ownership": {
    "owner": "Portal Platform Team",
    "product": "Acme Customer Portal v2.8.1",
    "affected_component": "portal-api — GET /api/v1/export/users",
    "source_repository": "git.example.com/acme/portal-api @ src/routes/export.py"
  },
  "tickets": "None Provided",
  "rating": {
    "impact": "High",
    "likelihood": "High",
    "risk_rating": "High",
    "risk_factor": "High",
    "cvss_v3": "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
  },
  "category": "Broken Access Control",
  "attack_vector": "Remote, unauthenticated HTTPS GET to a public endpoint; no user interaction required.",
  "cwe": ["CWE-306", "CWE-359"],
  "description": "The portal-api service on portal.example.com (203.0.113.20) exposes GET /api/v1/export/users, an administrative bulk-export feature. Every other /api/v1/ route enforces a session or bearer token via @require_auth; this route is registered directly with app.add_url_rule() and performs no authentication or authorization check (E3). An anonymous GET returns the full users table in CSV or JSON (E1, E2). The endpoint path appears in the publicly served bundle main.3f1a.js (E4).\n\nCVSS rationale — AV:N: exploited over the Internet with one HTTPS request (E1); AC:L: deterministic on every attempt; PR:N: no cookie/token/header sent (E1); UI:N: no victim action; S:U: disclosure stays within the portal's authority; C:H: complete users table including password hashes (E2); I:N: read-only endpoint; A:N: no availability effect.",
  "impact": "Any Internet user can download the complete customer dataset: 14,382 records with names, emails, phone numbers, bcrypt password hashes, and last-login IPs. Direct consequences: large-scale PII breach with regulatory notification duties (GDPR Art. 33/34), credential stuffing, and targeted phishing. By inference (not scored into CVSS), offline cracking of weak passwords from the exposed hashes enables account takeover on the portal and on services where customers reuse passwords.",
  "location": {
    "input": "`GET https://portal.example.com/api/v1/export/users?format=csv` — `format` selects csv|json; no authentication material required.",
    "output": "HTTP 200 body mirroring the full `users` table (user_id, email, full_name, phone, bcrypt password_hash, last_login_ip); same data feeds the nightly BI export."
  },
  "root_cause": "The route handler export_users() in src/routes/export.py:27-41 is registered without the @require_auth decorator used by all sibling routes; the assumption that register_api_routes() applies authentication globally is wrong — it only covers routes registered through api_route(), and export_users() is registered via a raw app.add_url_rule() call (commit 9f3c2ab).",
  "call_chain": [
    {"label": "GET /api/v1/export/users", "role": "source", "file": "src/app.py", "lines": [86, 88], "gate": "authentication middleware", "passes_because": "raw app.add_url_rule() registration bypasses api_route(), the only place @require_auth is attached"},
    {"label": "export_users()", "role": "hop", "file": "src/routes/export.py", "lines": [27, 41]},
    {"label": "dump_all_users() — SELECT * FROM users serialized into the response", "role": "sink", "file": "src/services/export_service.py", "lines": [12, 30]}
  ],
  "evidence": [
    {"claim": "The endpoint returns HTTP 200 to a request carrying no authentication material.", "lang": "http", "excerpt": "GET /api/v1/export/users?format=csv HTTP/1.1\nHost: portal.example.com\n\nHTTP/1.1 200 OK\nContent-Type: text/csv\nContent-Length: 1948211", "artifact": "poc/export_poc.sh"},
    {"claim": "The response body contains PII and password hashes for users other than any test account.", "excerpt": "user_id,email,full_name,phone,password_hash,last_login_ip\n1001,a.ortiz@example.com,Ana Ortiz,+1-555-0142,$2b$12$u1Qx…<redacted>,203.0.113.77\n1002,b.khan@example.com,Bilal Khan,+1-555-0177,$2b$12$rT9k…<redacted>,203.0.113.81", "artifact": "poc/users_head.txt"},
    {"claim": "The route is registered without the authentication decorator used by all sibling routes.", "file": "src/app.py", "lines": [86, 88], "lang": "python", "excerpt": "app.add_url_rule(\"/api/v1/export/users\",\n                 view_func=export_users)   # no @require_auth"},
    {"claim": "The endpoint path is discoverable in the publicly served JS bundle.", "excerpt": "$ curl -sk $TARGET/static/main.3f1a.js | grep -o '/api/v1/export/users'\n/api/v1/export/users", "lang": "sh", "artifact": "poc/js_grep.txt"}
  ],
  "artifacts": [
    {"path": "poc/export_poc.sh"},
    {"path": "poc/users_head.txt"},
    {"path": "poc/js_grep.txt"}
  ],
  "remediation": "1. Register export_users through api_route() with require_auth=True and an explicit admin role check. 2. Replace SELECT * with an explicit column allowlist; never serialize password_hash or last_login_ip. 3. Interim: block GET /api/v1/export/users for unauthenticated clients at the edge proxy. 4. Force a password reset for all users; the hashes must be treated as exposed.",
  "recommended_patch": {
    "diff": "--- a/src/app.py\n+++ b/src/app.py\n@@ -85,4 +85,4 @@ def register_api_routes(app):\n-    app.add_url_rule(\"/api/v1/export/users\",\n-                     view_func=export_users)\n+    api_route(app, \"/api/v1/export/users\",\n+              view_func=export_users, require_auth=True, roles=[\"admin\"])\n--- a/src/services/export_service.py\n+++ b/src/services/export_service.py\n@@ -12,7 +12,8 @@ def dump_all_users():\n-    rows = db.execute(\"SELECT * FROM users\")\n+    rows = db.execute(\n+        \"SELECT user_id, email, full_name, phone FROM users\")\n",
    "notes": "The second hunk removes password_hash and last_login_ip from the export regardless of caller — defense in depth independent of the auth fix."
  },
  "ci_cd_detection": {
    "stage": "pre-merge",
    "body": "```yaml\nrules:\n  - id: raw-route-registration-bypasses-auth\n    languages: [python]\n    severity: ERROR\n    message: Route registered with app.add_url_rule() bypasses the authentication wrapper. Register API routes via api_route() instead.\n    pattern: $APP.add_url_rule(...)\n    paths:\n      include: [\"src/\"]\n```",
    "command": "semgrep --config .semgrep/raw-route-registration.yml --error src/",
    "expect": "semgrep exits non-zero and reports raw-route-registration-bypasses-auth when any route bypasses api_route(), failing the job"
  },
  "regression_test": {
    "body": "def test_export_users_rejects_anonymous(client):\n    r = client.get(\"/api/v1/export/users?format=csv\")\n    assert r.status_code == 401, (\n        f\"expected 401 for anonymous export, got {r.status_code}\")\n    assert b\"password_hash\" not in r.data",
    "command": "pytest tests/test_export_requires_auth.py -q",
    "expect_vulnerable": "AssertionError: expected 401 for anonymous export, got 200 — 1 failed",
    "expect_patched": "1 passed"
  },
  "replication_steps": [
    "export TARGET=https://portal.example.com   # 203.0.113.20; tested at commit 9f3c2ab (v2.8.1)",
    "Control case: curl -sk -o /dev/null -w '%{http_code}\\n' \"$TARGET/api/v1/profile\"  → prints 401",
    "curl -sk \"$TARGET/api/v1/export/users?format=csv\" -o users.csv -w '%{http_code}\\n'  → prints 200",
    "head -3 users.csv && wc -l users.csv",
    "Success: users.csv starts with 'user_id,email,full_name,phone,password_hash,last_login_ip' followed by real user rows (14,383 lines at test time), with no authentication material in the request."
  ],
  "cross_references": [
    {"finding_id": "fnd_8c21e7", "relation": "sibling", "note": "Same portal-api service; verbose stack traces, lower severity."}
  ],
  "references": "- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)\n- [CWE-359: Exposure of Private Personal Information](https://cwe.mitre.org/data/definitions/359.html)\n- OWASP Top 10 2021 — A01: Broken Access Control\n- OWASP API Security Top 10 — API2: Broken Authentication\n- No CVE applicable (first-party code).",
  "classifications": [
    {"system": "OWASP", "id": "A01:2021"}
  ],
  "verification": {
    "status": "confirmed",
    "notes": "Replication steps 1–5 executed successfully against 203.0.113.20 on 2025-06-01."
  }
}
```

Points to notice in the mapping:

- `tickets` uses the sentinel `"None Provided"` rather than an invented Jira id.
- The CVSS rationale lives in `description` so the score is auditable; the
  speculative hash-cracking chain lives in `impact`, labeled as inference, and
  is not folded into the C/I metrics.
- Each `evidence` entry carries exactly one claim; source excerpts carry
  `file` + `lines`; file-backed claims name their `artifact`.
- `cross_references` uses a real `fnd_` id returned by an earlier
  `report_finding` call — never a made-up one; with no related findings it
  would be the string `"None"`.
- The regression test is asymmetric: `expect_vulnerable` is a failure,
  `expect_patched` is a pass.
