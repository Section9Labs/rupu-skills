# rupu wiring for the codeql skill

The pipeline output is `workunits.json`: a **clean top-level JSON array**
(starts with `[`) of objects

```json
[
  {
    "id": "codeql-0001-a1b2c3d4",
    "title": "py/sql-injection @ app/db/orders.py:88",
    "targets": ["app/db/orders.py:88"],
    "hints": {
      "rule": "py/sql-injection",
      "severity": "9.8",
      "level": "error",
      "cwe": "CWE-089",
      "message": "This SQL query depends on a user-provided value.",
      "codeflow_steps": [
        "app/web/views.py:31 request.args['q']",
        "app/service/search.py:14 build_filter(q)",
        "app/db/orders.py:88 cursor.execute(sql)"
      ]
    }
  }
]
```

rupu's workflow `for_each:` JSON-parses any value that starts with `[`, so
this file can be consumed directly.

## Workflow: read_file + for_each

```yaml
steps:
  - id: scan
    run: >
      python3 scripts/run_codeql.py --language python
      --source-root /src/example.com-app --db /tmp/db-example
      --suite security-extended --sarif /tmp/results.sarif
      --output /tmp/workunits.json

  - id: load_units
    tool: read_file
    args:
      path: /tmp/workunits.json

  - id: triage_unit
    for_each: "{{ steps.load_units.output }}"   # parses: file starts with '['
    prompt: |
      Load the `work-units` skill conventions. You own ONE CodeQL work unit:
      {{ item }}
      Open each entry in targets (path:line). Walk hints.codeflow_steps in
      order — confirm the source is attacker-reachable, every propagation step
      holds, and the sink is exploitable; construct a concrete PoC input.
      If verified, load the `finding-report` skill and file it with
      findings.report. If dead (sanitized barrier, unreachable source), record
      why in your notes and move on.
```

## Lead-agent fan-out with dispatch

```yaml
  - id: fan_out
    for_each: "{{ steps.load_units.output }}"
    tool: dispatch
    args:
      agent: code-reviewer
      input: |
        CodeQL work unit (verify source->sink, PoC, then report):
        {{ item | tojson }}
      skills: ["codeql", "work-units", "finding-report"]
```

Batching: if there are hundreds of units, first load the `work-units` skill
to merge/split by file or rule before dispatch — do not hand one agent one
result line each; group by `targets[0]` file.

## Coverage: assets.mark

Mark the repo, every scanned file that produced results (plus the module
roots you pointed `--source-root` at), and dependency packages if SCA ran
alongside:

```json
{"tool": "assets.mark", "args": {"asset": "repo:example.com/payments-api", "kind": "repository", "status": "scanned", "note": "codeql python-security-extended, db /tmp/db-example"}}
{"tool": "assets.mark", "args": {"asset": "repo:example.com/payments-api:app/db/orders.py", "kind": "file", "status": "scanned", "note": "codeql: 2 results"}}
{"tool": "assets.mark", "args": {"asset": "repo:example.com/payments-api:app/web/", "kind": "module", "status": "scanned"}}
{"tool": "assets.mark", "args": {"asset": "pkg:pypi/flask@2.0.1", "kind": "dependency", "status": "scanned"}}
```

A helper to enumerate distinct files from the work units:

```bash
python3 - <<'EOF'
import json
units = json.load(open("/tmp/workunits.json"))
print("\n".join(sorted({t.rsplit(":",1)[0] for u in units for t in u["targets"]})))
EOF
```

## Reporting: findings.report (via the finding-report skill)

Only for **verified** units — after walking the code flow and building a PoC.
Load the `finding-report` skill for the full report format; the call shape:

```json
{
  "tool": "findings.report",
  "args": {
    "title": "SQL injection in orders search (py/sql-injection)",
    "asset": "repo:example.com/payments-api:app/db/orders.py",
    "severity": "critical",
    "cwe": "CWE-089",
    "evidence": "Source: app/web/views.py:31 request.args['q'] -> app/service/search.py:14 build_filter() -> sink app/db/orders.py:88 cursor.execute(sql). PoC: GET /orders?q=' UNION SELECT password_hash FROM users-- returns user hashes.",
    "reproduction": "codeql database analyze /tmp/db-example codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=results.sarif ; see result ruleId=py/sql-injection, codeFlow preserved in work unit codeql-0001-a1b2c3d4",
    "remediation": "Parameterize the query in build_filter(); use cursor.execute(sql, params)."
  }
}
```

## SARIF routing

Always route the raw `results.sarif` (per language, with `--sarif-category`
set) to the **`sarif-triage`** skill as well — it dedups across tools
(semgrep, codeql, SCA) and normalizes severity before the fan-out, so agents
don't verify the same sink twice.
