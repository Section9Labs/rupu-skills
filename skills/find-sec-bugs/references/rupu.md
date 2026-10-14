# rupu wiring for find-sec-bugs output

The parser (`scripts/fsb_to_workunits.py`) writes a **clean top-level JSON
array** of work units, which rupu's `for_each:` JSON-parses directly (any
value starting with `[` is parsed).

Work-unit shape:

```json
[
  {
    "id": "fsb-0001-sql-injection-jdbc",
    "title": "SQL_INJECTION_JDBC in com.example.app.UserDao.findByName (UserDao.java:42)",
    "targets": ["src/main/java/com/example/app/UserDao.java:42"],
    "hints": {
      "pattern": "SQL_INJECTION_JDBC",
      "rank": "4",
      "priority": "1",
      "cwe": "CWE-89",
      "severity": "high",
      "class": "com.example.app.UserDao",
      "method": "findByName",
      "message": "This use of java/sql/Statement.executeQuery(...) can be vulnerable to SQL injection"
    }
  }
]
```

## Workflow: read_file + for_each

```yaml
steps:
  - id: scan
    run: >
      python3 skills/find-sec-bugs/scripts/run_findsecbugs.py
      --plugin /opt/findsecbugs-plugin.jar
      --aux target/deps --source src/main/java
      --out-dir fsb-out target/classes

  - id: load_units
    tool: read_file
    args:
      path: fsb-out/workunits.json

  - id: verify_each
    for_each: "{{ steps.load_units.output }}"   # top-level JSON array -> iterated
    as: unit
    prompt: |
      Verify this Find Security Bugs result against the source.
      Pattern: {{ unit.hints.pattern }} ({{ unit.hints.cwe }}),
      rank {{ unit.hints.rank }}, confidence priority {{ unit.hints.priority }}.
      Open {{ unit.targets | join(", ") }} and trace whether attacker-controlled
      input reaches the flagged sink in {{ unit.hints.class }}.{{ unit.hints.method }}.
      Load the `finding-report` skill and file via findings.report if confirmed.
```

## Lead-agent fan-out with dispatch

```yaml
  - id: fanout
    for_each: "{{ steps.load_units.output }}"
    as: unit
    tool: dispatch
    args:
      agent: code-review-worker
      input: |
        Work unit {{ unit.id }}: {{ unit.title }}
        Targets: {{ unit.targets | join(", ") }}
        Hints: {{ unit.hints | tojson }}
        Load the `find-sec-bugs` skill for the pattern playbook
        (references/bug-patterns.md), verify, and report via the
        `finding-report` skill.
```

For large result sets, first load the `work-units` skill to split/batch
`workunits.json` (e.g. group by pattern class or by file) instead of
dispatching one agent per raw result.

## Coverage: assets.mark

Mark the asset model — the repository, the scanned modules/artifacts, and the
dependency packages that fed the auxclasspath:

```yaml
- tool: assets.mark
  args:
    asset: repo:example.com/example-app
    status: scanned
    evidence: "spotbugs 4.8.6 + findsecbugs 1.13.0, effort:max, threshold:low"

- tool: assets.mark
  args:
    asset: "module:example-app/target/classes"
    status: scanned
    evidence: "fsb-out/fsb.sarif, 37 results, 0 missing classes"

- tool: assets.mark
  args:
    asset: "package:maven/org.apache.commons/commons-collections4@4.4"
    status: observed
    evidence: "on auxclasspath; relevant to OBJECT_DESERIALIZATION gadget analysis"
```

Mark a module `partial` if stderr reported missing classes (degraded taint
accuracy) and note the missing-class list in evidence.

## Reporting: findings.report

File **verified** issues only, after source-level confirmation, via the
`finding-report` skill's pack. Example call:

```yaml
- tool: findings.report
  args:
    title: "SQL injection in UserDao.findByName via 'name' request parameter"
    severity: high
    cwe: CWE-89
    asset: repo:example.com/example-app
    location: "src/main/java/com/example/app/UserDao.java:42"
    tool: "spotbugs+findsecbugs"
    rule: SQL_INJECTION_JDBC
    evidence: |
      req.getParameter("u") concatenated into the query string at
      UserDao.java:38-42 and passed to Statement.executeQuery.
      Confirmed reachable from GET /users?u= (UserController.java:27).
      findsecbugs rank 4, priority 1 (High confidence).
    recommendation: "Use PreparedStatement with bound parameters."
```

## SARIF handoff

Route `fsb-out/fsb.sarif` to the `sarif-triage` skill to merge/dedup with
SARIF from semgrep (`p/java`) and CodeQL (`java-security-extended`) runs over
the same repository. Keep the native XML alongside — it is the source of
rank/priority/CWE that generic SARIF triage lacks; the work units already
carry those fields in `hints`.
