# rupu wiring for njsscan output

How to plug this skill's artifacts (`workunits.json`, `njsscan.sarif`) into
rupu workflows, coverage tracking, and reporting.

## 1. Work-unit contract

`scripts/njsscan_to_workunits.py` (and `scripts/run_njsscan.py`, which calls
it) writes a **clean top-level JSON array** — rupu's `for_each:` JSON-parses
any value that starts with `[`, so no wrapper object, no comments:

```json
[
  {
    "id": "njsscan-a1b2c3d4",
    "title": "node_sqli_injection in routes/user.js",
    "targets": ["routes/user.js:42", "routes/user.js:44"],
    "hints": {
      "rule": "node_sqli_injection",
      "severity": "ERROR",
      "cwe": "CWE-89",
      "owasp": "A1: Injection",
      "description": "Untrusted user input in a raw SQL query...",
      "tool": "njsscan"
    }
  }
]
```

One unit per (rule, file); `targets` carries every matched `path:line`.

## 2. Workflow: `read_file` + `for_each:`

```yaml
steps:
  - id: scan
    run: python3 skills/njsscan/scripts/run_njsscan.py ${repo_path} --missing-controls -o out/

  - id: load_units
    tool: read_file
    args:
      path: out/workunits.json

  - id: verify_each
    for_each: ${load_units.output}        # parses because the file is a clean JSON array
    as: unit
    steps:
      - prompt: |
          Load the `work-units` skill conventions. Verify work unit
          ${unit.id} (${unit.title}): open each target in ${unit.targets},
          trace the input of the matched sink back to a request/file/env
          source, and decide exploitability. Rule ${unit.hints.rule},
          severity ${unit.hints.severity}, ${unit.hints.cwe}.
          If verified, load the `finding-report` skill and file it with
          findings.report. If a false positive, record why.
```

## 3. Lead-agent fan-out with `dispatch`

```yaml
  - id: fan_out
    for_each: ${load_units.output}
    as: unit
    tool: dispatch
    args:
      task: >
        Verify njsscan finding ${unit.id} — ${unit.title}.
        Targets: ${unit.targets}. Hints: ${unit.hints}.
        Use the `work-units` skill for intake, the `taint-analysis` skill
        (javascript sinks) for dataflow confirmation, and the
        `finding-report` skill to file verified issues.
```

Batching tip: for large runs, have the lead group units by `hints.rule` and
dispatch one worker per rule family (all SQLi units to one worker, all
secrets to another) to amortize context.

## 4. Coverage: `assets.mark`

Mark the repo, the scanned modules, and the dependency packages so coverage
is trackable:

```yaml
- tool: assets.mark
  args:
    asset: repo:example.com/payments-api
    status: scanned
    detail: "njsscan 0.4.x --missing-controls; 143 js files, 12 templates"

- tool: assets.mark
  args:
    asset: module:payments-api/routes/user.js
    status: findings
    detail: "node_sqli_injection ERROR x2"

# files listed in njsscan.json errors[] were NOT analyzed — mark the gap:
- tool: assets.mark
  args:
    asset: module:payments-api/public/bundle.min.js
    status: skipped
    detail: "njsscan parse error — cover via eslint-plugin-security/codeql"

# dependency packages (from package-lock.json) — njsscan does not do SCA:
- tool: assets.mark
  args:
    asset: pkg:npm/node-serialize@0.0.4
    status: needs-review
    detail: "used at routes/profile.js:17; unserialize() sink confirmed by njsscan node_deserialize"
```

## 5. Reporting: `findings.report`

Only after verification (source→sink traced, reachability confirmed). Load
the `finding-report` skill for the full pack; shape of the call:

```yaml
- tool: findings.report
  args:
    title: "SQL injection in GET /users/:id (routes/user.js:42)"
    severity: high
    asset: repo:example.com/payments-api
    location: "routes/user.js:42"
    cwe: CWE-89
    evidence: |
      db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
      req.params.id flows unmodified from the route into the template
      literal. Verified: id=1 OR 1=1 returns all rows in local run.
    tool: "njsscan node_sqli_injection (ERROR)"
    recommendation: "Parameterized query: db.query('SELECT * FROM users WHERE id = ?', [id])"
```

## 6. SARIF handoff

Pass `out/njsscan.sarif` (and `eslint.sarif` if the eslint pass ran) to the
`sarif-triage` skill. It owns cross-tool dedup; do not merge SARIF here.
Keep the native JSON (`out/njsscan.json`) as the evidence artifact — it has
`match_string` snippets SARIF lacks.
