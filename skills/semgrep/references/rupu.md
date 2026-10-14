# rupu wiring for the semgrep skill

How Semgrep output plugs into the rupu fleet: work-unit file, workflow
consumption, dispatch fan-out, coverage marking, and finding reports.

## 1. Produce the work-unit array

```bash
python3 scripts/run_semgrep.py \
  --config p/security-audit --config p/secrets --config ./rules \
  --repo /work/example.com-app \
  --sarif semgrep.sarif --out workunits.json
```

`workunits.json` is a CLEAN top-level JSON array (rupu's `for_each:`
JSON-parses any value starting with `[`):

```json
[
  {
    "id": "semgrep-0001",
    "title": "taint-flask-sqli-concat in app/views/search.py (3 hits)",
    "targets": ["app/views/search.py:42", "app/views/search.py:77", "app/views/search.py:91"],
    "hints": {
      "rule": "taint-flask-sqli-concat",
      "severity": "error",
      "cwe": "CWE-89: SQL Injection",
      "owasp": "A03:2021 - Injection",
      "message": "User-controlled value flows into a dynamically-built SQL string..."
    }
  }
]
```

Load the `work-units` skill — it is the shared splitter; do not re-implement
grouping/splitting logic beyond what the parser script already does.

## 2. Workflow: read_file + for_each

```yaml
steps:
  - id: load-units
    tool: read_file
    args:
      path: workunits.json

  - id: review-unit
    for_each: "{{ steps.load-units.output }}"   # parses the JSON array
    prompt: |
      You are reviewing one Semgrep finding group in /work/example.com-app.
      Rule: {{ item.hints.rule }} (severity {{ item.hints.severity }},
      {{ item.hints.cwe }}). Semgrep says: {{ item.hints.message }}
      Open each target location, trace the dataflow (sources, sanitizers,
      sink), and decide exploitable / not. Targets:
      {{ item.targets }}
      If verified, load the `finding-report` skill and file it with
      findings.report. Either way, mark the reviewed file(s) with assets.mark.
```

## 3. Lead-agent fan-out with dispatch

```yaml
  - id: fan-out
    for_each: "{{ steps.load-units.output }}"
    tool: dispatch
    args:
      agent: code-reviewer
      task: |
        Verify Semgrep work unit {{ item.id }}: {{ item.title }}.
        Targets: {{ item.targets }}. Hints: {{ item.hints }}.
        Report verified issues via the `finding-report` skill; mark coverage
        with assets.mark when done.
```

Batch large arrays (e.g. chunks of 10 units per dispatch) when the unit count
exceeds the crew size; the `work-units` skill documents the chunking pattern.

## 4. Coverage: assets.mark

Asset model for code review: the repository, the files/modules scanned, and
the dependency packages. Mark the repo and scan surface right after the scan;
mark individual files as agents finish reviewing their units.

```json
{"tool": "assets.mark", "args": {
  "asset": "repo:example.com-app@a1b2c3d",
  "kind": "repository",
  "status": "scanned",
  "note": "semgrep 1.x, configs: p/security-audit,p/secrets,./rules; 412 files scanned, 37 findings — vulture"
}}
```

```json
{"tool": "assets.mark", "args": {
  "asset": "repo:example.com-app@a1b2c3d:app/views/search.py",
  "kind": "file",
  "status": "reviewed",
  "note": "semgrep unit semgrep-0001 triaged: 2 TP, 1 FP — vulture"
}}
```

```json
{"tool": "assets.mark", "args": {
  "asset": "pkg:pypi/flask@2.0.1",
  "kind": "dependency",
  "status": "inventoried",
  "note": "from requirements.txt of example.com-app; SCA handled separately — vulture"
}}
```

The scanned-file list comes from `semgrep --json` (`paths.scanned`) or
`--verbose` output; `run_semgrep.py --list-scanned` emits it alongside the
work units for bulk marking.

## 5. Verified issues: findings.report

Load the `finding-report` skill for the full reporting pack. Example call for
a verified Semgrep taint finding:

```json
{"tool": "findings.report", "args": {
  "title": "SQL injection in search endpoint (user input concatenated into query)",
  "severity": "high",
  "asset": "repo:example.com-app@a1b2c3d:app/views/search.py",
  "location": "app/views/search.py:42-44",
  "cwe": "CWE-89",
  "evidence": "flask.request.args.get('n') -> q = \"SELECT ... '\" + n + \"'\" -> cur.execute(q); semgrep rule taint-flask-sqli-concat, dataflow trace confirmed by manual read; PoC: /search?n=' OR '1'='1",
  "recommendation": "Parameterize: cur.execute(\"SELECT ... WHERE n=%s\", (n,))",
  "reporter": "vulture"
}}
```

## 6. Cross-tool normalization

When this repo is also scanned by other SARIF-emitting tools (CodeQL, bandit,
gosec...), do NOT merge by hand: feed all SARIF files to the `sarif-triage`
skill for normalization and dedupe, then split the merged result with the
`work-units` skill as above.
