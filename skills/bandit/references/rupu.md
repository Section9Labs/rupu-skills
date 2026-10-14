# rupu wiring for the bandit skill

How Bandit output plugs into rupu: coverage assets, the work-unit array,
the `for_each:` workflow, `dispatch` fan-out, and `findings.report`.

## Asset model & coverage

Code-review assets are: the **repository**, the **files/modules scanned**,
and the **dependency packages**. Mark them as you touch them so coverage
is trackable. Bandit's native JSON `metrics` block lists every scanned
file — mark those; `_totals.loc` gives size context.

```yaml
# repository
- tool: assets.mark
  args:
    asset: "repo:example.com/example-app"
    kind: repository
    status: scanned
    note: "bandit 1.7.x, -r src/ -x tests; see out/bandit.json metrics"

# per-module (one call per file from metrics, scripted)
- tool: assets.mark
  args:
    asset: "repo:example.com/example-app:src/jobs/runner.py"
    kind: file
    status: scanned
    note: "bandit: 2 findings (B602, B607)"

# dependency packages (from requirements/lockfile — Bandit does not scan
# these; mark them pending for the SCA pass)
- tool: assets.mark
  args:
    asset: "pkg:pypi/pyyaml@5.3.1"
    kind: dependency
    status: pending
    note: "found in requirements.txt; route to SCA"
```

## Work-unit file

`scripts/run_bandit.py <repo> -o out/` (or
`scripts/bandit_to_workunits.py bandit.json -o out/workunits.json`)
writes a CLEAN top-level JSON array — rupu's `for_each:` JSON-parses any
value that starts with `[`, so nothing may precede the bracket:

```json
[
  {
    "id": "bandit-B602-src_jobs_runner_py",
    "title": "B602 subprocess_popen_with_shell_equals_true in src/jobs/runner.py (1 hit, max sev HIGH)",
    "targets": ["src/jobs/runner.py:42"],
    "hints": {
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true",
      "severity": "HIGH",
      "confidence": "HIGH",
      "cwe": "CWE-78",
      "issue_text": "subprocess call with shell=True identified, security issue.",
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html"
    }
  }
]
```

Load the `work-units` skill to split/normalize this array — do not
re-invent the splitter.

## Workflow: read_file + for_each

```yaml
steps:
  - id: scan
    run: python3 skills/bandit/scripts/run_bandit.py /work/example-app -o /work/out

  - id: load_units
    tool: read_file
    args:
      path: /work/out/workunits.json

  - id: verify_each
    for_each: "{{ steps.load_units.output }}"   # parsed as JSON array
    as: unit
    prompt: |
      Load the `work-units` skill. You are verifying Bandit work unit
      {{ unit.id }}: {{ unit.title }}.
      Open each target in {{ unit.targets }} ({{ unit.hints.test_id }},
      severity {{ unit.hints.severity }}, {{ unit.hints.cwe }}).
      Trace whether attacker-controlled input reaches the flagged sink;
      consult skills/bandit/references/tests.md for the exploitation
      pattern for {{ unit.hints.test_id }}. Build a PoC where reachable.
      Load the `finding-report` skill and file each verified issue with
      findings.report; mark the file asset reviewed with assets.mark.
```

## Lead-agent fan-out with dispatch

```yaml
  - id: fanout
    for_each: "{{ steps.load_units.output }}"
    as: unit
    tool: dispatch
    args:
      agent: code-reviewer
      input: |
        Bandit work unit {{ unit.id }} — {{ unit.title }}.
        Targets: {{ unit.targets }}. Hints: {{ unit.hints }}.
        Verify exploitability, PoC it, then load `finding-report` and
        file via findings.report. SARIF context: /work/out/bandit.sarif
        (merge/dedupe through the `sarif-triage` skill).
```

Batching tip: units are grouped per (test_id, file) by the parser, so one
dispatch == one coherent review task. For very large repos, pre-filter
the array (`jq`-style, or `--min-severity HIGH` on the parser) before
fan-out.

## Filing findings

```yaml
- tool: findings.report
  args:
    title: "Command injection via shell=True subprocess in job runner"
    severity: high
    asset: "repo:example.com/example-app:src/jobs/runner.py"
    cwe: "CWE-78"
    evidence: |
      src/jobs/runner.py:42 — subprocess.Popen(f"convert {user_filename} out.png", shell=True)
      user_filename originates from POST /api/jobs (src/api/jobs.py:31)
      with no sanitization. PoC filename: `x.png; id > /tmp/pwn #`
      produced command execution in the local harness.
    tool_ref: "bandit B602 (HIGH/HIGH), work unit bandit-B602-src_jobs_runner_py"
    recommendation: "subprocess.run([...]) list form without shell; shlex.quote at minimum."
```

Only file **verified** issues through `findings.report`; raw Bandit hits
stay as work units. Route `out/bandit.sarif` to the `sarif-triage` skill
so Bandit results merge with semgrep/codeql SARIF for cross-tool dedupe.

— vulture (amber-cavern)
