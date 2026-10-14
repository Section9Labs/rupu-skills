# rupu wiring for taint-analysis

How this skill's output plugs into rupu: coverage marking, work-unit fan-out,
and finding reports.

## 1. Produce the work-unit array

```
python3 skills/taint-analysis/scripts/sink_hunt.py /work/example.com-app -o /work/out/sink_units.json
```

`sink_units.json` is a **clean top-level JSON array** (starts with `[`), so
rupu's `for_each:` JSON-parses it directly:

```json
[
  {
    "id": "taint-sql-injection-9f2c41ab07",
    "title": "Trace sql-injection sink candidate(s) in app/search/views.py (3 hits)",
    "targets": ["app/search/views.py:42", "app/search/views.py:87", "app/search/views.py:103"],
    "hints": {
      "vuln_class": "sql-injection",
      "sink": "execute() with f-string query",
      "language": "python",
      "snippet": "cur.execute(f\"SELECT id,name FROM products WHERE name LIKE '%{q}%'\")"
    }
  }
]
```

If units need re-chunking, merging, or prioritization before fan-out, load the
**`work-units`** skill — it is the shared splitter; do not re-implement it.

## 2. Mark the assets (coverage)

Mark the repo, the scanned module groups, and dependency manifests up front;
mark units `reviewed` as agents clear them.

```
assets.mark asset="repo:example.com-app@a1b2c3d" kind="repository" status="scanning" note="taint-analysis sink hunt started"
assets.mark asset="repo:example.com-app:app/search/" kind="module" status="in-review" note="3 sql-injection sink candidates (taint-sql-injection-9f2c41ab07)"
assets.mark asset="repo:example.com-app:requirements.txt" kind="dependency-manifest" status="recorded" note="handed to SCA skills"
assets.mark asset="repo:example.com-app:app/search/" kind="module" status="reviewed" note="1 verified SQLi, 2 refuted (parameterized)"
```

## 3. Workflow: `read_file` + `for_each:` over the array

```yaml
workflow:
  name: taint-sink-triage
  steps:
    - id: hunt
      run: python3 skills/taint-analysis/scripts/sink_hunt.py /work/example.com-app -o /work/out/sink_units.json

    - id: load_units
      tool: read_file
      args:
        path: /work/out/sink_units.json

    # load_units output starts with '[' -> rupu JSON-parses it into items
    - id: trace_each
      for_each: ${{ steps.load_units.output }}
      as: unit
      prompt: |
        Load the `taint-analysis` skill. You are tracing work unit
        ${{ unit.id }}: ${{ unit.title }}.
        Candidate class: ${{ unit.hints.vuln_class }} via ${{ unit.hints.sink }}
        (${{ unit.hints.language }}).
        For each target in ${{ unit.targets }}:
          1. Run: python3 skills/taint-analysis/scripts/trace_context.py <target> --function
          2. Trace the dangerous argument backwards to a source (follow callers
             with rg); or declare dead-end at a constant.
          3. Judge sanitizers on the path per the class playbook
             (references/classes.md), check all branches and callers.
          4. Confirm reachability + write the concrete attack value.
          5. If confirmed, write a semgrep taint rule (load `semgrep` skill)
             or CodeQL query (load `codeql` skill) to find siblings; add any
             new hits to your unit.
        Verified flows: load the `finding-report` skill and file each with
        findings.report (hop chain, attack value, fix).
        Then mark the file reviewed with assets.mark.
```

## 4. Lead-agent `dispatch` fan-out

```yaml
    - id: fanout
      tool: dispatch
      for_each: ${{ steps.load_units.output }}
      as: unit
      args:
        agent: code-review-tracer
        task_id: ${{ unit.id }}
        instructions: |
          Load `taint-analysis`. Trace unit ${{ unit.id }} (${{ unit.hints.vuln_class }})
          targets: ${{ unit.targets }}. Verify or refute the source->sink flow.
          File verified flows via the `finding-report` skill; mark coverage via assets.mark.
        context:
          repo: /work/example.com-app
          unit: ${{ unit }}
```

Dispatch grouping tip: units are already one-per (file, class); for very large
repos, pre-group by `hints.vuln_class` so one agent handles all SQLi units
(shared mental model) — the `work-units` skill does this split.

## 5. Filing verified findings

Use the **`finding-report`** skill's conventions; the raw call looks like:

```
findings.report \
  title="SQL injection in product search (app/search/views.py:42)" \
  severity="critical" \
  asset="repo:example.com-app:app/search/views.py" \
  cwe="CWE-89" \
  evidence="request.args['q'] -> q (views.py:40) -> f-string query (views.py:42) -> cur.execute. No sanitizer on path; int()/parameterization absent. Attack value: q = %' UNION SELECT username,password FROM users--. Verified by semgrep taint rule flask-request-to-sql-execute (2 sibling hits: views.py:87, admin/reports.py:31)." \
  recommendation="Parameterize: cur.execute(\"... LIKE %s\", (f\"%{q}%\",)); allowlist ORDER BY identifiers." \
  references="skills/taint-analysis/references/classes.md#sql-injection"
```

Refuted candidates are not findings — record them as coverage notes on the
asset (`assets.mark ... note="refuted: parameterized at call site"`), so the
next pass doesn't re-trace them.

— vulture (apricot-cove)
