# code-review — rupu wiring

How the umbrella skill's artifacts plug into rupu: the `for_each:` workflow over
the work-unit array, the lead `dispatch` fan-out, and the `assets.mark` /
`findings.report` calls for repo/files/packages.

## Work-unit contract

Both `scripts/plan_review.py` (Phase 0 plan) and the `work-units` skill
(Phase 5 final inventory) write a file whose entire content is ONE clean
top-level JSON array — rupu's `for_each:` JSON-parses any value that starts
with `[`, so there must be no wrapper object, no comments, no trailing text:

```json
[
  {
    "id": "cr-001",
    "title": "Run semgrep SAST over /work/app",
    "targets": ["/work/app"],
    "hints": {"skill": "semgrep", "phase": "1-sast", "severity": "info"}
  },
  {
    "id": "wu-042",
    "title": "SQLi candidate in app/api/orders.py",
    "targets": ["app/api/orders.py:88"],
    "hints": {"rule": "python.django.security.injection.sql", "severity": "high",
              "cwe": "CWE-89", "tool": "semgrep"}
  }
]
```

## Workflow: read_file + for_each

Phase 0 plan fan-out (each unit names the sub-skill to load in `hints.skill`):

```yaml
steps:
  - id: load_plan
    tool: read_file
    args:
      path: out/plan.json

  - id: run_phase
    for_each: "{{ load_plan.output }}"
    steps:
      - tool: agent
        args:
          prompt: |
            Load the `{{ item.hints.skill }}` skill. Execute work unit
            {{ item.id }}: {{ item.title }}. Targets: {{ item.targets }}.
            Emit SARIF/native JSON into out/, then load the `sarif-triage`
            skill to normalize it and the `work-units` skill to split the
            normalized findings into work units.
```

Phase 5 verification fan-out over the final inventory:

```yaml
steps:
  - id: load_units
    tool: read_file
    args:
      path: out/work-units.json

  - id: verify
    for_each: "{{ load_units.output }}"
    steps:
      - tool: agent
        args:
          prompt: |
            Verify candidate {{ item.id }} ({{ item.hints.rule }},
            {{ item.hints.severity }}, {{ item.hints.cwe }}) at
            {{ item.targets }}. Open the source, confirm the source->sink
            path or vulnerable config, build a PoC input where practical.
            If real: load the `finding-report` skill to file each verified
            issue via findings.report. If false positive: record a one-line
            discard reason.
```

## Lead dispatch fan-out

A lead agent reading `out/work-units.json` fans out one worker per unit (or per
batch of ~10 units for small findings):

```
dispatch(
  task=f"Load the code-review skill, then the sub-skill in hints.skill. "
       f"Work unit: {json.dumps(unit)}. Verify against the source at "
       f"{unit['targets']} and file via the finding-report skill if real.",
  label=unit["id"],
)
```

Batch variant: group units by `hints.rule` or by top-level directory of
`targets[0]` so one worker holds the whole module's context.

## assets.mark — coverage for repo, files, packages

Mark the repo as soon as Phase 0 completes:

```
assets.mark(asset_type="repository", identifier="git.example.com/example/app",
            status="in-review",
            notes="code-review umbrella: profiled; 4 languages, 6 manifests")
```

Mark modules/files as each phase covers them (scanned-clean is still coverage):

```
assets.mark(asset_type="file", identifier="git.example.com/example/app:app/api/orders.py",
            status="scanned",
            notes="semgrep+bandit+codeql clean except wu-042 (verified SQLi)")
```

Mark every dependency package from the syft SBOM (`components[].purl`):

```
assets.mark(asset_type="package", identifier="pkg:pypi/django@3.2.4",
            status="scanned",
            notes="grype: GHSA-xxxx (high) — reachable, see finding CR-07; osv: match")
```

A small loop over the SBOM:

```python
import json
sbom = json.load(open("out/native/sbom.cdx.json"))
for c in sbom.get("components", []):
    assets.mark(asset_type="package", identifier=c.get("purl", c["name"]),
                status="scanned", notes="SBOM via syft; scanned by grype+osv-scanner")
```

## findings.report — shape for this skill's output

File every verified issue through the `finding-report` skill, which wraps
`findings.report`. The fields this pack always carries:

```
findings.report(
  title="SQL injection in order lookup (app/api/orders.py:88)",
  severity="high",                      # from sarif-triage normalized rank
  asset="git.example.com/example/app",
  location="app/api/orders.py:88",
  cwe="CWE-89",
  evidence="source: request.args['order_id'] (orders.py:71) -> fmt into query "
           "string (orders.py:86) -> cursor.execute(q) (orders.py:88); no "
           "parameterization, no sanitizer. PoC: GET /api/orders?order_id=1%20OR%201=1--",
  remediation="Use parameterized query: cursor.execute('SELECT ... WHERE id=%s', [order_id])",
  tool="semgrep+manual",
  rule="python.django.security.injection.sql",
)
```

Verified trufflehog secrets (Phase 2) skip the queue — report immediately:

```
findings.report(
  title="Live AWS access key in git history (commit 3f2a91c, config/prod.env)",
  severity="critical",
  asset="git.example.com/example/app",
  location="config/prod.env:3 @ 3f2a91c",
  cwe="CWE-798",
  evidence="trufflehog detector=AWS Verified=true; key AKIA... validated against STS",
  remediation="Revoke key, rotate, purge from history, add gitleaks pre-commit hook",
  tool="trufflehog",
)
```

## Pipeline summary

```
profile_repo.py -> repo-profile.json ─┐
plan_review.py  -> plan.json ─────────┤ for_each / dispatch (phase runs)
tools           -> out/sarif, out/native
sarif-triage    -> normalized findings
work-units      -> out/work-units.json ─ for_each / dispatch (verification)
verified        -> finding-report (findings.report)
coverage        -> assets.mark (repo, files, packages)
```

— vulture (hazel-chapel)
