# rupu wiring for trufflehog output

Normalize → coverage → fan-out → report. Do not hand-roll the splitter or
report format: **load the `work-units` skill** for splitting and the
**`finding-report` skill** for filing issues.

## 1. Produce the work-unit array

```sh
python3 scripts/run_trufflehog.py git file:///tmp/app.git --out-dir out/
# or from existing JSONL:
python3 scripts/trufflehog_to_workunits.py out/trufflehog.jsonl -o out/workunits.json
```

`out/workunits.json` is a CLEAN top-level JSON array (rupu's `for_each:`
JSON-parses any value starting with `[`), verified findings first:

```json
[
  {
    "id": "trufflehog-9a1b2c3d4e5f",
    "title": "[VERIFIED] AWS in config/prod.env:12",
    "targets": ["config/prod.env:12"],
    "hints": {
      "detector": "AWS",
      "verified": "true",
      "severity": "critical",
      "commit": "203f1e2ab9c...",
      "redacted": "AKIA****************",
      "extra": "account=123456789012 arn=arn:aws:iam::123456789012:user/deploy",
      "cwe": "CWE-798"
    }
  }
]
```

## 2. Mark coverage with `assets.mark`

The code-review asset model: the repository, the files/modules scanned, the
dependency packages. Mark what trufflehog covered — one call per asset:

```
assets.mark {"asset": "repo:https://example.com/org/app.git",
             "kind": "repository", "status": "scanned",
             "by": "trufflehog git", "detail": "all refs, results=verified,unknown"}
assets.mark {"asset": "github-org:example", "kind": "repository-group",
             "status": "scanned", "by": "trufflehog github",
             "detail": "42 repos incl. issue/PR comments"}
assets.mark {"asset": "s3://example-backups", "kind": "bucket",
             "status": "scanned", "by": "trufflehog s3"}
```

Mark exclusions (`--exclude-paths`, skipped repos) with
`"status": "skipped"` so coverage gaps stay visible.

## 3. rupu workflow: `read_file` + `for_each:`

```yaml
steps:
  - id: scan
    run: >
      python3 skills/trufflehog/scripts/run_trufflehog.py
      git file:///tmp/app.git --out-dir out/ --results verified,unknown

  - id: load_units
    tool: read_file
    args:
      path: out/workunits.json

  - id: triage_each
    for_each: "{{ steps.load_units.output }}"   # clean top-level array -> iterated
    as: unit
    steps:
      - id: handle
        agent: secret-triage
        prompt: |
          Load the `work-units` skill. Work unit: {{ unit }}.
          If hints.verified == "true": load the `finding-report` skill and file
          it with findings.report, quoting hints.extra as blast radius.
          If hints.verified == "unknown": re-verify (rerun the single detector
          or exercise the credential per the trufflehog skill's
          references/verification.md), then file if live.
          Cross-reference the gitleaks skill's work units for the same path:line.
```

## 4. Lead-agent `dispatch` fan-out

```
units = json.parse(read_file("out/workunits.json"))
for unit in units:                       # already sorted verified-first
    dispatch(agent="secret-triage",
             input={"workunit": unit, "repo": "file:///tmp/app.git"},
             brief="Load the work-units skill to interpret the unit; "
                   "verified units go straight to the finding-report skill; "
                   "unknowns get re-verified first.")
```

## 5. File verified issues with `findings.report`

Use the **`finding-report`** skill's pack; a typical call:

```
findings.report {
  "title": "Live GitHub PAT with repo+admin:org scope in CI config",
  "severity": "critical",
  "asset": "repo:https://example.com/org/app.git",
  "location": ".github/workflows/deploy.yml:31 @ 203f1e2a",
  "cwe": "CWE-798",
  "evidence": "trufflehog detector Github, Verified=true; ExtraData: login=ci-bot, scopes=repo,admin:org; token ghp_****************",
  "impact": "Token grants write to all 42 org repos and org administration; present in history since 2024-03-02.",
  "remediation": "Revoke the PAT, replace with GitHub App or OIDC workload identity, audit org audit-log since commit date."
}
```

Severity ladder: `verified` + write/admin scope → critical; `verified`
read-only → high; `unknown` → high until re-verified; `unverified`
high-value detector → medium (leak path finding, credential-rotation
evidence). One finding per distinct credential — collapse multiple commits
of the same `redacted` value into a single report with the earliest commit
as introduction date.
