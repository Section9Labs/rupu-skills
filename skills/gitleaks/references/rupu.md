# rupu wiring for gitleaks output

This file shows how to plug gitleaks results into the rupu fleet: normalize →
coverage → fan-out → report. Do not hand-roll the splitter or report format:
**load the `work-units` skill** for splitting and the **`finding-report`
skill** for filing issues.

## 1. Produce the work-unit array

```sh
python3 scripts/run_gitleaks.py --mode git /tmp/app.git --out-dir out/
# or, from existing reports:
python3 scripts/gitleaks_to_workunits.py out/gitleaks.json out/gitleaks.sarif -o out/workunits.json
```

`out/workunits.json` is a CLEAN top-level JSON array (rupu's `for_each:`
JSON-parses any value starting with `[`):

```json
[
  {
    "id": "gitleaks-0001-aws-access-token",
    "title": "aws-access-token in config/prod.env:12",
    "targets": ["config/prod.env:12"],
    "hints": {
      "rule": "aws-access-token",
      "severity": "high",
      "commit": "203f1e2ab9c...",
      "author": "dev@example.com",
      "entropy": "4.73",
      "redacted_match": "AKIA****************",
      "cwe": "CWE-798"
    }
  }
]
```

## 2. Mark coverage with `assets.mark`

The code-review asset model: the repository, the files/modules scanned, the
dependency packages. Mark what gitleaks covered:

```
assets.mark {"asset": "repo:https://example.com/org/app.git",
             "kind": "repository", "status": "scanned",
             "by": "gitleaks", "detail": "full history --all, 1842 commits"}
assets.mark {"asset": "repo:app/config/", "kind": "module",
             "status": "scanned", "by": "gitleaks"}
assets.mark {"asset": "repo:app@worktree", "kind": "files",
             "status": "scanned", "by": "gitleaks dir"}
```

Mark skipped assets too (e.g. blobs excluded by `--max-target-megabytes`)
with `"status": "skipped"` so coverage gaps are visible.

## 3. rupu workflow: `read_file` + `for_each:`

```yaml
steps:
  - id: scan
    run: python3 skills/gitleaks/scripts/run_gitleaks.py --mode git /tmp/app.git --out-dir out/

  - id: load_units
    tool: read_file
    args:
      path: out/workunits.json

  - id: triage_each
    for_each: "{{ steps.load_units.output }}"   # top-level JSON array -> iterated
    as: unit
    steps:
      - id: verify
        agent: secret-triage
        prompt: |
          Load the `work-units` skill. Work unit: {{ unit }}.
          Recover the secret from history (git show {{ unit.hints.commit }}:<file>),
          decide real vs placeholder, then load the `trufflehog` skill to
          live-verify the credential. If verified or plainly sensitive,
          load the `finding-report` skill and file it with findings.report.
```

## 4. Lead-agent `dispatch` fan-out

```
units = json.parse(read_file("out/workunits.json"))
for unit in units:
    dispatch(agent="secret-triage",
             input={"workunit": unit, "repo": "/tmp/app.git"},
             brief="Load the work-units skill to interpret the unit; verify the "
                   "secret (trufflehog skill); file via the finding-report skill.")
```

Prioritize dispatch order: provider rules and private keys first, then
`generic-api-key` by `hints.entropy` descending (the parser already sorts).

## 5. File verified issues with `findings.report`

Use the **`finding-report`** skill's pack; a typical call for a gitleaks hit:

```
findings.report {
  "title": "Live AWS access key committed to git history",
  "severity": "critical",
  "asset": "repo:https://example.com/org/app.git",
  "location": "config/prod.env:12 @ 203f1e2a",
  "cwe": "CWE-798",
  "evidence": "gitleaks rule aws-access-token, entropy 4.73; verified live via trufflehog AWS detector (GetCallerIdentity ok); key AKIA****************",
  "impact": "Key grants s3:* and iam:PassRole in account 198.51.100.0-prod; removed from HEAD in a later commit but recoverable from any clone.",
  "remediation": "Rotate the key, audit CloudTrail from commit date, purge history (git filter-repo) after rotation."
}
```

File one finding per distinct secret (dedupe multiple commits of the same
value — the parser's `id` is stable per rule+file+line+commit; collapse by
`redacted_match` when reporting).
