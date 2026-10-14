---
name: sarif-triage
description: Normalize, deduplicate, and triage SARIF 2.1.0 and native-JSON output from any SAST/SCA/secret scanner (semgrep, CodeQL, gosec, bandit, njsscan, brakeman, gitleaks, trivy, npm audit) into one unified, prioritized, rupu-ingestible set of work units and findings; use after every scanner run to turn raw results into fan-out work and filed findings.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# SARIF Triage — turn any scanner output into action

This is the shared "scanner output → action" technique. Every tool skill
(semgrep, CodeQL, gosec, bandit, njsscan, brakeman, gitleaks, trivy, SCA
auditors) routes its raw output here. The pipeline is three composable
stdlib-only scripts:

```
raw SARIF / native JSON
  └─ scripts/normalize_sarif.py   → normalized findings JSON list
       └─ scripts/dedupe_findings.py → unique, corroborated, scored findings
            └─ scripts/to_workunits.py → CLEAN top-level JSON array of work units
```

One-liner that chains all three:

```bash
python3 scripts/normalize_sarif.py semgrep.sarif codeql.sarif gitleaks.sarif \
  | python3 scripts/dedupe_findings.py \
  | python3 scripts/to_workunits.py --min-severity low -o workunits.json
```

Each script reads the previous stage's JSON on stdin or from a path and
writes JSON to stdout or `-o FILE`, so you can also run stages separately and
inspect intermediates. Progress counts go to stderr, never stdout.

## 1. Collect scanner output

Prefer SARIF from every tool — it is the lingua franca:

- `semgrep scan --config auto --sarif -o semgrep.sarif .`
- `codeql database analyze db codeql/python-queries --format=sarif-latest -o codeql.sarif`
- `gosec -fmt sarif -out gosec.sarif ./...`
- `bandit -r . -f sarif -o bandit.sarif` (or `-f json` — native is handled too)
- `njsscan --sarif -o njsscan.sarif .`
- `brakeman -o brakeman.sarif`
- `gitleaks detect --report-format sarif --report-path gitleaks.sarif`

Native JSON is also accepted and autodetected: semgrep `--json`, bandit
`-f json`, gosec `-fmt json`, gitleaks `--report-format json`, trivy
`-f json`, `npm audit --json`. Force detection with `--format` and tag the
source with `--tool` when a wrapper renames the driver:

```bash
python3 scripts/normalize_sarif.py bandit-out.json --format bandit --tool bandit
```

## 2. SARIF 2.1.0 — the fields that matter

You only need a small slice of the spec (full paths + per-tool examples in
`references/sarif-fields.md`):

- `runs[].tool.driver.name` — which tool produced the run.
- `runs[].tool.driver.rules[]` — rule catalog: `id`,
  `shortDescription.text` (title), `defaultConfiguration.level` (fallback
  level), `properties.cwe` / `properties.tags` (CWE lives here —
  CodeQL uses tags like `external/cwe/cwe-089`),
  `properties["security-severity"]` (CVSS-like 0–10 string).
- `runs[].results[]` — the findings: `ruleId` (+ `ruleIndex` fallback),
  `level` (error/warning/note/none), `message.text`,
  `locations[0].physicalLocation.artifactLocation.uri` +
  `.region.startLine`/`.startColumn`,
  `partialFingerprints` (stable dedup keys, e.g.
  `primaryLocationLineHash`), and `codeFlows[].threadFlows[].locations[]` —
  the taint path from source to sink (CodeQL path queries, semgrep
  taint mode emit these).

Tool quirks: semgrep puts `security-severity` and CWE in rule properties;
CodeQL puts severity on rules only (results carry just `level`) and CWE in
tags; gosec/bandit/njsscan/brakeman emit plain level-based SARIF; gitleaks
SARIF has no CWE (normalize to CWE-798, severity high — a secret is a
secret).

## 3. Normalize — one record shape for everything

`normalize_sarif.py` emits:

```json
{"tool": "semgrep", "rule_id": "python.lang.security.sqli", "title": "...",
 "file": "app/db.py", "line": 42, "severity": "high", "cwe": "CWE-89",
 "message": "...", "fingerprint": "ab12cd34ef567890",
 "code_flow": ["app/views.py:10 -- source: request.args", "app/db.py:42 -- sink"]}
```

Severity resolution order (full per-tool tables in
`references/severity-map.md`):

1. `properties["security-severity"]` (CVSS-like): ≥9.0 critical, ≥7.0 high,
   ≥4.0 medium, >0 low.
2. SARIF `level`: error→high, warning→medium, note→low, none→info.
3. Tool-native strings: bandit/gosec HIGH/MEDIUM/LOW → high/medium/low;
   semgrep ERROR/WARNING/INFO → high/medium/info; npm moderate→medium;
   trivy CRITICAL→critical; brakeman confidence High/Medium/Weak →
   high/medium/low.

Fingerprint: prefer SARIF `partialFingerprints` (hashed, stable across
line-shift); else sha256 of the tool-independent key
`file|line|rule_id|normalized-message`, truncated to 16 hex.

## 4. Deduplicate and corroborate

`dedupe_findings.py` merges in two passes:

- **Pass 1** — exact fingerprint match (kills repeat runs and intra-tool
  duplicates).
- **Pass 2** — same `(file, line)` bucket: collapse records whose CWE agrees
  (or where one side lacks a CWE) when they come from *different* tools;
  same-tool records only collapse on identical rule ids. The merged record
  keeps `tools: ["codeql","semgrep"]`, per-tool `rule_ids`/`messages`, the
  highest severity, the richest `code_flow`, and all fingerprints.

Corroboration (`len(tools)`) is the strongest truth signal you get for free:
two independent engines flagging the same line/CWE is rarely a coincidence.

## 5. Triage and prioritize

Each merged record gets:

- `priority` = severity weight (critical 100 / high 70 / medium 40 / low 15 /
  info 5) × (1 + 0.4·(corroboration−1)), +10 if a code flow exists (a
  concrete source→sink path means reachability, not just a pattern hit),
  ×0.3 if the path looks like noise.
- `noise` — true for tests/, spec/, fixtures/, vendor/, node_modules/,
  dist/, generated files, `*_test.go`, `test_*.py`, `*.min.js`. These are
  likely-false classes: review last, don't skip (secrets in test fixtures
  are still real secrets).
- `confidence` — high if corroborated by ≥2 tools or carrying a code flow;
  low if noise-path or info severity; medium otherwise.

When triaging a record manually, walk `code_flow` top to bottom: step 1 is
the attacker-controlled source, the last step is the sink; confirm no
sanitizer sits between them before calling it verified. Filter aggressively:
`--min-severity medium --drop-noise` for a first exploitation pass, then a
second pass over the remainder.

## 6. Split into work units and hand off

`to_workunits.py` writes a **clean top-level JSON array** (rupu's
`for_each:` JSON-parses any value starting with `[`):

```bash
python3 scripts/to_workunits.py deduped.json --group file --max-units 50 -o workunits.json
```

- Default: one unit per finding, sorted by priority, ids `wu-0001-<fp8>`.
- `--group file` merges co-located findings into one unit per file (good
  when one reviewer agent should read the whole file once); `--group rule`
  for sweep-style fixes.
- Every unit carries `targets: ["path:line", ...]` and
  `hints: {tools, severity, cwe, rule, fingerprint, confidence,
  corroboration, priority, message, code_flow?}` — enough for a child agent
  to open the file, replay the taint path, and verify.

Then wire into the fleet (concrete YAML, `dispatch` pattern, and tool-call
examples in `references/rupu.md`):

1. **Coverage** — record the repository, every scanned file/module, and
   every dependency package with `assets.mark` so coverage is trackable.
2. **Fan-out** — load the `work-units` skill to split the normalized
   findings into work units and drive them: a rupu workflow consumes
   `workunits.json` with `read_file` + `for_each:`; a lead agent fans out
   over the same array with `dispatch`, one child per unit (or per file
   group), passing the unit's `targets` and `hints` verbatim.
3. **Report** — for each unit the child agent verifies in source, load the
   `finding-report` skill and file the record with `findings.report`,
   carrying over fingerprint, CWE, severity, corroborating tools, and the
   code-flow evidence. Unverified units go back into the queue with their
   confidence downgraded, not into the report.
