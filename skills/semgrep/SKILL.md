---
name: semgrep
description: Run Semgrep (OSS CLI) static analysis for security code review across languages — pick registry rulesets, write custom pattern and taint rules, tune targeting/performance, emit SARIF/JSON, and convert results into rupu work units for fan-out triage. Use as the first SAST step on any source repository.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Semgrep — multi-language SAST workhorse

Semgrep matches code semantically (AST-aware patterns, not regex over text) across
30+ languages. It is fast enough to run on every repo first, before heavier tools.
This skill covers scanning, ruleset selection, custom rule authoring (including
taint mode), output handling, and the handoff into rupu work units.

## 1. Install / update / version

```bash
python3 -m pip install --upgrade semgrep     # or: brew install semgrep
semgrep --version                            # confirm >= 1.x
```

Offline use: pre-fetch registry packs once while online —
`semgrep scan --config p/security-audit --dryrun .` caches rules under
`~/.semgrep/`. For fully air-gapped runs, vendor rule YAML locally
(`git clone https://github.com/semgrep/semgrep-rules`) and point `--config` at
the directory. Set `SEMGREP_SEND_METRICS=off` (or pass `--metrics=off`) to stop
telemetry; note `--config auto` forces metrics on, so prefer named packs offline.

## 2. Core commands

- `semgrep scan [OPTIONS] [TARGETS...]` — the modern form; use this. Bare
  `semgrep` is the legacy alias for the same thing.
- `semgrep ci` — pipeline mode: diff-aware (scans only changes vs the merge
  base), policy-driven when `SEMGREP_APP_TOKEN` is set, exits non-zero on
  blocking findings. Use in CI; for interactive review use `semgrep scan`.
- `semgrep --validate --config ./rules/` — syntax/schema check rules.
- `semgrep --test ./rules/` — unit-test rules against annotated fixtures.

## 3. Baseline scan recipe

```bash
cd /path/to/repo
semgrep scan \
  --config p/security-audit --config p/secrets \
  --metrics=off \
  --sarif --output semgrep.sarif \
  --jobs 8 --timeout 30 --max-memory 4000 \
  .
# human-readable second pass view of the same results:
semgrep scan --config p/security-audit --config p/secrets --metrics=off --text .
```

Multiple `--config` flags combine rulesets in one run. Add the framework pack
matching the stack (see below), then a language pack, then `p/secrets` always.

## 4. Rule sources (`--config`)

| Source | Example | When |
|---|---|---|
| Auto | `--config auto` | Quick start; registry picks rules per detected languages (sends project metrics) |
| Registry pack | `--config p/security-audit` | Named curated packs — the normal choice |
| Local dir/file | `--config ./rules/` | Your custom rules; combine with packs |
| Single rule URL | `--config https://semgrep.dev/c/r/python.lang.security.audit.exec-detected` | One-off rule |

Key packs: `p/default`, `p/security-audit` (high-signal security), `p/ci`
(low-FP, CI-safe), `p/owasp-top-ten`, `p/secrets`, language packs
(`p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/ruby`,
`p/php`, `p/csharp`), framework packs (`p/django`, `p/flask`, `p/express`,
`p/react`, `p/nodejs`, `p/rails`, `p/spring`), and `p/cwe-top-25`,
`p/sql-injection`, `p/xss`, `p/command-injection`, `p/insecure-transport`,
`p/jwt`, `p/docker`, `p/kubernetes`, `p/terraform`. Full catalog and selection
strategy: `references/rulesets.md`.

## 5. Targeting & performance

```bash
semgrep scan --config p/security-audit \
  --include '*.py' --include '*.js' \
  --exclude 'tests/' --exclude '*.min.js' --exclude 'vendor/' \
  --jobs 8 --max-target-bytes 2000000 --timeout 30 --max-memory 4000 \
  src/ services/
```

- Positional targets are files or dirs; default `.`. Respects `.gitignore` and
  `.semgrepignore` (one glob per line; create it to permanently skip
  `vendor/`, generated code, minified bundles). `--no-git-ignore` to override.
- `--include` / `--exclude` take globs, repeatable. `--exclude-rule <id>`
  silences one rule.
- `--jobs N` parallelism; `--timeout SECS` per-rule-per-file (0 = none);
  `--timeout-threshold N` drops a file after N rule timeouts;
  `--max-memory MB` per-file cap; `--max-target-bytes` skips huge files
  (default 1MB — raise for legit large sources, generated code is usually noise).
- Diff-aware without `semgrep ci`:
  `semgrep scan --config p/ci --baseline-commit origin/main` scans only
  findings introduced since that commit — ideal for PR review on big repos.

## 6. Output & result control

```bash
semgrep scan --config p/security-audit --sarif --output semgrep.sarif .
semgrep scan --config p/security-audit --json  --output semgrep.json  .
semgrep scan --config p/ci --gitlab-sast --output gl-sast.json .
semgrep scan --config p/security-audit --severity ERROR --severity WARNING .
semgrep scan --config p/ci --error .          # exit 1 if any finding — CI gate
semgrep scan --config ./rules/taint.yaml --dataflow-traces .   # show taint path
semgrep scan --config p/python --autofix --dryrun .            # preview fixes
semgrep scan --config p/python --autofix .                     # apply fixes
```

- SARIF is the canonical interchange format for this fleet — always produce it.
- `--dataflow-traces` prints source→propagation→sink steps for taint-mode rules
  (also embedded in JSON/SARIF). Essential for triaging injection findings.
- `--verbose` / `--debug` show skipped files, parse errors, rule timings —
  check these when coverage looks thin. `--time` adds per-rule timing to JSON.
- Severities: `INFO < WARNING < ERROR`. Full flag reference: `references/cli.md`.

## 7. Writing custom rules — the real power

Registry packs find the generic 80%. Custom rules find *this codebase's* bugs:
its wrapper functions, its ORM escape hatches, its internal "do not call" APIs.
Full tutorial with multi-language examples: `references/writing-rules.md`.

### 7.1 Search-mode rule anatomy

```yaml
rules:
  - id: example-com-raw-sql-fstring
    languages: [python]
    severity: ERROR
    message: f-string interpolated into cursor.execute() — SQL injection.
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
      references:
        - https://owasp.org/Top10/A03_2021-Injection/
    patterns:
      - pattern: $CUR.execute(f"...")
      - pattern-not-inside: |
          def test_...(...):
              ...
```

Operators (compose freely inside `patterns:`):
- `pattern` — match this AST shape. `pattern-either` — OR of sub-patterns.
- `pattern-not` — subtract matches. `pattern-inside` / `pattern-not-inside` —
  require/forbid an enclosing context (function, class, `with` block…).
- `pattern-regex` / `pattern-not-regex` — raw regex over the file (secrets, headers).
- Metavariables `$X`, `$FUNC`, `$ARG` bind any expression/identifier; the same
  name must bind the same value within one pattern clause. `...` (ellipsis)
  matches any sequence of args/statements/characters in strings.
- `metavariable-pattern` — recursively constrain what `$X` matched;
  `metavariable-regex` — regex on `$X`'s text;
  `metavariable-comparison` — numeric/string comparison, e.g.
  `comparison: $MODE >= 0o777` or `comparison: int($TIMEOUT) == 0`.
- `fix: $CUR.execute("...", params)` enables `--autofix`.

### 7.2 Taint-mode rule (source → sink dataflow)

```yaml
rules:
  - id: example-com-flask-to-os-system
    languages: [python]
    severity: ERROR
    mode: taint
    message: Request data flows into shell execution — command injection.
    metadata:
      cwe: "CWE-78: OS Command Injection"
      owasp: "A03:2021 - Injection"
    pattern-sources:
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.form[...]
      - pattern: flask.request.get_json()
    pattern-sanitizers:
      - pattern: shlex.quote(...)
      - pattern: int(...)
    pattern-propagators:
      - pattern: $D.update($S)
        from: $S
        to: $D
    pattern-sinks:
      - pattern: os.system(...)
      - pattern: subprocess.call($CMD, ..., shell=True, ...)
      - pattern: subprocess.run($CMD, ..., shell=True, ...)
```

Taint tracks values through assignments, string concatenation/f-strings, and
function args intraprocedurally. `pattern-propagators` extends flow through
calls the engine doesn't model (dict merges, custom builders). Run taint rules
with `--dataflow-traces`. A SQL-concat taint rule and JS/Go variants are in
`references/writing-rules.md`.

### 7.3 Test and validate rules

Fixture `tests/cmd_injection.py` next to the rule, annotated:

```python
import os, flask
def handler():
    cmd = flask.request.args.get("cmd")
    # ruleid: example-com-flask-to-os-system
    os.system("ping " + cmd)
    # ok: example-com-flask-to-os-system
    os.system("ping 192.0.2.10")
```

```bash
semgrep --validate --config rules/        # schema + pattern syntax
semgrep --test rules/                     # ruleid:/ok: annotations must match
```

## 8. Reading output & triage

Each finding carries: `check_id` (rule), `path`, `start.line`/`end.line`,
`extra.severity`, `extra.message`, `extra.metadata` (cwe/owasp/confidence),
`extra.metavars` (what `$X` bound — read these to see the exact tainted
variable/call), and `extra.dataflow_trace` for taint rules.

Triage order: ERROR-severity taint rules with full traces first (near-confirmed
injection), then ERROR search rules, then WARNING. Confirm by reading the code
at each trace step — is the source really attacker-controlled, is there a
sanitizer Semgrep missed?

False-positive handling:
- Inline: `# nosemgrep` or `# nosemgrep: rule-id` on the matched line (language
  comment syntax varies: `// nosemgrep`, `<!-- nosemgrep -->`).
- Per-rule path excludes inside the rule YAML:
  `paths: { exclude: ["tests/*", "*_test.go"] }`.
- Run-level: `--exclude-rule <id>`, `--exclude <glob>`, `.semgrepignore`.

## 9. Handoff — produce rupu work units

End-to-end driver (scan → SARIF → work units):

```bash
python3 scripts/run_semgrep.py \
  --config p/security-audit --config p/secrets --config ./rules \
  --repo /path/to/repo \
  --sarif semgrep.sarif --out workunits.json
# or convert an existing SARIF:
python3 scripts/semgrep_sarif_to_workunits.py semgrep.sarif -o workunits.json
```

`workunits.json` is a clean top-level JSON array:
`[{"id","title","targets":["path:line",...],"hints":{"rule","severity","cwe","owasp","message"}},...]`
grouped per rule+file so each unit is one coherent review task.

Then:
1. Load the `work-units` skill to split/queue the normalized findings as work
   units for the crew; a rupu workflow consumes `workunits.json` with
   `read_file` + `for_each:`, and a lead agent fans out with `dispatch`
   (concrete YAML in `references/rupu.md`).
2. Mark the repository, scanned files/modules, and dependency packages as
   covered with `assets.mark` (examples in `references/rupu.md`).
3. For each finding an agent verifies in source, load the `finding-report`
   skill and file it via `findings.report`.
4. When combining Semgrep SARIF with other scanners' SARIF, use the
   `sarif-triage` skill for cross-tool normalization and dedupe before splitting.
