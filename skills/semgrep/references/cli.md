# Semgrep CLI reference (flags that matter)

All flags below apply to `semgrep scan` (modern form; bare `semgrep` is the
legacy alias). `semgrep ci` shares most of them.

## Rule selection

| Flag | Meaning |
|---|---|
| `--config auto` | Registry picks rules based on detected languages/frameworks. Forces metrics on. |
| `--config p/<pack>` | Named registry ruleset, e.g. `p/security-audit`. Repeatable — all configs merge into one run. |
| `--config r/<rule-id>` | Single registry rule by id. |
| `--config ./rules/` | Local directory of rule YAML files (recursive). |
| `--config ./rule.yaml` | Single local rule file. |
| `--config https://semgrep.dev/c/r/...` | Rule(s) by URL. |
| `--exclude-rule <id>` | Drop one rule from whatever configs loaded. Repeatable. |
| `-e PATTERN -l LANG` | Ad-hoc one-pattern scan without a rule file: `semgrep scan -e 'os.system(...)' -l python src/`. |
| `--validate --config X` | Check rule syntax/schema; no scan. |
| `--test DIR` | Run rule unit tests against `ruleid:`/`ok:` annotated fixtures. |

## Targeting

| Flag | Meaning |
|---|---|
| positional `TARGETS` | Files/dirs to scan (default `.`). |
| `--include GLOB` | Only scan matching paths. Repeatable. `--include '*.py'` |
| `--exclude GLOB` | Skip matching paths. Repeatable. `--exclude 'vendor/'` |
| `.semgrepignore` | gitignore-style file in repo root; applied automatically. Default also skips `.gitignore` entries. |
| `--no-git-ignore` | Scan files git ignores (vendored deps, build output). |
| `--scan-unknown-extensions` | Attempt files with unrecognized extensions when explicitly targeted. |
| `--baseline-commit REF` | Report only findings not present at REF — diff-aware scanning. `--baseline-commit origin/main` |
| `--max-target-bytes N` | Skip files larger than N bytes (default 1000000). `0` = no limit. |

## Performance

| Flag | Meaning |
|---|---|
| `--jobs N` / `-j N` | Parallel workers (default: CPU count). |
| `--timeout SECS` | Max seconds per rule per file (default 5; `0` disables). |
| `--timeout-threshold N` | Skip a file entirely after N rule timeouts (default 3). |
| `--max-memory MB` | Per-file memory cap; file skipped if exceeded. |
| `--time` | Include per-rule/per-file timing in JSON output — find slow rules. |

## Output

| Flag | Meaning |
|---|---|
| `--sarif` | SARIF 2.1.0 to stdout. |
| `--json` | Semgrep native JSON. |
| `--gitlab-sast` | GitLab SAST report JSON. |
| `--gitlab-secrets` | GitLab secret-detection report JSON. |
| `--junit-xml` | JUnit XML. |
| `--emacs` / `--vim` | Editor-friendly line formats. |
| `--text` | Default human-readable output (explicit when combined). |
| `--output FILE` / `-o FILE` | Write the formatted output to FILE instead of stdout. `--sarif --output semgrep.sarif` |
| `--severity LEVEL` | Only report INFO/WARNING/ERROR; repeatable: `--severity ERROR --severity WARNING`. |
| `--error` | Exit code 1 when findings exist (CI gating). Exit 0 otherwise even with findings. |
| `--strict` | Also fail on rule/scan errors. |
| `--dataflow-traces` | Print/embed taint source→sink traces for taint-mode findings. |
| `--verbose` | List skipped files, parse errors, config resolution. |
| `--debug` | Full engine logging. |
| `--quiet` / `-q` | Suppress non-finding output. |
| `--no-rewrite-rule-ids` | Keep original rule ids instead of prefixing local dir structure. |
| `--force-color` / `--no-color` | TTY color control. |

## Autofix

| Flag | Meaning |
|---|---|
| `--autofix` / `-a` | Apply `fix:` edits from rules in place. |
| `--dryrun` | With `--autofix`: show the diff, change nothing. |

## Behavior / environment

| Flag / env | Meaning |
|---|---|
| `--metrics=off` | Disable telemetry (`auto` config overrides this). Env: `SEMGREP_SEND_METRICS=off`. |
| `--disable-version-check` | No update ping — needed offline. |
| `SEMGREP_RULES` | Space-separated configs via env instead of `--config`. |
| `SEMGREP_APP_TOKEN` | Enables policy-driven `semgrep ci` against Semgrep AppSec Platform. |
| `--oss-only` | (ci) Force OSS engine even with a token. |

## Exit codes

- `0` — completed; no blocking findings (or findings present without `--error`).
- `1` — findings found with `--error`, or blocking findings in `ci` mode.
- `2`+ — fatal errors (bad config, no targets, parse failures with `--strict`).

## `semgrep ci` specifics

```bash
SEMGREP_APP_TOKEN=... semgrep ci                 # policy from platform, diff-aware
semgrep ci --config p/ci --sarif --output ci.sarif   # tokenless: explicit config
```

Diff-aware by default in CI contexts (uses `SEMGREP_BASELINE_REF` or the
detected merge base). Use `scan` for full-repo audits, `ci` for gating changes.

## Useful combos

```bash
# Big monorepo, security focus, fast:
semgrep scan --config p/security-audit --config p/secrets \
  --exclude 'node_modules/' --exclude 'dist/' --exclude '*.min.js' \
  --jobs 16 --max-memory 5000 --timeout 20 \
  --sarif -o semgrep.sarif --metrics=off .

# Only new issues in a feature branch:
semgrep scan --config p/ci --baseline-commit origin/main --json -o new.json .

# Hunt one API ad hoc across a polyglot repo:
semgrep scan -e '$X.innerHTML = $Y' -l javascript --text web/
```
