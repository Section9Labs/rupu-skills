---
name: bandit
description: Run and triage Bandit, the PyCQA Python SAST linter — recursive scans, config/baseline/threshold tuning, SARIF/JSON output, the full Bxxx test catalog by vulnerability class, noise suppression, and conversion of results into rupu work units; use when auditing Python source for injection, deserialization, crypto, SSL/TLS, secrets, and unsafe-API issues, then route deeper taint questions to semgrep/codeql/pysa.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Bandit — Python SAST

Bandit parses Python source into an AST and runs per-node plugin tests
(B1xx–B7xx). It is fast, intrafile, and pattern-based: perfect for a first
sweep over any Python repo, and the findings map cleanly to CWEs. It does
NOT do cross-function or cross-file taint — see "Limits & handoff" below.

## 1. Install

```bash
pip install bandit            # core
pip install "bandit[sarif]"   # adds -f sarif
pip install "bandit[toml]"    # adds pyproject.toml [tool.bandit] support
bandit --version
```

## 2. Run

```bash
# Recursive scan of a tree (the normal mode)
bandit -r src/

# Repo-wide, with vendored/test noise excluded
bandit -r . -x ./.venv,./node_modules,./tests,./migrations

# Only aggregate by file, show 5 lines of context around each hit
bandit -r src/ -n 5 --aggregate file
```

Key flags (full list in `bandit --help`):

| Flag | Effect |
|---|---|
| `-r` | recurse into directories |
| `-x`, `--exclude` | comma-separated glob paths to skip (`-x ./.venv,./tests`) |
| `-l` / `-ll` / `-lll` | report only ≥LOW / ≥MEDIUM / ≥HIGH **severity** |
| `-i` / `-ii` / `-iii` | report only ≥LOW / ≥MEDIUM / ≥HIGH **confidence** |
| `--severity-level {all,low,medium,high}` | same as `-l..`, explicit form |
| `--confidence-level {all,low,medium,high}` | same as `-i..`, explicit form |
| `-t B602,B608` | run ONLY these test ids |
| `-s B101,B311` | skip these test ids |
| `-c bandit.yaml` | config file (profiles, per-test options) |
| `--baseline baseline.json` | suppress findings already present in a prior JSON report |
| `-f <fmt>` / `-o <file>` | output format / file |
| `-q` | quiet (errors only on stderr) |
| `--exit-zero` | exit 0 even with findings (CI-friendly wrappers) |

Exit codes: `0` = clean, `1` = findings (or usage error) — treat `1` as
"results present", not failure.

### Config file (`-c bandit.yaml`)

```yaml
# bandit.yaml
exclude_dirs: ['.venv', 'tests', 'migrations']
skips: ['B101', 'B311']        # assert, random — usually noise
# tests: ['B602','B608']       # or whitelist instead
any_other_function_with_shell_equals_true:
  no_shell: [os.execl, os.execle]
```

Or in `pyproject.toml` (needs `bandit[toml]`):

```toml
[tool.bandit]
exclude_dirs = [".venv", "tests"]
skips = ["B101"]
```

### Baseline (diff-scanning)

```bash
bandit -r . -f json -o baseline.json          # snapshot current state
# ... later, only NEW findings are reported:
bandit -r . --baseline baseline.json
```

## 3. Output formats and reading a result

```bash
bandit -r src/ -f json  -o bandit.json      # native JSON — richest, parse this
bandit -r src/ -f sarif -o bandit.sarif     # SARIF 2.1.0 — for sarif-triage
bandit -r src/ -f csv   -o bandit.csv
bandit -r src/ -f html  -o bandit.html
bandit -r src/ -f txt   -o bandit.txt       # same as screen, no color
bandit -r src/ -f screen                    # default terminal view
```

A screen/txt result:

```
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with
   shell=True identified, security issue.
   Severity: High   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   Location: src/jobs/runner.py:42
41          cmd = f"convert {user_filename} out.png"
42          subprocess.Popen(cmd, shell=True)
```

Read it as: **test id** (B602 → which plugin fired), **severity** (impact
class Bandit assigns the pattern), **confidence** (how sure the matcher is —
HIGH means the AST shape is unambiguous), **CWE**, **file:line**, and the
**code snippet**. In native JSON each entry in `results[]` carries
`test_id`, `test_name`, `issue_severity`, `issue_confidence`,
`issue_cwe.id`, `filename`, `line_number`, `line_range`, `code`,
`issue_text`, `more_info` (docs URL). The `metrics` block gives per-file
LOC and counts — use it for coverage accounting.

## 4. Test catalog — the ids that matter

Full catalog with vulnerable examples: `references/tests.md`. The high-value
classes:

- **Code execution**: `B102` exec, `B307` eval, `B202` tarfile extractall.
- **Shell / command injection**: `B602` subprocess shell=True, `B603`
  subprocess without shell (check args), `B604` any function with
  shell=True, `B605` os.system/popen with a built string, `B606`
  start-process no shell, `B607` partial exec path, `B609` wildcard
  injection. Prioritize B602/B604/B605 where the string contains a
  variable.
- **Deserialization**: `B301` pickle/cPickle/dill/shelve loads, `B302`
  marshal, `B403`/`B404` the imports, `B506` `yaml.load` without
  SafeLoader.
- **Weak crypto**: `B303`/`B324` md5/sha1 via hashlib (`usedforsecurity`),
  `B304`/`B305` weak ciphers/modes (DES, RC4, ECB), `B505` weak key sizes.
- **TLS/SSL**: `B501` `requests(..., verify=False)`, `B502` bad TLS
  version, `B503` ssl with bad defaults, `B504` ssl without version.
- **Secrets**: `B105` hardcoded password string, `B106` as funcarg,
  `B107` as default arg. Chain with trufflehog/gitleaks for history.
- **Web framework**: `B201` Flask `debug=True` (Werkzeug RCE), `B701`
  jinja2 `autoescape=False`, `B703` django mark_safe, `B610`/`B611`
  django extra/RawSQL.
- **SQL**: `B608` string-built SQL (`f"SELECT ... {x}"`, `%`, `+`,
  `.format`). High-value — hand every B608 to taint tooling.
- **XML / XXE**: `B313`–`B320` xml.etree/sax/minidom/pulldom/xmlrpclib,
  `B405`–`B411` the imports. Fix = defusedxml.
- **Filesystem**: `B306` `tempfile.mktemp` (race), `B108` hardcoded /tmp
  paths, `B103` chmod 0777.
- **Network**: `B104` bind 0.0.0.0, `B310` urllib urlopen (scheme-abuse /
  SSRF candidate), `B312` telnetlib, `B321`/`B402` ftplib.
- **Low-signal (skip early)**: `B101` assert used (only matters in
  prod logic under `python -O`), `B311` `random` (only if used for
  tokens/secrets), `B110`/`B112` try/except pass/continue.

## 5. Tuning noise

```bash
bandit -r src/ -ll -ii -s B101,B311 -x ./tests        # the usual triage cut
bandit -r src/ -t B602,B604,B605,B608,B301,B506 -lll  # exploit-first pass
```

Inline suppression — always scoped to a test id, never bare:

```python
subprocess.Popen(STATIC_CMD, shell=True)  # nosec B602 -- constant string
```

Audit existing suppressions: `grep -rn "nosec" src/` — a `# nosec` on a
line with user-controlled input is itself a finding.

## 6. Workflow (scan → work units → verify → report)

1. Mark the repo and scanned modules as assets with `assets.mark`
   (asset model: repository, files/modules, dependency packages — see
   `references/rupu.md`).
2. Scan: `python3 scripts/run_bandit.py <repo-path> -o out/` — runs
   Bandit with both JSON and SARIF outputs and emits
   `out/workunits.json`, a clean top-level JSON array of
   `{id,title,targets:["path:line"],hints:{test_id,severity,confidence,cwe}}`.
   Or convert an existing report: `python3 scripts/bandit_to_workunits.py
   bandit.json -o workunits.json` (auto-detects native JSON vs SARIF).
3. Load the `work-units` skill to split/normalize `workunits.json` into
   per-agent work units; a rupu workflow consumes it with `read_file` +
   `for_each:`, and a lead agent fans out with `dispatch` (concrete YAML
   in `references/rupu.md`).
4. Feed `out/bandit.sarif` to the `sarif-triage` skill to merge/dedupe
   with other scanners' SARIF.
5. For each work unit: open the file at the target line, decide whether
   the flagged sink is reachable from attacker input, and build a PoC
   (e.g. for B602: trace the string back to a request parameter, then
   demonstrate command execution). Load the `finding-report` skill to
   file each verified issue via `findings.report`.

## 7. Limits & handoff

Bandit is AST pattern matching, **one file at a time, no dataflow**. It
tells you a dangerous sink exists; it cannot tell you whether tainted
input reaches it, and it misses sinks reached through wrappers or
indirection. Route accordingly:

- **`semgrep` skill** — taint-mode rules (`mode: taint`,
  pattern-sources/sinks) for intra-file and simple cross-function flows;
  fast confirmation of B602/B608-class leads.
- **`codeql` skill** — full interprocedural dataflow for Python
  (`codeql database create --language=python`, security-extended suite)
  when the repo warrants deep analysis.
- **Pysa (Pyre)** — Facebook's configured taint analysis for Python:
  write `.pysa` source/sink models, `pyre analyze`. Setup and output
  reading in `references/pysa.md`.

Bandit covers first-party code only; for dependency packages (the SCA
side of the asset model) run `pip-audit`/OSV tooling and mark those
packages as assets too.
