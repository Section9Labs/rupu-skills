---
name: gosec
description: Run and triage gosec (securego/gosec), the Go source security analyzer — install, scan Go modules/packages, select rules (Gxxx) and severity/confidence filters, handle #nosec suppressions, emit SARIF/JSON, convert results into rupu work units, and route findings to deeper dataflow analysis. Use whenever a target repository contains Go code (go.mod, *.go) during security code review.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# gosec — Go source security analysis

gosec is an AST-based scanner for Go. It inspects every Go file in a buildable
module and flags insecure patterns: SQL built by string concatenation, command
execution with tainted arguments, path traversal in file opens, weak crypto,
weak RNG, hardcoded credentials, bad TLS config, bad file permissions, unsafe
pointer use, integer truncation, and more. Each finding carries a rule id
(Gxxx), severity, confidence, CWE, file:line, and the offending source line.

## 1. Install

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
# binary lands in $(go env GOPATH)/bin — ensure it is on PATH
gosec -version
```

Alternative: `curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b /usr/local/bin`.

gosec needs a **buildable module**: run it from the directory containing
`go.mod` (or a GOPATH package). If `go build ./...` fails, fix module
resolution first (`go mod download`, `go mod tidy`, set `GOFLAGS=-mod=mod` or
`GONOSUMCHECK`/`GOFLAGS=-mod=vendor` for vendored repos). Private modules:
`GOPRIVATE=git.example.com/* go mod download`.

## 2. Run

```sh
cd /path/to/repo            # directory with go.mod
gosec ./...                 # scan the whole module (preferred)
gosec -r /path/to/dir       # recursive scan of a directory tree
gosec ./internal/api/...    # scan one package subtree
gosec github.com/example/pkg # a package path resolvable in the module
```

Useful run-time flags (full list in `references/cli.md`):

```sh
gosec -tests ./...                       # also scan *_test.go
gosec -exclude-dir vendor -exclude-dir third_party ./...
gosec -tags integration,netgo ./...      # honor build tags so tagged files are parsed
gosec -concurrency 8 ./...               # worker count (default = NumCPU)
gosec -quiet ./...                       # only emit output when issues found
```

Multi-module repos (go.work or several go.mod files): run gosec once per
module root; a single `-r` from the repo top may fail type resolution across
module boundaries.

## 3. Rule selection and filters

```sh
gosec -include G201,G202,G204,G304 ./...   # only these rules
gosec -exclude G104,G307 ./...             # everything except these
gosec -severity high ./...                 # drop findings below HIGH severity
gosec -confidence medium ./...             # drop findings below MEDIUM confidence
```

Severity/confidence values: `low`, `medium`, `high`. For a first pass over a
large codebase, `-severity medium -confidence medium` cuts most noise (G104
unhandled-errors dominates raw output). For a thorough review run **unfiltered**
once and triage from JSON — low-severity rules like G101 and G404 are often
the real bugs.

### Suppressions (`#nosec`)

Developers silence gosec inline:

```go
tx, _ := db.Query(q) // #nosec G201 -- q is a constant, reviewed 2024-01
```

- Bare `#nosec` suppresses every rule on that line; `#nosec G201 G202`
  suppresses only those ids.
- `-nosec` **ignores all `#nosec` comments** — always do at least one run with
  `-nosec` to audit what has been suppressed; stale suppressions hide real bugs.
- `-track-suppressions` keeps suppressed findings in JSON/SARIF output with a
  `suppressions` block (kind + justification) instead of dropping them —
  preferred for review: you see both active and suppressed issues in one report.
- `-nosec-tag=falsepositive` changes the magic comment to `#falsepositive`
  (some teams rename it); search the codebase for both `#nosec` and any custom
  tag (`grep -rn '#nosec\|#gosec' --include='*.go'`).

## 4. Output formats and exit behaviour

```sh
gosec -fmt sarif -out gosec.sarif ./...     # SARIF 2.1.0 — feed to sarif-triage
gosec -fmt json  -out gosec.json  ./...     # native JSON — richest (code snippet, stats)
gosec -fmt text ./...                        # human-readable to stdout
gosec -fmt sarif -out gosec.sarif -stdout -verbose=text ./...  # file + console at once
```

Other formats: `yaml`, `csv`, `junit-xml`, `html`, `sonarqube`, `golint`,
`text` (default). Exit code is 1 when issues are found (and on build errors);
control it with:

```sh
gosec -no-fail ./...                 # always exit 0 (pipelines where you parse output yourself)
gosec -fail-severity high ./...      # exit non-zero only for HIGH findings
```

Use `scripts/run_gosec.py` to run both SARIF and JSON in one shot and produce
work units:

```sh
python3 scripts/run_gosec.py --repo /path/to/repo --outdir out/
# -> out/gosec.sarif, out/gosec.json, out/workunits.json
```

## 5. Reading a result

Native JSON: `Issues[]` with `rule_id`, `severity`, `confidence`, `cwe.id`,
`file`, `line` (may be a range `"41-44"`), `column`, `details`, `code` (the
flagged source with context), and optionally `suppressions`. `Stats` gives
files/lines scanned and `#nosec` count; `Golang errors` lists files that
failed to parse (coverage gaps — fix build tags or deps and rerun).

Triage order: **severity HIGH + confidence HIGH first** (these are usually
concrete sinks: G201/G204/G304/G402), then HIGH severity at lower confidence
(gosec couldn't prove the argument is non-constant — manual check needed),
then MEDIUM. Confidence encodes how sure gosec is that the pattern is
exploitable-shaped, not whether input is attacker-controlled — that is your
job.

## 6. Rule catalog by vulnerability class (details in `references/rules.md`)

| Class | Rules | What to look for |
|---|---|---|
| SQL injection | G201 (format string), G202 (concatenation) | `fmt.Sprintf`/`+` building queries passed to `db.Query/Exec` |
| Command injection | G204 | `exec.Command`/`syscall.Exec` with variable program or args |
| Path traversal / file inclusion | G304 | `os.Open`/`ioutil.ReadFile` with tainted path; pair with G305 (zip/tar slip) |
| Unsafe pointers | G103 | `unsafe.Pointer` use — memory safety escape hatch |
| Weak crypto | G401 (MD5/SHA1), G501–G505 (DES/RC4/MD5/SHA1 imports), G506/G507 (MD4/RIPEMD160) | hashing passwords/signatures with broken primitives |
| Weak RNG | G404 | `math/rand` where tokens/keys/nonces need `crypto/rand` |
| Hardcoded credentials | G101 | string literals assigned to password/token/secret-named vars |
| TLS misconfig | G402 (InsecureSkipVerify, bad MinVersion/ciphers), G403 (weak RSA key < 2048) | `tls.Config` review |
| Integer overflow | G115 | `int64 -> int32/uint8` style conversions that truncate |
| Unhandled errors | G104 | dropped `err` — security-relevant when on crypto/auth/io calls |
| Bind all interfaces | G102 | `net.Listen("tcp", "0.0.0.0:...")` / `":8080"` |
| File/dir permissions | G301–G307 | `os.MkdirAll(0777)`, world-readable key files, `os.Create` perms |
| Template injection | G203 | `template.HTML/JS/URL(...)` disabling html/template autoescape |
| Decompression bomb | G110 | `io.Copy` from zlib/gzip reader without `io.LimitReader` |
| SSRF | G107 | `http.Get(url)` with variable URL |
| Others | G105/G106, G108/G109, G111, G112, G113, G114, G601/G602 | see references/rules.md |

## 7. Limits — and where to route next

gosec is an **intrafile, mostly intraprocedural heuristic** engine:

- It flags `db.Query(q)` when `q` is non-constant but cannot trace whether `q`
  originates from an HTTP parameter three functions away. High FP *and* FN
  rate on anything requiring dataflow.
- It misses sinks reached through interfaces, wrappers (`myDB.RawQuery`),
  ORMs (`gorm.Raw`), and generated code.
- No cross-package taint, no sanitizer awareness (`filepath.Clean` vs. real
  containment checks).

Route accordingly:

- For taint tracking of G201/G202/G204/G304/G107-class findings, run
  **`semgrep`** (Go taint rules, `p/golang`, `p/gosec`-equivalent rulesets)
  and **`codeql`** (Go `security-extended` suite) over the same repo, and load
  the **`taint-analysis`** skill to trace source→sink paths for the Go sinks
  gosec surfaced (`database/sql`, `os/exec`, `os.Open`, `net/http`,
  `text/template`).
- gosec covers code only, not dependencies — run SCA (`go list -m all`,
  govulncheck, osv-scanner) separately for vulnerable packages.

## 8. Parse, hand off, report (rupu)

1. Run `python3 scripts/run_gosec.py --repo <repo> --outdir out/` (or run gosec
   manually and `python3 scripts/gosec_to_workunits.py --json out/gosec.json
   --out out/workunits.json`). The output file is a **clean top-level JSON
   array** of work units `{id, title, targets:["path:line"], hints:{rule_id,
   severity, confidence, cwe, ...}}`.
2. Mark coverage with `assets.mark`: the repository, every scanned Go
   file/module (gosec JSON `Stats.files`), and — once SCA runs — the
   dependency packages. Concrete calls in `references/rupu.md`.
3. Load the **`work-units`** skill to split/normalize `out/workunits.json`
   into per-agent work units; a rupu workflow consumes the array with
   `read_file` + `for_each:`, and a lead agent fans out over it with
   `dispatch` (YAML in `references/rupu.md`).
4. Feed `out/gosec.sarif` to the **`sarif-triage`** skill for cross-tool
   dedupe/merge with semgrep/codeql SARIF from the same repo.
5. For each work unit, verify in source (is the flagged value attacker
   reachable? is the suppression justified?). File every verified issue by
   loading the **`finding-report`** skill and calling `findings.report` with
   the rule id, CWE, file:line evidence, and the exploitability analysis.
