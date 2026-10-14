# gosec CLI reference

Invocation shape: `gosec [flags] <packages|paths>`

Targets: `./...` (module root, all packages), a package import path
(`github.com/example/app/internal/api`), relative package paths
(`./cmd/server/...`), or with `-r` a filesystem directory walked recursively.
Run from the module root (where `go.mod` lives) so type checking works.

## Target / build flags

| Flag | Meaning |
|---|---|
| `-r` | Recurse into directories given as filesystem paths instead of package patterns |
| `-tests` | Include `*_test.go` files (excluded by default) |
| `-exclude-dir <dir>` | Skip a directory; repeatable (`-exclude-dir vendor -exclude-dir gen`) |
| `-tags "t1 t2"` / `-tags t1,t2` | Build tags passed to the loader; files guarded by `//go:build` tags are otherwise invisible |
| `-concurrency N` | Parallel package analyzers (default: NumCPU) |
| `-enable-audit` | Enable experimental/audit-mode rules |

## Rule selection

| Flag | Meaning |
|---|---|
| `-include G101,G201` | Run only the listed rule ids |
| `-exclude G104,G307` | Run everything except the listed ids |
| `-exclude-generated` | Skip files with the standard `// Code generated ... DO NOT EDIT.` header |
| `-severity low\|medium\|high` | Minimum severity to report (default low) |
| `-confidence low\|medium\|high` | Minimum confidence to report (default low) |

`-include` and `-exclude` are mutually exclusive in intent; prefer `-exclude`
for broad sweeps, `-include` for focused re-scans of one class.

## Suppressions

| Flag | Meaning |
|---|---|
| `-nosec` | Ignore all `#nosec` comments (audit mode — findings reappear) |
| `-nosec-tag <tag>` | Alternate magic comment token instead of `nosec` |
| `-track-suppressions` | Keep suppressed findings in output with a `suppressions` array (`kind: inSource`, justification text after `--`) instead of omitting them |

Inline syntax in Go source:

```go
// suppress everything on this line:
data, _ := os.ReadFile(p) // #nosec
// suppress specific rules, with justification:
data, _ := os.ReadFile(p) // #nosec G304 -- p is validated against an allowlist above
```

A `#nosec` on a block statement (e.g. a function or `if` block comment)
suppresses findings within the block.

## Output

| Flag | Meaning |
|---|---|
| `-fmt <format>` | `text` (default), `json`, `yaml`, `csv`, `junit-xml`, `html`, `sonarqube`, `golint`, `sarif` |
| `-out <file>` | Write report to file instead of stdout |
| `-stdout` | Also print to stdout when `-out` is used |
| `-verbose <format>` | Format for the stdout copy when `-stdout` is set (e.g. `-verbose=text`) |
| `-no-color` | Disable ANSI colors in text output |
| `-quiet` | Produce output only when issues are found |
| `-sort` | Sort issues by severity (default true; `-sort=false` for file order) |
| `-show-ignored` | Print issues that were nosec'd (text mode) |

## Exit code

| Flag | Meaning |
|---|---|
| (default) | Exit 1 if any issue found or any file failed to build |
| `-no-fail` | Always exit 0 |
| `-fail-severity low\|medium\|high` | Exit non-zero only when findings at/above this severity exist |

## Config file

`-conf gosec.json` loads per-rule configuration, e.g.:

```json
{
  "global": { "nosec": "enabled", "audit": "enabled" },
  "G101": {
    "pattern": "(?i)passwd|password|secret|token|apikey|api_key|bearer|cred",
    "ignore_entropy": false,
    "entropy_threshold": "80.0"
  },
  "G104": { "ioutil": ["WriteFile"] },
  "G111": { "pattern": "http\\.Dir\\(\"\\/\"\\)|http\\.Dir\\('\\/'\\)" },
  "G302": "0600"
}
```

Notable configurables: G101 secret-name regex + entropy, G104 per-package
function ignore lists, G301–G307 permission thresholds (octal string), G111
served-directory pattern.

## Misc

| Flag | Meaning |
|---|---|
| `-version` | Print version/build info |
| `-ai-api-provider` / `-ai-api-key` | (newer builds) LLM-generated autofix suggestions appended to findings |

## Recommended invocations

```sh
# Full-fidelity audit run (keep everything, see suppressions, machine output):
gosec -tests -track-suppressions -fmt json -out gosec.json -no-fail ./...
gosec -tests -track-suppressions -fmt sarif -out gosec.sarif -no-fail ./...

# Suppression audit (what did #nosec hide?):
gosec -nosec -fmt json -out gosec-nosec.json -no-fail ./...

# Focused re-scan on injection sinks only:
gosec -include G201,G202,G204,G304,G107 -fmt text ./...
```
