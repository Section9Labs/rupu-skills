# codeql database analyze — suites, packs, flags

```bash
codeql database analyze <db> <queries...> \
  --format=sarif-latest --output=results.sarif \
  [--sarif-category=<id>] [--download] [--threads=0] [--ram=<MB>] \
  [--sarif-add-snippets] [--max-paths=<n>] [--rerun] [--verbosity=progress]
```

`<queries...>` may be any mix of:
- a **pack name** → runs its default suite (`code-scanning`): `codeql/python-queries`
- a **pack-scoped suite**: `codeql/java-queries:codeql-suites/java-security-extended.qls`
- a **pinned pack**: `codeql/go-queries@1.1.3`
- a **local .ql file**, a directory of queries, or a local pack directory (`./audit-queries`)
- nothing → the DB's baseline/default suite

## Standard query packs

| Language | Pack |
|---|---|
| C/C++ | `codeql/cpp-queries` |
| C# | `codeql/csharp-queries` |
| Go | `codeql/go-queries` |
| Java/Kotlin | `codeql/java-queries` |
| JS/TS | `codeql/javascript-queries` |
| Python | `codeql/python-queries` |
| Ruby | `codeql/ruby-queries` |
| Swift | `codeql/swift-queries` |
| Actions | `codeql/actions-queries` |

Pre-fetch (needed for standalone CLI, or use `--download` on analyze):

```bash
codeql pack download codeql/python-queries codeql/javascript-queries
codeql resolve queries codeql/python-queries:codeql-suites/python-security-extended.qls
# ^ lists exactly which .ql files a suite would run
```

## Suites per pack (under `codeql-suites/`)

- `<lang>-code-scanning.qls` — default; precision high/very-high security
  queries, `@kind problem|path-problem`, security-relevant tags. Lowest noise.
- `<lang>-security-extended.qls` — adds medium-precision and
  `security-experimental` adjacent queries. **Audit default.**
- `<lang>-security-and-quality.qls` — security-extended plus
  correctness/maintainability/readability. Noisy for pure security review.

Example:

```bash
codeql database analyze /tmp/db-example \
  codeql/javascript-queries:codeql-suites/javascript-security-extended.qls \
  --format=sarif-latest --output=js.sarif --sarif-category=javascript \
  --threads=0 --ram=8192 --download --sarif-add-snippets
```

## Flags that matter

| Flag | Use |
|---|---|
| `--format` | `sarif-latest` (SARIF 2.1.0) for machine handoff; `csv` for a quick look; `sarifv2.1.0` explicit pin. |
| `--output` | Results file path. |
| `--sarif-category` | Run identity when merging multi-language/multi-config SARIF (`runAutomationDetails.id`). |
| `--download` | Fetch missing query packs from the registry before running. |
| `--threads=0` | All cores. |
| `--ram=<MB>` | Evaluator memory cap; raise to 8000–16000 for big Java/C++ DBs. |
| `--sarif-add-snippets` | Embed code snippets around each location — helps downstream triage without a checkout. |
| `--max-paths=<n>` | Max code-flow paths per result (default 4). |
| `--rerun` | Re-evaluate queries even if cached results exist. |
| `--sarif-add-query-help` | Embed query help markdown into SARIF. |
| `--no-print-diagnostics-summary` / `--print-metrics-summary` | Output tuning. |

## Related subcommands

```bash
codeql database interpret-results <db> --format=sarif-latest --output=r.sarif <queries>
#   re-render SARIF from cached raw results (BQRS) without re-evaluating
codeql database run-queries <db> <queries>      # evaluate only, keep BQRS
codeql bqrs decode --format=csv <file.bqrs>     # inspect raw results
codeql generate query-help <query.ql> --format=markdown
```

## Severity & CWE in the output

Each rule in `runs[].tool.driver.rules[]` (or `tool.extensions[].rules[]`) has:
- `properties.security-severity` — numeric string `"0.0"`–`"10.0"`
  (critical ≥9.0, high ≥7.0, medium ≥4.0, low <4.0),
- `properties.tags` — includes `security` and `external/cwe/cwe-NNN`
  (sometimes multiple CWEs),
- `defaultConfiguration.level` — `error`/`warning`/`note`,
- `properties.precision` — `very-high`/`high`/`medium`/`low`; weigh medium-
  precision results from security-extended accordingly.

Browse the full query catalog + CWE coverage per language in the
`github/codeql` repository (`<lang>/ql/src/Security/CWE-*/`) or the published
"CodeQL query help" docs. `codeql resolve queries <suite>` tells you exactly
what will run against your DB.
