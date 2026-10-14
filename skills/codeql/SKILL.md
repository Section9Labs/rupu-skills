---
name: codeql
description: Deep interprocedural security code review with the GitHub CodeQL CLI — build a database from source, run the standard security query suites or custom taint-tracking queries, and parse SARIF code-flow paths (source→sink) into triageable work units. Use when semgrep-style intrafile matching is not enough — taint through many functions/files, framework-aware dataflow, injection/deserialization/SSRF chains across a whole codebase.
license: MIT
metadata:
  author: Section9Labs
---

# CodeQL — interprocedural dataflow code review

CodeQL compiles the target codebase into a relational database and runs
declarative QL queries over it. Its killer feature versus pattern scanners is
**global taint tracking**: a finding comes with a *code flow* — the ordered
chain of locations from the untrusted source to the dangerous sink, across
function and file boundaries. That path is the triage gold; preserve it.

## 1. Install & verify

Prefer the **CLI bundle** (CLI + precompiled standard query packs — much
faster first run than standalone CLI, which must download/compile packs):

```bash
# Linux x64 bundle (also: osx64, win64)
curl -LO https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
tar xzf codeql-bundle-linux64.tar.gz && export PATH="$PWD/codeql:$PATH"

codeql version
codeql resolve languages    # extractors available: cpp, csharp, go, java, javascript, python, ruby, swift, actions
codeql resolve packs        # query packs on the search path
codeql resolve qlpacks      # legacy name; shows pack locations
```

Supported languages: `cpp` (C/C++), `csharp`, `go`, `java` (also Kotlin),
`javascript` (also TypeScript), `python`, `ruby`, `swift`, `actions`
(GitHub Actions workflows). TypeScript rides on `javascript`; Kotlin on `java`.

Standalone CLI only? Pull packs on demand:
`codeql pack download codeql/python-queries codeql/java-queries` (add
`@x.y.z` to pin a version).

## 2. Build the database

```bash
codeql database create /tmp/db-example --language=python --source-root=/src/example.com-app --overwrite
```

- **Interpreted languages** (`python`, `javascript`, `ruby`, `actions`): no
  build needed — the extractor walks the source tree. Fast.
- **Compiled languages** (`java`, `cpp`, `go`, `csharp`, `swift`): CodeQL
  must *trace a real build* so it sees exactly the code that compiles:

```bash
codeql database create /tmp/db-java  --language=java --source-root=/src/app \
  --command='mvn clean package -DskipTests' --overwrite
codeql database create /tmp/db-cpp   --language=cpp  --source-root=/src/app \
  --command='make -j8' --overwrite
codeql database create /tmp/db-go    --language=go   --source-root=/src/app \
  --command='go build ./...' --overwrite
```

Omit `--command` and CodeQL attempts **autobuild** (heuristic; works for
standard mvn/gradle/msbuild layouts, fails on exotic builds). The build must
actually compile — do a clean first; incremental builds that compile nothing
yield near-empty databases.

**Multi-language repo** — one pass, one DB per language:

```bash
codeql database create /tmp/dbs --db-cluster --language=javascript,python,go \
  --source-root=/src/app --overwrite
# produces /tmp/dbs/javascript, /tmp/dbs/python, /tmp/dbs/go
```

Useful knobs: `--threads=0` (all cores), `--ram=<MB>`, `--no-run-unnecessary-builds`,
`-O extraction-option=value`. Per-language build recipes (gradle, cmake,
bazel wrappers, .NET, filters to scan a subset): `references/database-create.md`.

## 3. Analyze with the security suites

```bash
codeql database analyze /tmp/db-example \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=results.sarif \
  --sarif-category=python --threads=0 --download
```

Suite choice (per language `<lang>`):

| Suite | Contents |
|---|---|
| `code-scanning` (default — just name the pack, e.g. `codeql/python-queries`) | High-precision security queries |
| `<lang>-security-extended.qls` | + lower-precision/experimental security queries — **use this for audits** |
| `<lang>-security-and-quality.qls` | security-extended + maintainability/quality noise |

- `--download` auto-fetches missing packs; or pre-fetch with
  `codeql pack download codeql/<lang>-queries`.
- `--sarif-category` distinguishes runs when you merge SARIF from several
  languages into one file/upload.
- `--format=sarif-latest` → SARIF 2.1.0. Also handy: `--format=csv` for a
  quick eyeball, `--print-metrics-summary`.
- Scale: `--threads=0 --ram=6000` (MB). Large Java/C++ DBs want 8–16 GB RAM.
- Run a **single query**: pass a `.ql` path instead of a suite. Run a whole
  pack at a pinned version: `codeql/java-queries@1.1.0`.

Full flag reference, suite catalog, and CWE coverage pointers:
`references/analyze-and-suites.md`. The standard packs implement queries for
the usual CWE top set (SQLi CWE-089, command injection CWE-078, path traversal
CWE-022, XSS CWE-079, deserialization CWE-502, SSRF CWE-918, XXE CWE-611,
crypto CWE-327/338, etc.) — each query's `@tags` carry `external/cwe/cwe-NNN`.

## 4. Custom queries when the standard suites miss your sink

When the app has bespoke sources (custom RPC layer) or sinks (in-house SQL
wrapper), write a small taint-tracking query — ~30 lines of QL:

```bash
codeql pack init myorg/audit-queries --dir=audit-queries   # writes qlpack.yml
cd audit-queries && codeql pack install                     # resolves codeql/<lang>-all dep
codeql database analyze /tmp/db-example ./audit-queries \
  --format=sarif-latest --output=custom.sarif
```

Core QL shape: define `isSource` (remote input, `RemoteFlowSource`),
`isSink` (argument to your dangerous call), instantiate
`TaintTracking::Global<Config>`, select `source, sink` with a `@kind path-problem`
header so SARIF gets code flows. Minimal working example, qlpack.yml anatomy,
quick-eval workflow, and model-extension packs: `references/custom-queries.md`.

## 5. Read the SARIF

Per result in `runs[].results[]`:
- `ruleId` (e.g. `py/sql-injection`), `message.text`,
  `locations[0].physicalLocation` → file + startLine (the **sink**).
- `codeFlows[].threadFlows[].locations[]` — ordered source→sink steps. A
  finding with a code flow is near-certainly a true dataflow; triage effort
  goes into exploitability of the sink, not whether the flow exists.
- Rule metadata in `runs[].tool.driver.rules[]` (and `tool.extensions[]`):
  `properties.security-severity` (CVSS-ish 0–10), `properties.tags` with
  `external/cwe/cwe-NNN`, `defaultConfiguration.level`.

## 6. Gotchas

- **Compiled build fails** → no DB. Fix the build first (JDK version, deps,
  `--command='./build.sh'` wrapping anything). Check
  `<db>/log/database-create-*.log`. A DB with ~0 lines of code means the
  traced build compiled nothing.
- **Wrong language choice**: TS→`javascript`, Kotlin→`java`. For mixed repos
  always `--db-cluster`.
- **Time/size**: DB creation on big Java/C++ monorepos is the long pole
  (build time + extraction). Analyze is CPU/RAM bound — `--threads=0`, raise
  `--ram`.
- **Subset scanning**: interpreted langs — point `--source-root` at the
  subdir, or use extractor filters (see `references/database-create.md`);
  compiled langs — trace a build of just the target module
  (`--command='mvn -pl service-a package'`).
- Re-running `database create` on an existing dir needs `--overwrite`.

## 7. One-shot pipeline + handoff (rupu)

```bash
python3 scripts/run_codeql.py --language python --source-root /src/example.com-app \
  --db /tmp/db-example --suite security-extended \
  --sarif results.sarif --output workunits.json
# or parse an existing SARIF:
python3 scripts/codeql_sarif_to_workunits.py results.sarif -o workunits.json
```

`workunits.json` is a **clean top-level JSON array** of
`{id, title, targets:["path:line"], hints:{rule, severity, cwe, message, codeflow_steps}}` —
directly consumable by a rupu workflow (`read_file` + `for_each:`) or a lead
agent's `dispatch` fan-out.

Handoff procedure:
1. `assets.mark` the repository, the scanned files/modules (one asset per
   distinct path in the work units), and — if you also ran SCA — the
   dependency packages. Coverage must be trackable.
2. Load the **`work-units`** skill to split/normalize `workunits.json` into
   per-agent work units (don't re-invent the splitter).
3. Route the raw `results.sarif` to the **`sarif-triage`** skill for
   cross-tool dedup and severity normalization.
4. For every work unit an agent **verifies** (walk the codeflow_steps, confirm
   source reachability and sink exploitability, build a PoC input), load the
   **`finding-report`** skill and file it via `findings.report`.

Concrete workflow YAML, `dispatch` pattern, and example `assets.mark` /
`findings.report` calls: `references/rupu.md`.
