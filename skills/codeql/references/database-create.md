# codeql database create — per-language recipes

General form:

```bash
codeql database create <db-dir> \
  --language=<lang> \
  --source-root=<src> \
  [--command='<build command>'] \
  [--db-cluster] [--overwrite] [--threads=0] [--ram=<MB>] \
  [--no-run-unnecessary-builds] [--codescanning-config=<file>] \
  [-O <extractor-option>=<value>]
```

Key flags:

| Flag | Meaning |
|---|---|
| `--language` | Extractor to use. With `--db-cluster`, comma-separated list. |
| `--source-root` | Checkout root. Defaults to cwd. Paths in SARIF are relative to this. |
| `--command` / `-c` | Build command to trace (compiled langs). Repeatable for multi-step builds. Quote the whole command. |
| `--db-cluster` | Create a parent dir with one sub-database per language. |
| `--overwrite` | Replace an existing database directory. |
| `--no-run-unnecessary-builds` | In a cluster, skip the build if only interpreted languages need it. |
| `--begin-tracing` / indirect tracing | For builds you must drive manually (IDE-driven, distributed): `codeql database init --begin-tracing`, source the generated env script, run the build yourself, then `codeql database finalize`. |
| `-O key=value` | Extractor options, e.g. `-O python.python_executable_name=python3`. |
| `--codescanning-config` | YAML config (paths/paths-ignore, packs, queries) in code-scanning format. |

A finished DB is finalized automatically by `database create`. Inspect with
`codeql database print-baseline <db>` (lines of code seen — sanity-check it's
not ~0) and `codeql resolve database <db>`.

## Interpreted languages — no build

```bash
# Python (2/3 auto-detected; venv deps are not required but help resolve imports)
codeql database create db-py --language=python --source-root=/src/app

# JavaScript + TypeScript (TS compiled by the extractor automatically)
codeql database create db-js --language=javascript --source-root=/src/app

# Ruby
codeql database create db-rb --language=ruby --source-root=/src/app

# GitHub Actions workflows (.github/workflows/*.yml)
codeql database create db-actions --language=actions --source-root=/src/app
```

Scan a subset: either point `--source-root` at the subdirectory, or pass a
code-scanning config:

```yaml
# config.yml
paths:
  - services/payments
paths-ignore:
  - "**/test/**"
  - "**/node_modules/**"
```

```bash
codeql database create db-js --language=javascript --source-root=/src/app \
  --codescanning-config=config.yml
```

(JS extractor env alternative: `LGTM_INDEX_FILTERS=$'exclude:**/*.min.js'`.)

## Java / Kotlin

Build must compile cleanly under a traceable JDK. Set `JAVA_HOME` to match
the project.

```bash
# Maven — always a clean build; skip tests to save time
codeql database create db-java --language=java --source-root=/src/app \
  --command='mvn clean package -DskipTests -B'

# Only one module of a monorepo
codeql database create db-java --language=java --source-root=/src/app \
  --command='mvn -pl services/payments -am clean package -DskipTests -B'

# Gradle — disable the daemon so tracing sees compiler invocations
codeql database create db-java --language=java --source-root=/src/app \
  --command='./gradlew --no-daemon clean assemble'

# Ant / plain javac / custom script
codeql database create db-java --language=java --source-root=/src/app \
  --command='./build.sh'
```

Kotlin sources are extracted by the `java` extractor during the same traced
build. Autobuild (no `--command`) recognizes maven/gradle wrappers and pom/
build.gradle at the root.

## C / C++

```bash
codeql database create db-cpp --language=cpp --source-root=/src/app \
  --command='make -j8'

# CMake — configure first (untraced is fine), trace the actual compile
cmake -S /src/app -B /src/app/build
codeql database create db-cpp --language=cpp --source-root=/src/app \
  --command='cmake --build /src/app/build -j8'

# Multi-step: repeat --command
codeql database create db-cpp --language=cpp --source-root=/src/app \
  --command='./configure' --command='make -j8'
```

Clean before tracing (`make clean`) — only compilations that *run* are
extracted. ccache/distcc can hide compiler calls; disable them
(`CCACHE_DISABLE=1`). Bazel: wrap in a script that runs
`bazel build --spawn_strategy=local //...` so compilers run in-process.

## Go

```bash
codeql database create db-go --language=go --source-root=/src/app \
  --command='go build ./...'
```

Autobuild handles standard module layouts (`go.mod` at root). Vendored or
multi-module repos: give explicit `--command`, or repeat it per module.
Ensure `GOFLAGS`/private module auth are set so `go build` succeeds.

## C#

```bash
codeql database create db-cs --language=csharp --source-root=/src/app \
  --command='dotnet build /t:rebuild /p:UseSharedCompilation=false'
# or msbuild / nuget restore first:
codeql database create db-cs --language=csharp --source-root=/src/app \
  --command='nuget restore' --command='msbuild /t:Rebuild'
```

`UseSharedCompilation=false` matters: the shared Roslyn compiler server dodges
tracing. Recent CLI versions also support **build-mode none** for C#/Java
(`--build-mode=none`) — extraction without a build; faster and tolerant of
broken builds, at some precision cost. Good fallback when you cannot make the
build work.

## Swift

macOS host; trace xcodebuild or swift build:

```bash
codeql database create db-swift --language=swift --source-root=/src/app \
  --command='xcodebuild build -scheme App CODE_SIGNING_ALLOWED=NO'
```

## Multi-language cluster

```bash
codeql database create /tmp/dbs --db-cluster \
  --language=java,javascript,python --source-root=/src/app \
  --command='mvn clean package -DskipTests -B' --overwrite
```

The `--command` applies to the compiled languages; interpreted extractors run
regardless. Analyze each sub-DB separately with a per-language suite and a
distinct `--sarif-category`.

## Troubleshooting

- `<db>/log/database-create-*.log` and `<db>/log/build-tracer*.log` show what
  the tracer saw. No compiler invocations logged ⇒ build didn't compile or
  tracing was bypassed (daemon, shared compilation, ccache, containers).
- Builds inside Docker: run `codeql database create` *inside* the same
  container as the build, or use indirect tracing.
- "Language X is not supported" ⇒ standalone CLI without extractor bundle;
  install the full bundle.
- Databases are directories; archive with `codeql database bundle <db> -o db.zip`
  to move between hosts.
