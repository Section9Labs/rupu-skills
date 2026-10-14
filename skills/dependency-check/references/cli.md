# Dependency-Check CLI — flags, analyzers, formats, build plugins

Binary names: `dependency-check.sh` (Linux/macOS), `dependency-check.bat`
(Windows), often symlinked as `dependency-check`. Docker:
`owasp/dependency-check` (mount source at `/src`, data cache at
`/usr/share/dependency-check/data`, report dir at `/report`).

```bash
docker run --rm \
  -v /opt/odc-data:/usr/share/dependency-check/data \
  -v "$(pwd)":/src -v "$(pwd)/odc-report":/report \
  owasp/dependency-check \
  --scan /src --format JSON --format SARIF --format HTML \
  --out /report --project example-app --nvdApiKey "$NVD_API_KEY"
```

## Core flags

| Flag | Meaning |
|---|---|
| `--scan <path>` | File/dir/Ant glob to scan. **Repeatable.** Quote globs: `--scan 'app/**/*.jar'` |
| `--out <dir>` | Report output directory (or file path for single format) |
| `--format <F>` | `HTML` (default), `XML`, `JSON`, `SARIF`, `CSV`, `JUNIT`, `JENKINS`, `GITLAB`, `ALL`. **Repeatable.** |
| `--project <name>` | Project name embedded in the report |
| `--prettyPrint` | Pretty-print JSON/XML output |
| `--exclude <glob>` | Ant-style exclude pattern. Repeatable. e.g. `--exclude '**/test/**'` |
| `--symLink <depth>` | Follow symlinks to given depth (default 0) |
| `--suppression <file>` | Suppression XML. **Repeatable.** URLs allowed. |
| `--hints <file>` | Hints XML to *add/correct* evidence (fix bad CPE matching instead of suppressing) |
| `--failOnCVSS <n>` | Exit code 1 if any finding has CVSS ≥ n (default 11 = never) |
| `--junitFailOnCVSS <n>` | In JUNIT format, mark testcases failed at CVSS ≥ n |
| `--enableExperimental` | Enable experimental analyzers (Go, Python source, Dart, Pipfile, etc.) |
| `--enableRetired` | Enable retired analyzers (e.g. raw JS file analysis) |
| `--log <file>` | Verbose log to file (debugging analyzer/CPE decisions) |
| `-d` / `--data <dir>` | H2 database / data cache directory |
| `--noupdate` | Skip NVD/feeds update — pure offline scan from cache |
| `--updateonly` | Only update the database, no scan |
| `--purge` | Delete the local H2 DB (fix corrupt/locked DB), then exit |
| `--dbDriverName/--dbDriverPath/--connectionString/--dbUser/--dbPassword` | External/shared DB (e.g. central PostgreSQL cache for a fleet) |
| `--proxyserver/--proxyport/--proxyuser/--proxypass/--nonProxyHosts` | Proxy for feed downloads |

## NVD flags

| Flag | Meaning |
|---|---|
| `--nvdApiKey <key>` | **Required in practice.** NVD API key |
| `--nvdApiDelay <ms>` | Delay between NVD API calls (raise to 4000–8000 on 403/429) |
| `--nvdMaxRetryCount <n>` | Retries per request |
| `--nvdValidForHours <h>` | Hours before cached NVD data is considered stale (default 4) |
| `--nvdDatafeed <url>` | Mirror URL of pre-generated NVD JSON feed (air-gapped setups) |
| `--nvdUser/--nvdPassword` | Basic auth for a protected datafeed mirror |

## Analyzer toggles

Pattern: `--disable<Analyzer>`. The important ones:

| Flag | Analyzer / ecosystem |
|---|---|
| `--disableJar` | Java JAR (manifest + pom evidence) |
| `--disableCentral` / `--disableCentralCache` | Maven Central hash lookup (precise GAV from sha1) |
| `--disableAssembly` | .NET assembly analyzer (needs `dotnet` 8 runtime — disable if absent to kill errors) |
| `--disableNuspec` / `--disableNugetconf` / `--disableMSBuild` | .NET package manifests |
| `--disableNodeJS` | package.json evidence |
| `--disableNodeAudit` | NPM Audit API lookups (needs `package-lock.json`) |
| `--nodeAuditSkipDevDependencies` | Keep Node Audit but ignore devDependencies |
| `--nodePackageSkipDevDependencies` | Skip devDependencies in package.json analysis |
| `--disableYarnAudit` / `--disablePnpmAudit` | yarn/pnpm audit (need yarn/pnpm on PATH) |
| `--disableRetireJS` / `--retirejsFilterNonVulnerable` | RetireJS for bundled JS files |
| `--disablePyDist` / `--disablePyPkg` | Python wheels/eggs / source packages |
| `--disablePip` / `--disablePipfile` / `--disablePoetry` | requirements.txt / Pipfile.lock / poetry.lock (experimental) |
| `--disableRubygems` / `--disableBundleAudit` / `--bundleAudit <path>` | Ruby gemspec / bundler-audit integration |
| `--disableComposer` / `--composerSkipDev` | PHP composer.lock |
| `--disableGolangDep` / `--disableGolangMod` / `--go <path>` | Go dependencies (mod analyzer runs `go list`, experimental) |
| `--disableCocoapodsAnalyzer` / `--disableSwiftPackageManagerAnalyzer` / `--disableCarthageAnalyzer` | iOS/macOS |
| `--disableDart` | Dart pubspec (experimental) |
| `--disableAutoconf` / `--disableCmake` | Native build systems |
| `--disableArchive` / `--zipExtensions <ext,...>` | Archive expansion (zip/war/ear/tar/rpm/apk...); add custom extensions |
| `--disableOpenSSL` | OpenSSL version source header |
| `--disableOssIndex` / `--ossIndexUsername/--ossIndexPassword` / `--ossIndexRemoteErrorWarnOnly` | Sonatype OSS Index (purl-based advisories; auth strongly recommended, anonymous is rate-limited) |
| `--disableKnownExploited` / `--kevURL <url>` | CISA KEV flagging |
| `--disableVersionCheck` | Don't check for a newer ODC version |

Hash-only fallback: unknown binaries still get md5/sha1/sha256 recorded —
useful for manual lookups even when no analyzer claims the file.

## Scan-target strategy

- Scan **source + lockfiles** (`package-lock.json`, `poetry.lock`,
  `composer.lock`, `go.mod`, `Gemfile.lock`) for the declared tree.
- Scan **built artifacts** (`target/*.jar`, `build/libs/`, `*.war`, `*.ear`,
  `dist/`, `node_modules/` if vendored, extracted container layers) for what
  actually ships — fat/shaded jars and vendored copies hide deps from
  manifests. Archives are auto-expanded.
- For Java, prefer the **Maven/Gradle plugin** when a build is available: it
  sees the resolved dependency graph (versions after conflict mediation),
  which is strictly more accurate than filesystem heuristics.

## Maven plugin

```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>USE_LATEST</version>
  <configuration>
    <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
    <formats><format>HTML</format><format>JSON</format><format>SARIF</format></formats>
    <suppressionFiles><suppressionFile>suppressions.xml</suppressionFile></suppressionFiles>
    <failBuildOnCVSS>7</failBuildOnCVSS>
  </configuration>
</plugin>
```

```bash
mvn org.owasp:dependency-check-maven:check          # per module
mvn org.owasp:dependency-check-maven:aggregate      # multi-module rollup
mvn org.owasp:dependency-check-maven:update-only
mvn org.owasp:dependency-check-maven:purge
```

Reports land in `target/`. Same JSON/SARIF schema as the CLI — feed them to
`scripts/depcheck_to_workunits.py` unchanged.

## Gradle plugin

```groovy
plugins { id 'org.owasp.dependencycheck' version 'USE_LATEST' }
dependencyCheck {
    nvd { apiKey = System.getenv('NVD_API_KEY'); delay = 4000 }
    formats = ['HTML', 'JSON', 'SARIF']
    suppressionFile = 'suppressions.xml'
    failBuildOnCVSS = 7
    analyzers { assemblyEnabled = false }
}
```

```bash
./gradlew dependencyCheckAnalyze     # current project
./gradlew dependencyCheckAggregate   # all subprojects
./gradlew dependencyCheckUpdate
./gradlew dependencyCheckPurge
```

Reports in `build/reports/`.
