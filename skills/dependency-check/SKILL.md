---
name: dependency-check
description: Run OWASP Dependency-Check for software composition analysis (SCA) - identify third-party dependencies across ecosystems (Java, .NET, npm, Python, Ruby, PHP, Go, native), match them to CPEs, and surface known CVEs from the NVD plus NPM Audit, RetireJS, OSS Index and CISA KEV; use when auditing a codebase or artifact tree for vulnerable dependencies, then normalize the JSON/SARIF report into work units for triage and exploitation.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# OWASP Dependency-Check (SCA)

## What it is

Dependency-Check is a multi-ecosystem software composition analysis tool. It
walks a scan path, runs **analyzers** that identify dependencies and collect
**evidence** (vendor/product/version strings from manifests, pom properties,
assembly metadata, package.json, filenames, jar manifests, hashes), then
matches that evidence to a **CPE** (Common Platform Enumeration) identifier.
Each matched CPE is cross-referenced against the **NVD** CVE database (cached
locally in an H2 database) and augmented by other sources:

- **NPM Audit** / **Node Audit** — npm advisory data for `package-lock.json`.
- **RetireJS** — known-vulnerable JavaScript libraries (bundled/minified JS).
- **OSS Index** (Sonatype) — package-coordinate (purl) based advisories; often
  more precise than CPE matching.
- **CISA KEV** — flags CVEs on the Known Exploited Vulnerabilities list
  (`isKev` in the report). Treat KEV hits as top priority: public, weaponized.

Analyzers exist for Java (`.jar`, `pom.xml`), .NET (assemblies,
`packages.config`, `*.csproj`, `.nuspec`), npm/yarn/pnpm, Python
(`requirements.txt`, `setup.py`, wheels/eggs, `Pipfile.lock`, `poetry.lock`),
Ruby (`Gemfile.lock`, gemspecs), PHP (`composer.lock`), Go (`go.mod`), Swift,
CocoaPods, Dart, autoconf/CMake for native code, and archive unpacking
(zip/war/ear/tar/rpm/apk/nupkg are expanded and scanned recursively). Several
analyzers (Go, Python, Dart, some others) are gated behind
`--enableExperimental`; `--enableRetired` adds retired analyzers.
See `references/cli.md` for the full analyzer and flag list.

## Core run (CLI)

```bash
dependency-check.sh \
  --scan /src/example-app \
  --scan /src/example-lib \
  --format SARIF --format JSON --format HTML \
  --out ./odc-report \
  --project "example-app" \
  --enableExperimental \
  --nvdApiKey "$NVD_API_KEY" \
  --prettyPrint
```

- `--scan` is repeatable and accepts files, directories, or Ant-style globs
  (`'src/**/*.jar'` — quote them). Point it at the repo root AND at any built
  artifacts (`target/`, `build/libs/`, `dist/`, published containers' extracted
  filesystems) — built artifacts expose shaded/bundled deps the manifests hide.
- `--format` is repeatable: `HTML`, `JSON`, `SARIF`, `XML`, `CSV`, `JUNIT`,
  `JENKINS`, `GITLAB`, or `ALL`. Always emit **JSON + SARIF** for machine
  handoff and **HTML** for human review.
- Useful toggles: `--nodeAuditSkipDevDependencies` (ignore devDeps in npm
  audit), `--disableNodeAudit`, `--disableAssembly` (if `dotnet` runtime is
  absent, this silences errors), `--disableRetireJS`, `--disableOssIndex`.
  Every analyzer has a `--disable<Name>` switch (`references/cli.md`).
- Exit code is non-zero on errors; add `--failOnCVSS 7` to make the exit code
  itself signal "CVSS ≥ 7 found" (useful in CI gates; default 11 = never fail).

Or use the helper, which wires formats, the NVD key, and the parser:

```bash
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
python3 scripts/run_depcheck.py --scan /src/example-app --out ./odc-report \
    --project example-app --workunits ./workunits.json -- --enableExperimental
```

## CRITICAL: NVD API key and the local data cache

The NVD switched to a key-gated API. **Without `--nvdApiKey` the initial
database build takes hours and gets throttled/403'd.** Get a key (free, from
nvd.nist.gov), export it, and pass it on every update. Tune `--nvdApiDelay`
(ms between API calls; raise to 4000–8000 if you see 403/429) and
`--nvdMaxRetryCount`.

The CVE data is cached in a local H2 DB (default under the install's `data/`
dir; override with `--data /path/to/odc-data` to share a cache across runs
and containers). Workflow:

```bash
# one-time / nightly: refresh the DB only, no scan
dependency-check.sh --updateonly --nvdApiKey "$NVD_API_KEY" --data /opt/odc-data

# every scan afterwards: pure offline, fast
dependency-check.sh --noupdate --data /opt/odc-data --scan /src/example-app \
  --format SARIF --format JSON --out ./odc-report --project example-app
```

If a run dies mid-update the H2 DB can be left locked/corrupt — `--purge`
deletes it so the next update rebuilds clean. OSS Index works anonymously but
rate-limits hard; set `--ossIndexUsername/--ossIndexPassword` for real use.
Full details: `references/nvd-and-suppression.md`.

## Suppression — mandatory FP control

CPE matching is fuzzy and Dependency-Check is **prone to wrong-CPE false
positives** (e.g. an internal `commons-utils.jar` matched to
`cpe:/a:apache:commons_*`, or a client library matched to the server's CPE).
Maintain a suppression file and pass `--suppression suppressions.xml`
(repeatable). Suppress by `sha1`/`packageUrl`/`filePath` (regex supported)
plus `cpe`, `cve`, or `vulnerabilityName`, optionally with `until=` expiry:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
  <suppress>
    <notes>Internal jar, not Apache Commons - wrong CPE. vulture/cobalt-mill</notes>
    <sha1>384faa82e193d4e4b0546059ca09572654bc3970</sha1>
    <cpe>cpe:/a:apache:commons_fileupload</cpe>
  </suppress>
  <suppress until="2026-01-01Z">
    <notes>CVE affects server component only; this is the client lib.</notes>
    <packageUrl regex="true">^pkg:maven/com\.example/.*-client@.*$</packageUrl>
    <cve>CVE-2021-44228</cve>
  </suppress>
</suppressions>
```

The HTML report has a per-finding "suppress" button that generates the XML
block for you. Schema and more patterns: `references/nvd-and-suppression.md`.

## Reading the output

In the JSON report (`dependency-check-report.json`), each entry in
`dependencies[]` has:

- `fileName` / `filePath` — the artifact. `isVirtual: true` means it came from
  a lockfile/manifest, not a physical binary.
- `packages[]` — purl identifiers (`pkg:maven/...@2.9.10`) with `confidence`.
- `vulnerabilityIds[]` — the matched **CPE(s)** with confidence
  (`LOW`/`MEDIUM`/`HIGH`/`HIGHEST`). **This is where FPs are born** — a LOW
  confidence CPE with a vendor that doesn't match the purl is almost always
  a mismatch.
- `vulnerabilities[]` — per CVE: `name`, `source` (NVD/NPM/OSSINDEX/RETIREJS),
  `severity`, `cvssv3.baseScore`/`cvssv2`, `cwes[]`, `description`,
  `vulnerableSoftware[]` (the version ranges), and KEV flags.

Triage order per finding:
1. **Is the CPE right?** Compare `vulnerabilityIds[].id` vendor/product to the
   purl / jar manifest. OSS Index hits (purl-based) rarely mislabel; NVD/CPE
   hits do. Wrong CPE → suppress by sha1/packageUrl + cpe.
2. **Is the version in range?** Check `vulnerableSoftware` against the actual
   version. Shaded/relocated jars may report the wrong version.
3. **Is the vulnerable code reachable?** Grep the codebase for use of the
   affected class/function/endpoint (the CVE description and references name
   them). A present-but-unused dep is lower priority but still reportable.
4. **Exploitability**: KEV flag, public PoC in `references[]`, CVSS vector
   (network/no-auth first). Confirmed-reachable KEV/CVSS≥9 deps are immediate
   exploitation candidates (e.g. Log4Shell, jackson-databind gadget chains,
   Struts OGNL, vulnerable minified jQuery with DOM XSS sinks).

## Normalize and hand off (rupu)

1. Parse the report into clean work units:

```bash
python3 scripts/depcheck_to_workunits.py \
  --json ./odc-report/dependency-check-report.json \
  --sarif ./odc-report/dependency-check-report.sarif \
  --out ./workunits.json --min-cvss 0
```

   This writes a top-level JSON array
   `[{"id","title","targets":["<dependency>"],"hints":{"cve","cvss","severity","cwe","cpe","purl","confidence","source","kev",...}}, ...]`
   sorted KEV-first then CVSS-desc, so `for_each:` can consume it directly.
2. `assets.mark` the repository, each scanned path, and **each dependency
   package** (purl) as covered assets — see `references/rupu.md` for the exact
   calls.
3. Load the `work-units` skill to split/batch the normalized findings in
   `workunits.json` into per-agent work units and fan out with `dispatch`.
4. Each agent verifies its unit (CPE sanity → version range → reachability →
   exploit), then loads the `finding-report` skill and files every verified
   issue with `findings.report`.
5. Route the SARIF file (`dependency-check-report.sarif`) to the
   `sarif-triage` skill for cross-tool dedup/merge with other scanners'
   SARIF output.

Workflow YAML, `dispatch` pattern, and example `assets.mark`/`findings.report`
calls live in `references/rupu.md`.

## Build-tool equivalents

- **Maven**: `mvn org.owasp:dependency-check-maven:check` — resolves the real
  dependency tree (better than filesystem scanning for Java). Same config via
  `<configuration>`; aggregate goal for multi-module builds.
- **Gradle**: plugin `org.owasp.dependencycheck`, task `dependencyCheckAnalyze`
  / `dependencyCheckAggregate`.
Details and config snippets: `references/cli.md`.
