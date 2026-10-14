---
name: code-review
description: Umbrella/router skill for authorized security code review of a source repository — triage the repo, then route to the right SAST, secret-scanning, SCA/SBOM, and taint-analysis sub-skills by name, normalize everything to one deduplicated finding set, and emit rupu-ingestible work units; load this first for any code-review engagement to get the end-to-end flow and know which sub-skill to load at each step.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Security Code Review — Umbrella / Router

This is the routing map for the full code-review pack (SAST + secrets + SCA + taint).
Follow the phases in order. At each step this skill names the sub-skill to **load by
name** for depth; do not improvise per-tool flags here — the sub-skill owns them.
Every phase ends by producing rupu-ingestible output (clean JSON array of work units,
`assets.mark` coverage, `findings.report` for verified issues). Wiring details:
`references/rupu.md`. Full command-level narrative: `references/flow.md`.
Language/ecosystem routing tables: `references/tool-matrix.md`.

## The flow at a glance

```
PHASE 0  profile repo ──> repo-profile.json + initial plan (work units)
PHASE 1  SAST          ──> semgrep, codeql, bandit/gosec/brakeman/njsscan/find-sec-bugs ──> SARIF
PHASE 2  secrets       ──> gitleaks + trufflehog (worktree AND full git history)
PHASE 3  SCA/SBOM      ──> grype-syft, osv-scanner, dependency-check, retire-js, cargo-audit
PHASE 4  taint         ──> taint-analysis (source->sink, semgrep taint-mode, codeql dataflow)
PHASE 5  triage        ──> sarif-triage ──> work-units ──> verify ──> finding-report + assets.mark
```

## PHASE 0 — Triage the repository (attack-surface profile)

Goal: know what the repo *is* before pointing tools at it — languages, frameworks,
build systems, dependency manifests, entry points, trust boundaries.

1. Run the profiler:
   ```
   python3 scripts/profile_repo.py /path/to/repo -o repo-profile.json
   ```
   It censuses file extensions into languages with LOC estimates, detects every
   dependency manifest (`requirements.txt`, `poetry.lock`, `Pipfile`, `package.json`,
   `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`/`go.sum`, `pom.xml`,
   `build.gradle[.kts]`, `Gemfile[.lock]`, `Cargo.toml`/`Cargo.lock`, `composer.json`,
   `*.csproj`), and flags likely entry points by name/content heuristics (HTTP
   routes/handlers, CLI mains, deserialization, template rendering, raw SQL, auth code).
   If `scc`, `tokei`, or `cloc` is installed, cross-check the census
   (`scc --format json`, `tokei -o json`, `cloc --json .`) — the profiler is the
   fallback when none are present.
2. Read the profile. Decide trust boundaries: where does untrusted input enter
   (HTTP params/bodies, headers, queue messages, CLI args, file uploads, env), and
   which modules sit on that boundary. Note these in the profile's `entry_points`.
3. Generate the initial plan — one work unit per tool-to-run for the detected stack:
   ```
   python3 scripts/plan_review.py repo-profile.json -o plan.json
   ```
   `plan.json` is a clean top-level JSON array `[{id,title,targets,hints},...]`
   ready for rupu `for_each:` or a lead's `dispatch` (see `references/rupu.md`).
4. Mark coverage now: `assets.mark` the repository asset and the top-level modules
   you intend to scan (shapes in `references/rupu.md`).

## PHASE 1 — SAST (route by language/stack)

Always start broad, then go deep on high-value code. See `references/tool-matrix.md`
for the full language → tool table.

- **Load the `semgrep` skill** first — multi-language, fast, community + per-language
  rulesets (`p/default`, `p/security-audit`, `p/owasp-top-ten`, language packs) plus
  custom rules for app-specific patterns. Run it over the whole repo regardless of stack.
- **Load the `codeql` skill** for deep interprocedural dataflow on the high-value
  targets identified in Phase 0 (auth, payment, deserialization, anything on a trust
  boundary): build a database per language, run the `security-extended` /
  `security-and-quality` query packs.
- Language-specific deep linters, per detected language:
  - Python → **load the `bandit` skill**
  - Go → **load the `gosec` skill**
  - Ruby/Rails → **load the `brakeman` skill**
  - JavaScript/Node → **load the `njsscan` skill**
  - Java/JVM (incl. Kotlin/Scala bytecode) → **load the `find-sec-bugs` skill**

Run every tool with SARIF output. Collect all SARIF files into one directory —
they are consumed in Phase 5 by the `sarif-triage` skill. Hand off: for each SAST
run, **load the `sarif-triage` skill** to normalize its SARIF, then **load the
`work-units` skill** to split the normalized findings into work units.

## PHASE 2 — Secret scanning

Scan the **working tree AND the full git history** — rotated files still live in
old commits.

- **Load the `gitleaks` skill**: fast full-history scan (`gitleaks git`) plus
  worktree scan (`gitleaks dir`), JSON/SARIF report.
- **Load the `trufflehog` skill**: detector-based scan with **live credential
  verification** (`trufflehog git file://. --json`) — verified hits are
  confirmed-valid credentials and go straight to `findings.report` at high/critical.

Normalize both tools' JSON through the `sarif-triage` skill alongside the SARIF.

## PHASE 3 — SCA + SBOM (dependency vulnerabilities)

Route by the ecosystems found in Phase 0 (`repo-profile.json: ecosystems`).

- **Load the `grype-syft` skill**: generate the SBOM with syft
  (`syft dir:. -o cyclonedx-json`), scan it with grype. The SBOM is also the
  package-asset inventory — `assets.mark` every package from it.
- **Load the `osv-scanner` skill**: lockfile-accurate scan against OSV.dev
  (`osv-scanner scan source -r . --format sarif`).
- Multi-ecosystem cross-check: **load the `dependency-check` skill** (OWASP, NVD-backed).
- Ecosystem-specific:
  - JS/front-end bundles and vendored libs → **load the `retire-js` skill**
  - Rust → **load the `cargo-audit` skill** (RUSTSEC advisories)

All SCA output flows into Phase 5 normalization. Reachability check during
verification: a vulnerable dependency whose vulnerable function is actually called
from app code outranks one that is merely declared.

## PHASE 4 — Taint / source→sink analysis

- **Load the `taint-analysis` skill.** It covers: the manual source→sink
  methodology (enumerate sources from the Phase 0 entry points, enumerate sinks,
  walk the dataflow), semgrep taint-mode rules (`mode: taint` with
  `pattern-sources`/`pattern-sinks`/`pattern-sanitizers`), codeql dataflow queries,
  and ripgrep sink-pattern packs per language.
- Target classes: injection (SQLi / command / LDAP / template injection), insecure
  deserialization, SSRF, path traversal, authorization gaps (IDOR, missing checks),
  crypto misuse, hardcoded secrets.
- Prioritize paths that start at a Phase 0 entry point and end in a sink inside a
  high-value module. Each traced source→sink path becomes a work unit with the full
  path in `hints`.

## PHASE 5 — Triage, verify, report

1. **Load the `sarif-triage` skill.** Feed it *every* output from Phases 1–4
   (SARIF and native JSON). It normalizes, deduplicates (same rule + file + line
   region across tools), and severity-ranks into one finding set.
2. **Load the `work-units` skill** to split the normalized set into the final
   work-unit inventory — ONE clean top-level JSON array
   `[{"id","title","targets":["path:line",...],"hints":{"rule","severity","cwe",...}},...]`
   written to a file (e.g. `work-units.json`). This is the fan-out artifact: a rupu
   workflow consumes it with `read_file` + `for_each:`; a lead agent fans out with
   `dispatch`. Snippets in `references/rupu.md`.
3. Verify each candidate against the source: open the flagged code, confirm the
   source→sink path or vulnerable config is real and reachable, build a PoC input
   where practical, discard false positives with a one-line reason.
4. **Load the `finding-report` skill** to file each verified issue via rupu
   `findings.report` (title, severity, CWE, file:line, dataflow trace, PoC,
   remediation).
5. Close coverage: `assets.mark` the repository, every file/module scanned, and
   every dependency package from the SBOM — scanned-clean assets count as coverage
   too. Shapes in `references/rupu.md`.

## Routing quick reference

| Need | Load skill |
|---|---|
| Broad multi-language SAST | `semgrep` |
| Deep interprocedural dataflow | `codeql` |
| Python / Go / Rails / Node / JVM SAST | `bandit` / `gosec` / `brakeman` / `njsscan` / `find-sec-bugs` |
| Secrets (history) / secrets (verified) | `gitleaks` / `trufflehog` |
| SBOM + vuln scan / OSV lockfile scan | `grype-syft` / `osv-scanner` |
| Multi-ecosystem SCA / JS libs / Rust | `dependency-check` / `retire-js` / `cargo-audit` |
| Source→sink methodology | `taint-analysis` |
| Normalize + dedup all output | `sarif-triage` |
| Split into work units | `work-units` |
| File verified issues | `finding-report` |
