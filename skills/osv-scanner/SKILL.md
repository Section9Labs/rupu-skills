---
name: osv-scanner
description: Run Google OSV-Scanner v2 against repositories, lockfiles, SBOMs and container images to match dependencies against the OSV.dev vulnerability database; normalize results (SARIF/JSON) into work units for triage and fan-out. Use for the SCA step of a code review when a repo has lockfiles/manifests or an SBOM exists.
license: Apache-2.0
metadata:
  author: Section9Labs
  tool: osv-scanner
  tool_version: "v2"
---

# OSV-Scanner v2 — SCA over the OSV.dev database

OSV-Scanner matches a project's dependency inventory (lockfiles, manifests,
SBOMs, container images) against OSV.dev, which aggregates GitHub Security
Advisories, PyPA, RustSec, Go vulndb, and distro feeds into a single
ecosystem-native format. It is the fastest, broadest SCA pass; pair it with
the `grype-syft` skill (Syft SBOM + Grype) to cross-check matches and to get
an SBOM artifact you can keep.

## Workflow

### 1. Scan

Recursive source scan (default mode — `scan source` is implied):

```sh
osv-scanner scan source -r /work/example-repo \
  --format sarif --output osv.sarif
osv-scanner scan source -r /work/example-repo \
  --format json --output osv.json
```

`osv-scanner -r /work/example-repo` is equivalent to `osv-scanner scan source -r ...`.
Run it twice (SARIF for archival/CI, JSON for parsing) or use `scripts/run_osv.py`
which does both and parses the result.

Key flags (full table in `references/cli.md`):

- `-r, --recursive` — walk the directory tree for every supported
  manifest/lockfile. Always use this on a repo root.
- `-L, --lockfile <path>` — scan an explicit lockfile, or a lockfile whose
  name doesn't match discovery: `-L requirements.txt:/tmp/reqs-frozen.txt`.
  **SBOMs are also fed through `-L`** — the old `--sbom` flag is DEPRECATED
  in v2. SBOM discovery is filename-based (`*.spdx.json`, `*.cdx.json`,
  `bom.json` …); an SBOM with a generic name like `output.json` will be
  silently missed, so pass it explicitly: `-L sbom.cdx.json`.
- `--include-git-root` — v2 skips the root git repository's own commit by
  default; set this to include it (needed for git-hash-based matching of the
  repo itself and vendored submodules).
- `--call-analysis=all` (or per-language, e.g. `--call-analysis=go`) —
  reachability analysis for supported languages (Go, Rust): only report
  vulns whose vulnerable function is actually called. Use it to cut noise,
  but record that unreached vulns were suppressed.
- `osv-scanner scan image example.com/app:1.4` — scan a container image
  (layer-aware; also accepts `--archive image.tar`).

### 2. Read the exit code — 128 is NOT clean

- `0` — packages were found, **no** vulnerabilities matched.
- `1` — vulnerabilities matched (normal "findings exist" result).
- `128` — **no packages found at all.** This is an inventory failure, not a
  clean result: the repo probably has no lockfiles (manifest-only, vendored
  deps, or an unsupported ecosystem). Do not report "no vulns" — instead
  generate a lockfile (`npm install --package-lock-only`, `pip freeze`,
  `go mod tidy`) or build an SBOM with Syft (`grype-syft` skill) and rescan.

Other non-zero codes (127 and below) are tool/config errors — read stderr.

### 3. Read the output

Per finding you get: **package**, **ecosystem** (npm, PyPI, Go, Maven,
crates.io, RubyGems, NuGet, Packagist/Composer, …), **installed version**,
**OSV id** (`GHSA-…`, `PYSEC-…`, `GO-…`, `RUSTSEC-…`) with **CVE aliases**,
**severity** (CVSS vector/score where provided; `groups[].max_severity` in
JSON), and the **fixed version** from the affected-range events. The JSON
`results[].source.path` tells you which lockfile the package came from —
that's the file you edit to fix it. Full ecosystem/lockfile coverage table:
`references/ecosystems.md`.

### 4. Normalize → work units

```sh
python3 scripts/osv_to_workunits.py osv.json --sarif osv.sarif -o workunits.json
```

This writes a **clean top-level JSON array** of work units:

```json
[{"id": "GHSA-xxxx-lodash-4.17.20",
  "title": "GHSA-xxxx (CVE-2021-23337) in lodash@4.17.20 [npm]",
  "targets": ["lodash@4.17.20"],
  "hints": {"ecosystem": "npm", "osv_id": "GHSA-xxxx", "cve": "CVE-2021-23337",
            "severity": "7.2", "fixed_version": "4.17.21",
            "lockfile": "package-lock.json"}}]
```

Then load the `work-units` skill to split/shape the normalized findings into
dispatchable work units — do not re-invent the splitter.

### 5. Verify and report

For each work unit: confirm the package+version really is resolved into the
build (lockfile vs. actual install), check whether the vulnerable code path
is used (grep imports/call sites; `--call-analysis` already did this for
Go/Rust), and determine the minimal fix bump from `fixed_version`.

- Mark the repo, every scanned lockfile, and every scanned dependency
  package with rupu's `assets.mark` so coverage is trackable.
- Load the `finding-report` skill and file each **verified** vulnerable
  dependency with `findings.report`.
- Concrete rupu workflow YAML, `for_each:` consumption, `dispatch` fan-out,
  and example `assets.mark` / `findings.report` calls: `references/rupu.md`.

### 6. Tune with osv-scanner.toml

Place `osv-scanner.toml` next to the scanned manifests to suppress accepted
risks by OSV id or to override package versions:

```toml
[[IgnoredVulns]]
id = "GHSA-xxxx-yyyy-zzzz"
reason = "Vulnerable function not reachable; verified 2024-05-01"

[[PackageOverrides]]
name = "internal-fork"
ecosystem = "npm"
ignore = true
reason = "Private fork, patched internally"
```

Pass `--no-ignore` to bypass the config when you want the raw picture.

## Cross-check

Run the `grype-syft` skill over the same tree: Syft catalogs packages that
OSV-Scanner's lockfile extractors miss (OS packages, binaries, jars inside
images), and Grype uses NVD/distro feeds that sometimes disagree with
OSV.dev. Diff the two work-unit arrays by `package@version` — anything
flagged by only one scanner deserves manual review. You can also feed the
Syft SBOM straight back into OSV-Scanner: `osv-scanner -L sbom.cdx.json`.

## Quick reference

| Task | Command |
|---|---|
| Repo scan | `osv-scanner -r . --format json --output osv.json` |
| Explicit lockfile | `osv-scanner -L package-lock.json` |
| SBOM scan | `osv-scanner -L sbom.cdx.json` |
| Container image | `osv-scanner scan image example.com/app:1.4` |
| Reachability | `osv-scanner -r . --call-analysis=all` |
| One-shot pipeline | `python3 scripts/run_osv.py /work/repo -o out/` |
