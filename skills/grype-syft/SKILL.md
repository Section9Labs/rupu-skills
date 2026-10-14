---
name: grype-syft
description: Generate SBOMs with Anchore Syft (directories, files, container images, registries) and scan them for known vulnerabilities with Grype; normalize Grype SARIF/JSON into work units for triage and fan-out. Use for the SBOM + SCA step of a code review, especially when there are no lockfiles, when scanning built images, or to cross-check osv-scanner.
license: MIT
metadata:
  author: Section9Labs
  tools: "syft, grype"
---

# Syft + Grype — SBOM generation and vulnerability scanning

Syft catalogs *everything installed* — OS packages, language packages,
binaries, jars-in-wars, Python dist-info, Go buildinfo — into an SBOM.
Grype matches that inventory against NVD, GitHub Security Advisories, and
distro feeds. The pipeline is: **generate the SBOM once, scan it many
times** — with Grype, with OSV-Scanner (`osv-scanner` skill), and again
later when databases update, without re-cataloging the target.

## Workflow

### 1. Generate the SBOM with Syft

```sh
syft dir:/work/example-repo -o syft-json=sbom.json -o cyclonedx-json=sbom.cdx.json
```

Sources (full list in `references/syft.md`):

- `dir:.` — a source tree or installed filesystem.
- `file:./app.jar` — a single archive/binary (recurses into nested archives).
- `image:example.com/app:1.4` or just `nginx:latest` — container image from
  the local daemon; `registry:example.com/app:1.4` forces a direct registry
  pull (no daemon needed); `docker-archive:img.tar`, `oci-dir:...` for
  exported images.

Output formats via `-o <format>[=<file>]`, repeatable:

- `syft-json` — richest; keep this one, it preserves every cataloger detail
  and gives Grype the best matching accuracy.
- `cyclonedx-json` / `cyclonedx-xml`, `spdx-json` / `spdx-tag-value` —
  interchange formats for other tools (osv-scanner takes these via `-L`).
- `table` — human skim.

Key flags: `--scope all-layers` (image scans: catalog every layer, not just
the squashed final filesystem — finds packages removed in later layers),
`--select-catalogers`/`--override-default-catalogers` to tune which
ecosystems are cataloged (e.g. `+sbom-cataloger`, `python,javascript`).

The SBOM is the portable artifact: archive it with the engagement evidence.

### 2. Scan with Grype

```sh
grype sbom:./sbom.json -o sarif=grype.sarif -o json=grype.json -o table
```

`sbom:` over the syft-json file is the **recommended pipeline** — but Grype
also scans sources directly (it embeds Syft): `grype dir:.`,
`grype image:example.com/app:1.4`, `grype registry:...`.

Key flags (full table in `references/grype.md`):

- `-o sarif|json|table|cyclonedx[=<file>]` — repeatable; emit SARIF and JSON
  in one run.
- `--fail-on high` — severity gate: nonzero exit (1) if any finding ≥ high.
  Levels: negligible, low, medium, high, critical.
- `--only-fixed` — show only vulns with an available fix (actionable set);
  run **without** it first so the full picture is on record.
- `--add-cpes-if-none` — synthesize CPEs for packages lacking them, enabling
  NVD CPE matching (more hits, more false positives — good for coverage
  passes, review matches by `matchDetails[].type`).
- `--distro ubuntu:22.04` — force the distro when scanning a filesystem that
  lacks `/etc/os-release` (chroots, extracted rootfs).
- `--by-cve` — key output rows by CVE instead of GHSA where possible.

Database: `grype db status` / `grype db update` / `grype db check`. The DB
auto-updates on run; update explicitly in offline-prepped environments and
record the DB build date with the results.

Ignore rules live in `.grype.yaml` (by vulnerability id, package, fix-state)
— see `references/grype.md`. Use `--show-suppressed` to audit what the
config is hiding.

### 3. Read the output

Per match: **package** name + **version**, package **type** (npm, python,
java-archive, go-module, deb, apk, rpm, binary…), **vulnerability id**
(CVE or GHSA, with `relatedVulnerabilities` carrying the aliases),
**severity**, **fix state** (`fixed`, `not-fixed`, `wont-fix`, `unknown`)
and **fixed-in version(s)**, plus `artifact.locations[].path` — the file the
package was found in (lockfile, dist-info dir, layer path in images) and
`matchDetails[].type` (`exact-direct-match` vs `cpe-match` — scrutinize CPE
matches, they are the main false-positive source).

### 4. Normalize → work units

```sh
python3 scripts/grype_to_workunits.py grype.json --sarif grype.sarif -o workunits.json
```

Writes a **clean top-level JSON array**:

```json
[{"id": "CVE-2023-xxxxx-openssl-1.1.1k",
  "title": "CVE-2023-xxxxx (critical) in openssl@1.1.1k [apk]",
  "targets": ["openssl@1.1.1k"],
  "hints": {"type": "apk", "vuln_id": "CVE-2023-xxxxx", "severity": "Critical",
            "fix_state": "fixed", "fixed_in": "1.1.1l-r0",
            "location": "lib/apk/db/installed"}}]
```

Then load the `work-units` skill to split/shape the normalized findings into
dispatchable work units — do not re-invent the splitter.

### 5. One-shot pipeline

```sh
python3 scripts/run_sbom_scan.py dir:/work/example-repo -o out/
# -> out/sbom.json, out/grype.sarif, out/grype.json, out/workunits.json
```

### 6. Verify and report

For each work unit: confirm the package is really present and in use (an
SBOM entry can be a leftover file), check `fix_state` and `matchDetails`
quality, and determine the upgrade/mitigation path.

- Mark the repo/image, the SBOM artifact, and **every cataloged dependency
  package** (vulnerable or not) with rupu's `assets.mark` so coverage is
  trackable — the SBOM component list is the coverage ledger.
- Load the `finding-report` skill and file each **verified** vulnerable
  dependency with `findings.report`.
- Concrete rupu workflow YAML (`read_file` + `for_each:`), `dispatch`
  fan-out, and example `assets.mark` / `findings.report` calls:
  `references/rupu.md`.

## Cross-check with osv-scanner

Feed the same SBOM to the `osv-scanner` skill
(`osv-scanner -L sbom.cdx.json`) and diff work-unit arrays by
`package@version` + vuln alias. Grype's NVD/CPE matching finds things OSV
misses (OS packages, binaries, CPE-only CVEs); OSV.dev's ecosystem-native
ranges are more precise for language packages. Agreement = strong signal;
single-source hits = manual review.

## Quick reference

| Task | Command |
|---|---|
| SBOM from source tree | `syft dir:. -o syft-json=sbom.json` |
| SBOM from image, all layers | `syft example.com/app:1.4 --scope all-layers -o syft-json=sbom.json` |
| Scan the SBOM | `grype sbom:./sbom.json -o sarif=grype.sarif -o json=grype.json` |
| Direct dir scan | `grype dir:. -o json` |
| Gate a build | `grype sbom:./sbom.json --fail-on high --only-fixed` |
| DB freshness | `grype db status && grype db update` |
| One-shot pipeline | `python3 scripts/run_sbom_scan.py dir:. -o out/` |
