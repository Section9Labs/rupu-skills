# Grype reference — sources, gates, database, ignore rules

## Sources

| Scheme | Meaning |
|---|---|
| `sbom:<path>` | Scan a Syft SBOM (syft-json best; CycloneDX/SPDX accepted). **Recommended pipeline input.** `grype sbom:./sbom.json` |
| `dir:<path>` | Scan a directory (embeds Syft to catalog first). |
| `file:<path>` | Single file/archive. |
| `image:<ref>` / bare ref | Container image via daemon. `grype example.com/app:1.4` |
| `registry:<ref>` | Direct registry pull. |
| `docker-archive:` / `oci-archive:` / `oci-dir:` | Exported images. |
| stdin | `syft dir:. -o syft-json \| grype` |

## Output (`-o <format>[=<file>]`, repeatable)

| Format | Use |
|---|---|
| `table` | Human skim (default). |
| `json` | Native, richest — feed to `scripts/grype_to_workunits.py`. |
| `sarif` | SARIF 2.1.0 for CI/code-scanning upload and archival. |
| `cyclonedx` / `cyclonedx-json` | SBOM + embedded vuln data (VEX-ish). |
| `template -t x.tmpl` | Go template custom output. |

Multiple at once: `grype sbom:./sbom.json -o json=grype.json -o sarif=grype.sarif -o table`.

## Gates and filters

| Flag | Meaning |
|---|---|
| `--fail-on <severity>` | Exit 1 if any match ≥ severity. Levels: `negligible`, `low`, `medium`, `high`, `critical`. |
| `--only-fixed` | Only matches with an available fix. |
| `--only-notfixed` | Inverse — the "no patch exists" set. |
| `--ignore-states wont-fix,not-fixed` | Drop by fix state. |
| `--by-cve` | Prefer CVE ids over GHSA in output rows. |
| `--add-cpes-if-none` | Synthesize CPEs for purl-only packages → enables NVD CPE matching. More coverage, more FPs; check `matchDetails[].type`. |
| `--distro ubuntu:22.04` | Force distro namespace when the target lacks `/etc/os-release`. |
| `--exclude './fixtures/**'` | Path excludes (dir/image scans). |
| `--platform linux/arm64` | Arch for multi-arch refs. |
| `--show-suppressed` | Include ignored matches in output (audit `.grype.yaml`). |
| `-s all-layers` | Scope for direct image scans (as in Syft). |
| `--vex vex.json` | Apply OpenVEX statements (filter `not_affected`/`fixed`). |

Exit codes: `0` clean (or below gate), `1` gate tripped (`--fail-on`),
other nonzero = execution error.

## Database management

```
grype db status     # location, build date, schema, validity
grype db check      # is a newer db available?
grype db update     # fetch latest
grype db list       # available listing entries
grype db import db.tar.gz   # offline/airgapped import
```

Auto-update on each run (disable: `GRYPE_DB_AUTO_UPDATE=false` for
airgapped use with `db import`). Record `grype db status` build date
alongside results — matches are only as fresh as the DB.

## Ignore rules — `.grype.yaml`

Searched in CWD, `~/.grype.yaml`, XDG config; or `-c grype.yaml`.
Any field combination; all specified fields must match:

```yaml
ignore:
  - vulnerability: CVE-2021-23337        # by id
    reason: "not reachable, verified 2024-05-01"
  - vulnerability: GHSA-xxxx-yyyy-zzzz
    package:
      name: lodash
      version: 4.17.20
      type: npm
  - fix-state: wont-fix                   # all distro wont-fix entries
  - package:
      location: "/fixtures/**"            # test fixtures
```

Ignored matches drop from results (and `--fail-on` counting); use
`--show-suppressed` to list them.

## JSON output shape (what the parser reads)

```json
{"matches": [
   {"vulnerability": {
      "id": "GHSA-xxxx-yyyy-zzzz", "severity": "High",
      "dataSource": "https://github.com/advisories/GHSA-...",
      "cvss": [{"metrics": {"baseScore": 7.2}}],
      "fix": {"versions": ["4.17.21"], "state": "fixed"},
      "description": "..."},
    "relatedVulnerabilities": [{"id": "CVE-2021-23337"}],
    "matchDetails": [{"type": "exact-direct-match", "matcher": "javascript-matcher"}],
    "artifact": {"name": "lodash", "version": "4.17.20", "type": "npm",
                 "purl": "pkg:npm/lodash@4.17.20",
                 "locations": [{"path": "package-lock.json"}]}}],
 "source": {...}, "distro": {...},
 "descriptor": {"db": {"built": "..."}}}
```

Triage keys: `matchDetails[].type` — `exact-direct-match` (purl/ecosystem
match, trustworthy) vs `exact-indirect-match` (matched via source package)
vs `cpe-match` (fuzzy CPE, main FP source). `fix.state`:
`fixed` / `not-fixed` / `wont-fix` / `unknown`.
