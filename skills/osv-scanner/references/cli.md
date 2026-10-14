# OSV-Scanner v2 CLI reference

## Subcommands

```
osv-scanner scan source [flags] <paths...>    # default mode; `osv-scanner [flags] <paths>` is the same
osv-scanner scan image  [flags] <image>       # container image scan (layer-aware)
osv-scanner fix         [flags]               # guided/in-place remediation (npm, Maven)
osv-scanner update      [flags]               # update deps in manifests to fixed versions
```

## scan source flags

| Flag | Meaning |
|---|---|
| `-r, --recursive` | Recursively walk directories for manifests/lockfiles. |
| `-L, --lockfile <file>` | Scan an explicit lockfile or SBOM. Repeatable. Prefix to force a parser when the filename is nonstandard: `-L requirements.txt:/tmp/frozen.txt`, `-L package-lock.json:/x/lock.json`. `--sbom` is **deprecated** — pass SBOM files through `-L`. |
| `--include-git-root` | Include the root git repository (skipped by default in v2). Needed for commit-hash matching of the repo itself. |
| `--call-analysis=<lang\|all>` | Reachability analysis; only report vulns whose vulnerable symbol is reachable. Supported: `go`, `rust`. `--no-call-analysis=<lang>` disables. |
| `--format <fmt>` | `table` (default), `json`, `sarif`, `markdown`, `html`, `gh-annotations`, `cyclonedx-1-4`, `cyclonedx-1-5`. |
| `--output <file>` | Write report to file instead of stdout. |
| `--config <file>` | Explicit `osv-scanner.toml` (otherwise discovered per-directory). |
| `--no-ignore` | Ignore all `IgnoredVulns`/`PackageOverrides` config entries. |
| `--licenses[=<allowlist>]` | Also report license info / violations (comma-separated SPDX allowlist). |
| `--offline` / `--download-offline-databases` | Use local OSV db copies; download them first with the latter. |
| `--verbosity <level>` | `error`, `warn`, `info`, `verbose`. |

## scan image

```
osv-scanner scan image example.com/app:1.4
osv-scanner scan image --archive ./app-image.tar
```

Scans OS packages and language artifacts across layers; the JSON output
includes per-layer provenance so you can tell base-image vulns from
app-layer vulns. `--format json|sarif` and `--output` work as for source.

## Exit codes

| Code | Meaning | Action |
|---|---|---|
| `0` | Packages found, no vulnerabilities matched | Clean (for the inventory that was found). |
| `1` | One or more vulnerabilities matched | Parse output, build work units. |
| `1–126` | Scan ran, errors or findings — check stderr | Investigate. |
| `127` | General error (bad flags, no API reachability, …) | Fix invocation. |
| `128` | **No packages found anywhere** | Inventory failure. Not clean. Generate lockfiles or an SBOM (Syft, see `grype-syft`) and rescan. |

## Config: osv-scanner.toml

Discovered in the same directory as each scanned manifest (or forced with
`--config`). String values only, with `reason` fields for audit trail:

```toml
[[IgnoredVulns]]
id = "GHSA-xxxx-yyyy-zzzz"
# ignoreUntil = 2024-12-31   # optional expiry
reason = "accepted risk, ticket EX-123"

[[PackageOverrides]]
name = "left-pad"
ecosystem = "npm"
version = "1.3.0"       # override detected version
# ignore = true         # or drop the package entirely
reason = "vendored and patched"
```

## JSON output shape (what the parser reads)

```json
{
  "results": [
    {
      "source": {"path": "/work/repo/package-lock.json", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
          "vulnerabilities": [
            {"id": "GHSA-....", "aliases": ["CVE-2021-23337"],
             "summary": "...",
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}],
             "affected": [{"ranges": [{"type": "SEMVER",
                           "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
          ],
          "groups": [
            {"ids": ["GHSA-...."], "aliases": ["CVE-2021-23337", "GHSA-...."],
             "max_severity": "7.2"}
          ]
        }
      ]
    }
  ]
}
```

`groups` deduplicates aliased advisories — iterate groups for one work unit
per real vulnerability, and use the member `vulnerabilities` entries for
summary/fixed-version detail. SARIF output (`--format sarif`) carries the
same data as SARIF 2.1.0 `runs[].results[]` with rule metadata in
`runs[].tool.driver.rules[]`.
