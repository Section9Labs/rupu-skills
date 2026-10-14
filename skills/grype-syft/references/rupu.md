# rupu wiring for grype-syft output

`scripts/grype_to_workunits.py` writes `workunits.json` as a **clean
top-level JSON array** — rupu's workflow `for_each:` JSON-parses any value
that starts with `[`, so point it straight at the file contents.

Shared skills: load the `work-units` skill to split/shape the normalized
findings into work units, and the `finding-report` skill to file each
verified issue. Do not re-invent either.

## Workflow: read_file + for_each over the work-unit array

```yaml
steps:
  - id: sbom_scan
    tool: shell
    args:
      cmd: >
        python3 skills/grype-syft/scripts/run_sbom_scan.py dir:/work/example-repo
        -o /work/out
  - id: load_units
    tool: read_file
    args:
      path: /work/out/workunits.json
  - id: triage
    for_each: "{{ steps.load_units.output }}"   # top-level JSON array -> iterated
    steps:
      - id: verify
        agent: dep-triage
        prompt: |
          Verify this Grype finding against /work/example-repo
          (SBOM: /work/out/sbom.json).
          Package: {{ item.targets[0] }} (type {{ item.hints.type }})
          Vulnerability: {{ item.hints.vuln_id }} severity {{ item.hints.severity }}
          Fix state: {{ item.hints.fix_state }}, fixed in {{ item.hints.fixed_in }}
          Found at: {{ item.hints.location }}
          Check matchDetails quality (cpe-match => scrutinize), confirm the
          package is actually used, and determine the upgrade path.
          If confirmed, load the `finding-report` skill and file it with
          findings.report.
```

## Lead-agent fan-out with dispatch

```
units = json.load(open("/work/out/workunits.json"))
for unit in units:
    dispatch(
        agent="dep-triage",
        task=f"Verify {unit['id']}: {unit['title']}",
        context={"work_unit": unit,
                 "sbom": "/work/out/sbom.json",
                 "repo": "/work/example-repo"},
    )
```

Batch by `hints.type` (one dispatch per package ecosystem) or by
`hints.severity` (criticals first) when the array is large.

## assets.mark — record what was cataloged and scanned

Asset model: the repository (or image), the SBOM artifact, and **every
package in the SBOM** — the full `artifacts[]` list from syft-json, not just
the vulnerable ones. Coverage means "we inventoried and checked it".

```
assets.mark(asset_type="repository", identifier="example.com/example-repo",
            status="scanned", tool="syft+grype")

assets.mark(asset_type="file", identifier="out/sbom.json",
            status="generated", tool="syft",
            detail="syft-json SBOM, 318 components")

assets.mark(asset_type="package", identifier="pkg:npm/lodash@4.17.20",
            status="scanned", tool="grype",
            detail="1 match (GHSA-xxxx), db built 2024-05-01")

assets.mark(asset_type="package", identifier="pkg:npm/express@4.19.2",
            status="scanned", tool="grype", detail="no matches")
```

Use the purl as the package identifier when present (stable across tools —
lets osv-scanner coverage merge with grype coverage). Record the Grype DB
build date (`descriptor.db.built` in grype.json) in the repository asset
detail so stale-DB scans are visible.

## findings.report — file each verified vulnerable dependency

Load the `finding-report` skill for the full pack; per-finding mapping:

```
findings.report(
    title="CVE-2021-23337: command injection in lodash@4.17.20 (npm)",
    asset="pkg:npm/lodash@4.17.20",
    severity="high",                       # hints.severity
    cwe="CWE-94",
    evidence="Cataloged by syft at package-lock.json; grype "
             "exact-direct-match via javascript-matcher; fix state fixed, "
             "fixed in 4.17.21; osv-scanner independently matched GHSA-xxxx",
    recommendation="Upgrade lodash to >=4.17.21; regenerate lockfile and SBOM",
    refs=["https://github.com/advisories/GHSA-xxxx"],
)
```

Include in `evidence`: the match type (`exact-direct-match` vs `cpe-match`),
the SBOM location path, the fix state, and whether the `osv-scanner` skill
corroborated the finding on the same SBOM (`osv-scanner -L sbom.cdx.json`).

— vulture (orchid-meridian)
