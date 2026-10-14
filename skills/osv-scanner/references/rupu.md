# rupu wiring for osv-scanner output

The normalizer `scripts/osv_to_workunits.py` writes `workunits.json` as a
**clean top-level JSON array** — rupu's workflow `for_each:` JSON-parses any
value that starts with `[`, so point it straight at the file contents.

Shared skills: load the `work-units` skill to split/shape the normalized
findings into work units, and the `finding-report` skill to file each
verified issue. Do not re-invent either.

## Workflow: read_file + for_each over the work-unit array

```yaml
steps:
  - id: scan
    tool: shell
    args:
      cmd: >
        python3 skills/osv-scanner/scripts/run_osv.py /work/example-repo
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
          Verify this OSV finding in /work/example-repo.
          Package: {{ item.targets[0] }}
          Advisory: {{ item.hints.osv_id }} ({{ item.hints.cve }})
          Lockfile: {{ item.hints.lockfile }}
          Confirm the version is actually resolved, check whether the
          vulnerable code path is used, and determine the fix bump
          (fixed_version: {{ item.hints.fixed_version }}).
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
        context={"work_unit": unit, "repo": "/work/example-repo"},
    )
```

Batch by lockfile (`hints.lockfile`) when the array is large — one dispatch
per lockfile keeps context local to a single ecosystem.

## assets.mark — record what was scanned

Asset model: the repository, the lockfiles/manifests scanned, and every
dependency package in the inventory (including clean ones — coverage means
"we checked it", not "it was vulnerable").

```
assets.mark(asset_type="repository", identifier="example.com/example-repo",
            status="scanned", tool="osv-scanner")

assets.mark(asset_type="file", identifier="example-repo/package-lock.json",
            status="scanned", tool="osv-scanner",
            detail="npm lockfile, 412 packages")

assets.mark(asset_type="package", identifier="npm:lodash@4.17.20",
            status="scanned", tool="osv-scanner",
            detail="2 advisories matched")
```

Mark every `results[].source.path` from the osv JSON as a file asset and
every `package@version` as a package asset. If osv-scanner exited **128**,
mark the repository asset with `status="inventory-failed"` so the gap is
visible — do not leave it looking covered.

## findings.report — file each verified vulnerable dependency

Load the `finding-report` skill for the full pack; the per-finding call maps
work-unit fields like this:

```
findings.report(
    title="CVE-2021-23337: command injection in lodash@4.17.20 (npm)",
    asset="npm:lodash@4.17.20",
    severity="high",                       # from hints.severity (CVSS 7.2)
    cwe="CWE-94",
    evidence="Resolved in example-repo/package-lock.json; template() called "
             "from src/render.js:88; OSV GHSA-xxxx, fixed in 4.17.21",
    recommendation="Bump lodash to >=4.17.21 and regenerate the lockfile",
    refs=["https://osv.dev/vulnerability/GHSA-xxxx"],
)
```

Cross-check note: when the `grype-syft` skill scanned the same tree, include
whether Grype agreed (same vuln id for same purl) in `evidence` — two-source
confirmation strengthens the finding.

— vulture (orchid-meridian)
