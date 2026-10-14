# rupu wiring for dependency-check output

The parser (`scripts/depcheck_to_workunits.py`) writes a **clean top-level
JSON array** of work units. rupu's workflow `for_each:` JSON-parses any value
that starts with `[`, so the file can be fed straight into `read_file` +
`for_each:`.

Work-unit shape:

```json
[
  {
    "id": "odc-0001-cve-2019-20330",
    "title": "CVE-2019-20330 (CVSS 9.8, CRITICAL) in jackson-databind-2.9.10.jar",
    "targets": ["lib/jackson-databind-2.9.10.jar"],
    "hints": {
      "cve": "CVE-2019-20330",
      "cvss": "9.8",
      "severity": "CRITICAL",
      "cwe": "CWE-502",
      "cpe": "cpe:2.3:a:fasterxml:jackson-databind:2.9.10:*:*:*:*:*:*:*",
      "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10",
      "confidence": "HIGHEST",
      "source": "NVD",
      "kev": "false",
      "description": "FasterXML jackson-databind 2.x before 2.9.10.2 lacks certain net.sf.ehcache blocking."
    }
  }
]
```

## Workflow YAML: read_file + for_each

```yaml
steps:
  - id: scan
    run: >
      python3 skills/dependency-check/scripts/run_depcheck.py
      --scan /src/example-app --out ./odc-report --project example-app
      --workunits ./workunits.json -- --enableExperimental

  - id: load_units
    tool: read_file
    args:
      path: ./workunits.json

  - id: verify_dep_cve
    for_each: "{{ steps.load_units.output }}"   # top-level JSON array -> iterated
    as: unit
    steps:
      - prompt: |
          Load the `work-units` skill conventions. You own work unit
          {{ unit.id }}: {{ unit.title }}.
          Dependency: {{ unit.targets[0] }}
          Hints: {{ unit.hints }}
          1. Verify the CPE match ({{ unit.hints.cpe }}) against the purl
             ({{ unit.hints.purl }}) and artifact metadata; confidence is
             {{ unit.hints.confidence }}.
          2. Verify the installed version is inside the vulnerable range for
             {{ unit.hints.cve }}.
          3. Determine reachability: locate code paths invoking the vulnerable
             API/component; build a PoC where feasible.
          4. If a false positive (wrong CPE / out of range), write a
             suppression entry with notes instead of a finding.
          5. If verified: load the `finding-report` skill and file it with
             findings.report.
```

## Lead-agent fan-out with dispatch

```
units = json.parse(read_file("workunits.json"))
# Batch per dependency (same target) so one agent handles all CVEs on one package:
for batch in group_by(units, u -> u.targets[0]):
    dispatch(
      agent="sca-verifier",
      input={
        "units": batch,
        "repo": "/src/example-app",
        "instructions": "Load the `work-units` skill to interpret the units; "
                        "verify CPE/version/reachability per unit; load the "
                        "`finding-report` skill and file verified issues via "
                        "findings.report."
      })
```

Use the `work-units` skill (the shared work-unit splitter) to do the
grouping/batching — do not re-implement splitting logic here.

## Coverage: assets.mark

The code-review asset model = repository + scanned files/modules + dependency
packages. Mark all three after the scan so coverage is trackable:

```
assets.mark(asset_type="repository", id="example.com/example-app",
            status="scanned", tool="dependency-check",
            meta={"report": "odc-report/dependency-check-report.json"})

assets.mark(asset_type="path", id="example-app/package-lock.json",
            status="scanned", tool="dependency-check")

# one per entry in dependencies[].packages[] of the JSON report:
assets.mark(asset_type="dependency",
            id="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10",
            status="scanned", tool="dependency-check",
            meta={"vulns": "3", "max_cvss": "9.8"})
assets.mark(asset_type="dependency",
            id="pkg:npm/lodash@4.17.11",
            status="scanned", tool="dependency-check",
            meta={"vulns": "0"})
```

`depcheck_to_workunits.py --assets assets.json` emits the full package list
(including clean, zero-CVE packages — mark those too; coverage means
"analyzed", not "vulnerable") so a loop can replay it into `assets.mark`.

## Reporting: findings.report

File only **verified** issues (CPE confirmed, version in range; reachability
and PoC status recorded). Load the `finding-report` skill for the full pack;
example call:

```
findings.report(
  title="CVE-2019-20330: jackson-databind 2.9.10 deserialization RCE (reachable)",
  asset="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10",
  severity="critical",
  cvss="9.8",
  cwe="CWE-502",
  evidence={
    "dependency": "lib/jackson-databind-2.9.10.jar",
    "cpe": "cpe:2.3:a:fasterxml:jackson-databind:2.9.10:*:*:*:*:*:*:*",
    "vulnerable_range": "[2.0.0, 2.9.10.2)",
    "reachability": "ObjectMapper.readValue on request body in src/main/java/com/example/Api.java:88 with default typing enabled",
    "poc": "gadget payload accepted; see workdir/poc-cve-2019-20330.json",
    "kev": "false",
    "work_unit": "odc-0001-cve-2019-20330"
  },
  remediation="Upgrade jackson-databind to >= 2.9.10.2 (prefer current 2.x); disable default typing."
)
```

False positives do NOT go to `findings.report` — they go into
`suppressions.xml` with a `<notes>` justification (see
`references/nvd-and-suppression.md`).

## SARIF handoff

`./odc-report/dependency-check-report.sarif` is SARIF 2.1.0. Route it to the
`sarif-triage` skill to merge/dedup with other scanners (semgrep, codeql,
trivy, etc.) in the same engagement.

— vulture (cobalt-mill)
