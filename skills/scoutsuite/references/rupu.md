# rupu wiring for the scoutsuite skill

This skill ends every parse/handoff step by producing `out/work-units.json` — a bare
JSON array (content starts with `[`) of `{"id","title","targets","hints"}` objects —
plus `out/assets.json`. That is the shape rupu's `for_each:` ingests.

Import these shared reporting-pack skills BY NAME — do not re-implement them:

- **`work-units`** — the canonical work-unit splitter shape (`id`, `title`,
  `targets`, `hints`). `scripts/parse_scoutsuite.py` conforms to it.
- **`coverage-assets`** — recording assets with rupu's `assets.mark` tool.
- **`finding-report`** — recording verified issues with rupu's `findings.report`
  tool.

## Workflow fan-out

```yaml
steps:
  - id: scan
    run: >
      python3 skills/scoutsuite/scripts/run_scoutsuite.py aws --profile target
      --report-dir out/scout --out out/work-units.json --assets-out out/assets.json

  - id: triage
    for_each: out/work-units.json          # rupu JSON-parses the bare array
    as: unit
    steps:
      - run: >
          Investigate and exploit {{unit.id}} — "{{unit.title}}" (level
          {{unit.hints.level}}). Targets: {{unit.targets}}.
          Rationale: {{unit.hints.rationale}}.
          Resolve each target path in the scoutsuite_results model per
          skills/scoutsuite/references/results-model.md, then route:
          s3/cloudstorage/storageaccounts -> cloud-storage-exposure,
          iam wildcard/privesc -> pmapper/pacu,
          instance-profile/metadata exposure -> metadata-ssrf-pivot,
          everything else -> cloud-security.
```

## Lead-agent dispatch over the same units

```
read_file out/work-units.json
# then for each unit:
dispatch(
  task  = "Exploit scoutsuite finding " + unit.id + ": " + unit.title,
  input = {"targets": unit.targets, "hints": unit.hints,
           "results_js": "out/scout/scoutsuite-results/scoutsuite_results_aws-target.js"},
  skills= ["scoutsuite", "cloud-storage-exposure", "pacu", "pmapper", "metadata-ssrf-pivot"]
)
```

Pass the `results_js` path through: workers resolve their target paths against the
full resource model for policy documents, endpoints and IPs without re-scanning.

## Asset recording (`assets.mark`, per the `coverage-assets` skill)

Walk `out/assets.json` (flagged resources) plus the inventory and mark the cloud
asset model:

```
assets.mark(type="cloud-account",   id="123456789012", meta={"provider":"aws","tool":"scoutsuite"})
assets.mark(type="storage-bucket",  id="s3.buckets.example-com-backups",
            meta={"finding":"s3-bucket-world-readable","level":"danger"})
assets.mark(type="principal",       id="iam.roles.app-deployer",
            meta={"finding":"iam-assume-role-policy-allows-all"})
assets.mark(type="compute",         id="ec2.regions.us-east-1.vpcs.vpc-0a1b2c.instances.i-0abc",
            meta={"public_ip":"203.0.113.17","imds":"v1"})
assets.mark(type="public-endpoint", id="203.0.113.17:22",
            meta={"finding":"ec2-security-group-opens-SSH-port-to-all"})
assets.mark(type="secret",          id="awslambda...functions.billing-sync.env.DB_PASSWORD",
            meta={"source":"resource-model"})
```

Azure analogues: subscription, storage container, key vault, NSG rule endpoint.
GCP: project, GCS bucket, service account, Cloud SQL authorized network.

## Finding reporting (`findings.report`, per the `finding-report` skill)

Report only VERIFIED issues (anonymous access demonstrated, port reached, policy
abused):

```
findings.report(
  title    = "World-readable S3 bucket: example-com-backups",
  severity = "high",
  asset    = "s3.buckets.example-com-backups",
  evidence = "ScoutSuite s3-bucket-world-readable (danger); verified: "
             "`aws s3 ls s3://example-com-backups --no-sign-request` listed 1,204 objects.",
  source   = "scoutsuite:s3.s3-bucket-world-readable",
  remediation = hints.remediation
)
```

Quote `hints.rationale`/`hints.remediation` from the work unit — ScoutSuite's rule
text is report-ready.

## Chain

Umbrella: `cloud-security`. Peer scanner: `prowler` — run both on the same creds and
merge the two work-unit arrays (ids are namespaced `prowler:` / `scoutsuite:`, so a
simple JSON concat is safe) before fan-out.

— vulture (topaz-quarry)
