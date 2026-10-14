# rupu wiring for the prowler skill

This skill ends every parse/handoff step by producing `out/work-units.json` — a bare
JSON array (content starts with `[`) of `{"id","title","targets","hints"}` objects —
plus `out/assets.json`. That is exactly the shape rupu's `for_each:` ingests.

Import these shared reporting-pack skills BY NAME — do not re-implement them:

- **`work-units`** — the canonical work-unit splitter shape (`id`, `title`,
  `targets`, `hints`). `scripts/parse_prowler.py` conforms to it.
- **`coverage-assets`** — how to record discovered assets with rupu's `assets.mark`
  tool.
- **`finding-report`** — how to record verified issues with rupu's
  `findings.report` tool.

## Workflow fan-out

```yaml
steps:
  - id: scan
    run: >
      python3 skills/prowler/scripts/run_prowler.py aws --profile target
      --severity critical high --output-dir out/prowler
      --out out/work-units.json --assets-out out/assets.json

  - id: triage
    for_each: out/work-units.json          # rupu JSON-parses the bare array
    as: unit
    steps:
      - run: >
          Investigate and exploit {{unit.id}} — "{{unit.title}}".
          Targets: {{unit.targets}}. Context: {{unit.hints}}.
          Route per skills/prowler/references/checks-triage.md
          (e.g. s3_bucket_public_* -> cloud-storage-exposure,
          iam_*privilege* -> pmapper/pacu, imdsv2 -> metadata-ssrf-pivot).
```

## Lead-agent dispatch over the same units

```
read_file out/work-units.json
# then for each unit:
dispatch(
  task  = "Exploit prowler finding " + unit.id + ": " + unit.title,
  input = {"targets": unit.targets, "hints": unit.hints},
  skills= ["prowler", "cloud-storage-exposure", "pacu", "pmapper", "metadata-ssrf-pivot"]
)
```

Group dispatches sensibly: one worker per check id is the default (that is how the
parser groups), one worker per account/region if targets exceed ~200.

## Asset recording (`assets.mark`, per the `coverage-assets` skill)

Walk `out/assets.json` and mark the cloud asset model:

```
assets.mark(type="cloud-account",  id="123456789012",            meta={"provider":"aws"})
assets.mark(type="principal",      id="arn:aws:iam::123456789012:role/app-deployer",
            meta={"privesc":"iam_policy_allows_privilege_escalation"})
assets.mark(type="storage-bucket", id="example-com-backups",
            meta={"public":"true","check":"s3_bucket_public_access"})
assets.mark(type="compute",        id="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc...",
            meta={"imds":"v1","public_ip":"203.0.113.17"})
assets.mark(type="public-endpoint",id="https://abc123.lambda-url.us-east-1.on.aws/",
            meta={"auth":"NONE"})
assets.mark(type="secret",         id="arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db",
            meta={"source":"ec2_instance_secrets_user_data"})
```

Equivalent types for Azure (subscription, blob container, key vault, managed
identity) and GCP (project, GCS bucket, service account, cloud function URL).

## Finding reporting (`findings.report`, per the `finding-report` skill)

Report once a unit is VERIFIED (anonymous listing succeeded, role assumed, metadata
creds pulled, endpoint invoked):

```
findings.report(
  title    = "Public S3 bucket with world-read + write: example-com-backups",
  severity = "high",
  asset    = "example-com-backups",
  evidence = "aws s3 ls s3://example-com-backups --no-sign-request → 1,204 objects; "
             "anonymous PUT accepted (test object uploaded+removed).",
  source   = "prowler:s3_bucket_public_access",
  remediation = hints.remediation
)
```

Carry `hints.risk` / `hints.remediation` from the work unit into the finding so the
report writes itself. Unverified FAILs stay work units, not findings.

## Chain

Umbrella: `cloud-security` (overall engagement flow, cross-provider pivoting).
Peer scanner: `scoutsuite` (run on the same creds, merge both work-unit files).

— vulture (topaz-quarry)
