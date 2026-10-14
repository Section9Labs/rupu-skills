# rupu wiring for CloudSploit output

This file documents how CloudSploit results flow into rupu. It builds on three shared
reporting-pack skills — import and follow them **by name**, do not re-implement:

- **`work-units`** — the canonical work-unit splitter shape: a file whose content is a
  bare JSON array of `{"id","title","targets","hints"}` objects.
- **`coverage-assets`** — recording enumerated assets with rupu's `assets.mark` tool.
- **`finding-report`** — recording verified issues with rupu's `findings.report` tool.

## 1. Produce the work-units file

```bash
python3 scripts/run_cloudsploit.py --cloudsploit-dir ./cloudsploit \
    --config ./config.js --json out/cloudsploit.json --collection out/collection.json
python3 scripts/parse_cloudsploit.py out/cloudsploit.json \
    --out out/work-units.json --assets out/assets.json
```

`out/work-units.json` starts with `[` and contains nothing but the array — exactly what
rupu's `for_each:` JSON-parses.

## 2. Workflow fan-out (`read_file` + `for_each`)

```yaml
steps:
  - id: scan
    run: |
      python3 skills/cloudsploit/scripts/run_cloudsploit.py \
        --cloudsploit-dir ./cloudsploit --config ./config.js \
        --json out/cloudsploit.json --collection out/collection.json
      python3 skills/cloudsploit/scripts/parse_cloudsploit.py \
        out/cloudsploit.json --out out/work-units.json --assets out/assets.json

  - id: triage-fails
    for_each:
      items: ${{ read_file('out/work-units.json') }}
      as: unit
    prompt: |
      Work unit ${{ unit.id }}: ${{ unit.title }}
      Targets: ${{ unit.targets }}
      Hints: ${{ unit.hints }}
      Follow skills/cloudsploit/references/plugins-triage.md for this hints.category:
      validate exploitability, exploit the misconfiguration, and record results
      per the coverage-assets and finding-report skills.
```

## 3. Lead-agent dispatch over the same units

```yaml
- id: lead
  prompt: |
    Read out/work-units.json (JSON array per the work-units skill). dispatch one
    sub-agent per unit; route by hints.category using
    skills/cloudsploit/references/plugins-triage.md (S3/Blob/GCS →
    cloud-storage-exposure, EC2 open-* → cloudfox + exposure flow, IAM →
    pmapper / cloud-privilege-escalation, snapshots/RDS → pacu,
    secrets/vaults → trufflehog, Entra → azure-entra-id).
    Give each sub-agent its unit's targets and hints verbatim plus access to
    out/collection.json for resource detail.
  tools: [dispatch, assets.mark, findings.report]
```

## 4. Asset model — `assets.mark`

Mark every entry from `out/assets.json` (see the `coverage-assets` skill for call shape).
Cloud asset model for this domain:

| asset kind | source |
|---|---|
| cloud account / subscription / project | the account scanned (from config.js / ARNs) |
| principal / role | IAM category resources (users, roles, service accounts) |
| compute instance | EC2/VM/GCE resources in results and collection |
| storage bucket / container | S3/Blob/GCS resources |
| public endpoint | RDS/SQL endpoints, open-SG instance IPs (from collection) |
| secret | KMS keys, Key Vault / Secrets Manager entries |

Example: `assets.mark(kind="storage-bucket", id="arn:aws:s3:::example-public-bucket",
status="tested", meta={"region":"us-east-1","worst_status":"FAIL"})`. Mark passing
resources too — coverage includes what was checked and clean. Mark UNKNOWN-status
services as `status="blocked"` so gaps are visible.

## 5. Findings — `findings.report`

Only after a unit's misconfiguration is **verified** (bucket actually listable, port
actually open, policy actually grants admin), report per the `finding-report` skill:

```
findings.report(
  title="S3 bucket world-readable: example-public-bucket",
  severity="high",
  asset="arn:aws:s3:::example-public-bucket",
  evidence="aws s3 ls s3://example-public-bucket --no-sign-request → 1,204 objects incl. backups/db.sql.gz",
  source="cloudsploit:s3BucketAllUsersPolicy",
  category="exposure"   # exposure | privesc | misconfig | data-access
)
```

Carry `hints.plugin` into `source` so findings trace back to the originating check.

## 6. Chaining

Hand off onward targets to sibling skills named in `references/plugins-triage.md`, and
return control to the `cloud-security` umbrella skill once this scan's units are
dispatched. Cross-validate interesting units with the `steampipe` skill's live SQL.
