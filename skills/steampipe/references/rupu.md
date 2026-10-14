# rupu wiring for Steampipe output

How Steampipe/Powerpipe results flow into rupu. Built on three shared reporting-pack
skills — import and follow them **by name**, do not re-implement:

- **`work-units`** — canonical splitter shape: a file containing a bare JSON array of
  `{"id","title","targets","hints"}` objects.
- **`coverage-assets`** — record enumerated assets with rupu's `assets.mark` tool.
- **`finding-report`** — record verified issues with rupu's `findings.report` tool.

## 1. Produce the work-units file

```bash
python3 scripts/run_steampipe_queries.py --queries-dir scripts/queries --out-dir out/queries
python3 scripts/parse_steampipe.py out/queries \
    --out out/work-units.json --assets out/assets.json
```

`out/work-units.json` starts with `[` and contains nothing but the array — exactly what
rupu's `for_each:` JSON-parses. Powerpipe benchmark JSON can be folded in too: extract
`alarm` results into the same `{"id","title","targets","hints"}` shape (targets =
`resource`, hints = `{control, reason, dimensions}`) and concatenate arrays.

## 2. Workflow fan-out (`read_file` + `for_each`)

```yaml
steps:
  - id: sweep
    run: |
      python3 skills/steampipe/scripts/run_steampipe_queries.py \
        --queries-dir skills/steampipe/scripts/queries --out-dir out/queries
      python3 skills/steampipe/scripts/parse_steampipe.py out/queries \
        --out out/work-units.json --assets out/assets.json

  - id: exploit-surface
    for_each:
      items: ${{ read_file('out/work-units.json') }}
      as: unit
    prompt: |
      Work unit ${{ unit.id }}: ${{ unit.title }}
      Targets: ${{ unit.targets }}
      Hints: ${{ unit.hints }}
      hints.rows carries the raw query rows (IPs, ports, policies, endpoints).
      Validate and exploit per the routing table in
      skills/steampipe/references/queries.md; record results per the
      coverage-assets and finding-report skills.
```

## 3. Lead-agent dispatch over the same units

```yaml
- id: lead
  prompt: |
    Read out/work-units.json (JSON array per the work-units skill). dispatch one
    sub-agent per unit, routed by hints.query_name:
      *_public_s3 / *_public_buckets / *_public_blobs / *_public_snapshots
        -> cloud-storage-exposure (pacu for snapshot restore; trufflehog on loot)
      *_open_sgs / *_open_nsgs / *_open_firewalls / *_public_compute / *_public_endpoints
        -> cloudfox + aws/azure/gcp-enumeration for endpoint detail, then exposure flow
      *_admin_principals / *_weak_credentials / *_sql_and_keys (SA keys)
        -> pmapper / cloud-privilege-escalation / pacu; azure-entra-id for Entra users
      *_public_rds / public SQL rows -> direct DB attack (pacu rds modules)
    Each sub-agent gets its unit's targets and hints verbatim and may run further
    steampipe queries from references/queries.md to deepen the chain.
  tools: [dispatch, assets.mark, findings.report]
```

## 4. Asset model — `assets.mark`

Mark everything in `out/assets.json` (call shape per the `coverage-assets` skill):

| asset kind | source |
|---|---|
| cloud account / subscription / project | `account_id` / `subscription_id` / `project` columns; `steampipe_connection` rows |
| principal / role | IAM query rows (users, roles, service accounts, policies) |
| compute instance | EC2/VM/GCE rows |
| storage bucket / container | S3/GCS/blob rows |
| public endpoint | public IPs, LB DNS names, DB endpoints from the rows |
| secret | SA keys, access keys, user_data hits, vault entries |

Example: `assets.mark(kind="public-endpoint", id="203.0.113.17",
status="tested", meta={"query_name":"aws_public_compute","account":"111111111111"})`.
Queries that returned zero rows still mean coverage — mark the account/provider surface
as checked so clean areas are visible.

## 5. Findings — `findings.report`

Report only after verification (anonymous list succeeded, port answered, privesc action
allowed), per the `finding-report` skill:

```
findings.report(
  title="Security group sg-0abc123 exposes 5432/tcp to 0.0.0.0/0 on 198.51.100.24",
  severity="high",
  asset="i-0123456789abcdef0",
  evidence="aws_open_sgs row + nc -vz 198.51.100.24 5432 → open; postgres pre-auth banner",
  source="steampipe:aws_open_sgs",
  category="exposure"
)
```

Carry `hints.query_name` (or the Powerpipe control name) into `source` for traceability.

## 6. Chaining

Route onward per the table in `references/queries.md`; cross-validate posture with the
`cloudsploit` sibling skill, and return to the `cloud-security` umbrella skill once this
sweep's units are dispatched.
