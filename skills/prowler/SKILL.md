---
name: prowler
description: Run and triage Prowler (v4/v5 Python CLI) posture scans across AWS, Azure, GCP and Kubernetes — authenticate per provider, scope by service/check/severity/compliance, parse the OCSF JSON output, and emit exploitable FAIL findings as rupu work units for follow-on attack skills.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Prowler — multi-cloud offensive posture assessment

Prowler enumerates a cloud estate with read-only API calls and evaluates hundreds of
security checks. Offensively it is the fastest way to turn one set of credentials into
a prioritized list of exploitable misconfigurations: public buckets, privesc-capable
IAM policies, public snapshots, open admin ports, unauthenticated function URLs,
IMDSv1 instances, public databases. Use it early, as the recon pass that decides what
to attack next. Umbrella skill: `cloud-security`. Peer scanner: `scoutsuite`.

## 1. Install

```bash
pipx install prowler          # preferred: isolated env
# or
pip install prowler
prowler --version             # v4/v5
```

Providers are subcommands: `prowler aws | azure | gcp | kubernetes` (v5 also has
`m365`, `github`). Every provider shares the output/scoping flags; auth differs.

## 2. Authenticate per provider

### AWS
Prowler uses whatever boto3 can resolve — named profile, env creds, instance role:

```bash
prowler aws --profile target                                  # ~/.aws/credentials profile
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... prowler aws
prowler aws --profile target --role arn:aws:iam::123456789012:role/SecurityAudit \
    --session-duration 3600                                   # assume a role first
prowler aws -f us-east-1 eu-west-1                            # scope regions (-f/--region)
```

Minimum useful perms: `SecurityAudit` + `ReadOnlyAccess` managed policies (or the
prowler-additions policy from the docs). Partial creds still work — prowler logs
AccessDenied per check and keeps going, so run it with whatever you have.

### Azure
Pick exactly ONE auth flag:

```bash
prowler azure --az-cli-auth                                   # reuse an existing `az login` session
prowler azure --sp-env-auth                                   # service principal from env:
#   AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID
prowler azure --browser-auth --tenant-id 00000000-0000-0000-0000-000000000000
prowler azure --managed-identity-auth                         # from an Azure VM/container you control
prowler azure --az-cli-auth --subscription-ids SUB-ID-1 SUB-ID-2   # scope subscriptions
```

The principal needs `Reader` on target subscriptions; Entra ID checks additionally
want Graph `Directory.Read.All`. Missing perms just reduce coverage.

### GCP
```bash
prowler gcp --credentials-file ./sa.json                      # service-account key
prowler gcp --credentials-file ./sa.json --project-ids proj-example-1 proj-example-2
prowler gcp                                                   # falls back to ADC (gcloud auth application-default login)
prowler gcp --impersonate-service-account scanner@proj-example-1.iam.gserviceaccount.com
```

Without `--project-ids` prowler scans every project the identity can list — do that
when you want the full blast radius of a stolen key.

### Kubernetes
```bash
prowler kubernetes --kubeconfig-file ~/.kube/config --context target-cluster
prowler kubernetes --namespace kube-system default            # scope namespaces
```

## 3. Scope the scan

```bash
prowler aws --list-services                 # enumerate service names
prowler aws --list-checks                   # all check ids
prowler aws --list-compliance               # frameworks (cis_2.0_aws, ens_rd2022_aws, ...)
prowler aws --list-categories               # e.g. internet-exposed

prowler aws --profile target --severity critical high              # only crit/high checks
prowler aws --profile target --services s3 iam ec2 rds lambda      # only these services
prowler aws --profile target --checks s3_bucket_public_access iam_policy_allows_privilege_escalation
prowler aws --profile target --categories internet-exposed         # attack-surface sweep
prowler aws --profile target --compliance cis_2.0_aws              # framework-scoped run
prowler aws --profile target --excluded-services cloudtrail        # skip noisy services
prowler aws --profile target --status FAIL                         # only emit FAILs
```

A good offensive first pass: `--severity critical high --status FAIL` across all
services, then targeted re-runs with `--checks` on anything interesting.

## 4. Output

```bash
prowler aws --profile target \
    --output-formats csv json-ocsf html \
    --output-directory ./out/prowler \
    --output-filename target-aws
```

Files land as `./out/prowler/target-aws.{csv,ocsf.json,html}` (default name embeds
account id + timestamp). `html` is the human report; `*.ocsf.json` is what you parse.
Exit codes: `0` = clean, `3` = FAIL findings exist (success for us; use
`--ignore-exit-code-3` in pipelines that treat nonzero as error), anything else =
runtime error — check `--log-level DEBUG --log-file prowler.log`.

## 5. Read the OCSF JSON

`*.ocsf.json` is a single JSON array of finding records. Per record:

| Field | Meaning |
|---|---|
| `status_code` | `FAIL` / `PASS` / `MANUAL` — filter on FAIL |
| `severity` | `Critical` / `High` / `Medium` / `Low` / `Informational` |
| `metadata.event_code` | the check id, e.g. `s3_bucket_public_access` |
| `finding_info.title` / `finding_info.uid` | human title / stable unique finding id |
| `resources[].uid`, `resources[].region`, `resources[].name` | offending resource ARNs/ids |
| `cloud.provider`, `cloud.account.uid` | provider + account/subscription/project |
| `risk_details` | why it matters |
| `remediation.desc`, `remediation.references` | fix guidance (useful for the report) |
| `status_detail` | per-resource explanation of the FAIL |

Triage order — pick the DIRECTLY EXPLOITABLE FAILs first:

1. **Public data**: `s3_bucket_public_access`, `s3_bucket_policy_public_write_access`,
   public EBS/RDS snapshots, public AMIs, public GCS buckets, public blob containers.
2. **IAM privesc**: `iam_policy_allows_privilege_escalation`,
   `iam_policy_with_full_administrative_privileges` (`iam:*` / `*:*`), wildcard trust,
   cross-account AssumeRole without ExternalId.
3. **Network exposure**: security groups / firewall rules `0.0.0.0/0` to SSH/RDP/DB
   ports, public RDS/SQL/ElastiCache, public EKS/AKS/GKE API endpoints.
4. **Code-exec surface**: unauthenticated Lambda function URLs, public Cloud
   Functions/Run invokers (`allUsers`), exposed app services.
5. **Pivot enablers**: `ec2_instance_imdsv2_enabled` FAILs (IMDSv1 → SSRF credential
   theft), broad Key Vault access policies, secrets in env vars / user data.

Full check→exploit mapping and which sibling skill to load next:
`references/checks-triage.md`.

## 6. Scripted run + work-unit split

```bash
# Run prowler and parse in one shot (writes out/work-units.json + out/assets.json):
python3 scripts/run_prowler.py aws --profile target -f us-east-1 eu-west-1 \
    --severity critical high --output-dir out/prowler --out out/work-units.json

python3 scripts/run_prowler.py azure --az-cli-auth --subscription-ids SUB-ID-1
python3 scripts/run_prowler.py gcp --credentials-file sa.json --project-ids proj-example-1

# Re-parse an existing OCSF file without rescanning:
python3 scripts/run_prowler.py aws --skip-run --output-dir out/prowler

# Or parse directly:
python3 scripts/parse_prowler.py --input out/prowler/target-aws.ocsf.json \
    --out out/work-units.json --assets-out out/assets.json
```

`parse_prowler.py` groups FAIL records by check id, keeps the exploitable ones
(public/privesc/exposure patterns plus everything critical/high; `--all-fails` keeps
every FAIL), and writes a bare JSON array of
`{"id","title","targets","hints"}` — targets are resource UIDs/ARNs, hints carry
`{severity, check_id, region(s), provider, status, risk, count}`. It also writes an
assets list (every resource prowler touched in a FAIL) to `out/assets.json`.

**This step always ends with `out/work-units.json`** — a rupu-ingestible array.
Wiring for fan-out, `assets.mark` and `findings.report`: `references/rupu.md`.

## 7. Hand off

- Each work unit is one attack task: hand `s3_bucket_public_*` units to
  `cloud-storage-exposure`, IAM privesc units to `pmapper`/`pacu`, IMDSv1 units to
  `metadata-ssrf-pivot` — the full routing table is `references/checks-triage.md`.
- Cross-check coverage with `scoutsuite` on the same creds (different rule engine,
  catches different things).
- Report verified issues and mark assets per `references/rupu.md`; chain back to
  `cloud-security` for the overall engagement flow.
