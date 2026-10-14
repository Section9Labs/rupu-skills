---
name: cloudfox
description: Enumerate cloud attack surface with BishopFox CloudFox — run aws all-checks (endpoints, instances, buckets, secrets, env-vars, permissions, role-trusts and more) plus the Azure modules, read the table/csv/json/loot output, execute the ready-to-run loot commands, and split results into work units for privesc and loot follow-up.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# CloudFox — operator-oriented cloud attack-surface enumeration

CloudFox (Bishop Fox, Go, single binary) answers the questions an operator asks after
landing credentials: *what is public, where are the secrets, which principals can I
become, which instances carry roles I can steal?* AWS is the primary target; Azure and
GCP have a smaller module set. Use this skill the moment you obtain any cloud
credential (profile, access key pair, assumed-role session, instance-profile creds).
It is the enumeration front end of the `cloud-security` umbrella skill.

## 1. Setup and credentials

CloudFox uses standard AWS credential resolution: `--profile <name>` reads
`~/.aws/credentials` / `~/.aws/config` (including `role_arn` + `source_profile`
chains and SSO profiles), or set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_SESSION_TOKEN` in the environment. Verify first:

```
aws sts get-caller-identity --profile target
cloudfox aws --profile target inventory
```

Useful global flags: `-o / --outdir <dir>` (output root), `-v2` (verbose, shows
permission errors per API call — tells you *which* reads you lack), `--max-goroutines N`
(concurrency), `-r / --regions` on some modules.

## 2. Run everything

```
cloudfox aws --profile target all-checks --outdir ./cloudfox
```

Multiple profiles: `cloudfox aws --profiles ./profiles.txt all-checks` (one profile
per line) or `--all-profiles`. `all-checks` runs every AWS module; it is read-only
API calls (`Describe*/List*/Get*`), noisy in CloudTrail but non-destructive.

## 3. Key AWS modules and the lead each one gives

Run any module standalone: `cloudfox aws --profile target <module>`.

| Module | Yields | Operator lead |
|---|---|---|
| `endpoints` | Every public endpoint: ALB/NLB, API Gateway, CloudFront, Elastic Beanstalk, Lightsail, App Runner, RDS, OpenSearch, Redshift, Cognito, Grafana, EKS, MQ | Web/API attack surface → hand hostnames to recon/web skills |
| `inventory` | Resource counts per service/region | Where the account actually lives; which regions to focus |
| `instances` | EC2: instance IDs, public+private IPs, **attached instance profiles** | Instance profile = role creds via IMDS → `metadata-ssrf-pivot`; `loot/` has GetUserData + EC2-connect commands |
| `buckets` | All S3 buckets + policy hints | → `cloud-storage-exposure`; `loot/bucket-commands.txt` is ready to run |
| `secrets` | SecretsManager secrets + SSM parameter **names** (not values) | `loot/pull-secrets-commands.txt` = exact `get-secret-value` / `get-parameter --with-decryption` commands |
| `env-vars` | Lambda, ECS task-def, SageMaker, App Runner environment variables **with values** | Secret goldmine: DB creds, API keys → `trufflehog` |
| `permissions` | Effective IAM permissions per principal; filter one: `--principal arn:aws:iam::123456789012:role/app-role` | Spot `iam:*`, `sts:AssumeRole`, `iam:PassRole`, `*:*` → `pmapper`/`pacu` |
| `role-trusts` | Trust policy of every role: which principals (incl. **cross-account**, services, OIDC/SAML) can assume it | Assume-role abuse; wildcard or foreign-account trust = direct pivot |
| `access-keys` | All IAM users' access key IDs + status | Match a found key to its user; stale active keys |
| `principals` | All users/roles in the account | Feed `pmapper` graph |
| `route53` | All hosted zones + records | Subdomain takeover candidates, internal naming |
| `ram` | Resources shared via Resource Access Manager | Cross-account resource access already granted |
| `ecr` | Repositories + latest image tags | `loot/` has docker pull commands → scan images with `trufflehog` |
| `elastic-network-interfaces` | Every ENI: IP ↔ attached resource mapping | Resolve "whose IP is this" in both directions |
| `cloudformation` | Stacks, **parameters and outputs** | Params/outputs frequently contain passwords and endpoints |
| `lambda` | Functions, runtimes, roles | `loot/` has get-function commands (presigned code download) |
| `outbound-assumed-roles` | CloudTrail-derived: roles *this* account assumed elsewhere | Map outbound cross-account trust → more accounts to hit |
| `api-gateway` | API endpoints + routes + **API keys** | Direct API attack surface |
| `sns` / `sqs` | Topics/queues + resource policies | Public-subscribable topics, readable queues (messages carry data/creds) |
| `filesystems` | EFS/FSx + mount targets | Mountable file shares |
| `databases` | RDS/Redshift/DocDB endpoints | Pair with creds from `env-vars`/`secrets` |
| `tags` / `resource-trusts` / `iam-simulator` / `workloads` | Supporting context | See `references/modules.md` |

Full per-module interpretation: `references/modules.md`.

## 4. Azure (and GCP)

```
cloudfox azure whoami    --tenant 00000000-0000-0000-0000-000000000000
cloudfox azure rbac      --tenant <tid>                       # role assignments per principal
cloudfox azure storage   --subscription <sub-id>              # storage accounts + public containers
cloudfox azure instances --subscription <sub-id>              # VMs, IPs, managed identities
cloudfox azure inventory --subscription <sub-id>
```

Auth via Azure CLI session (`az login`) or env vars. GCP support is early
(`cloudfox gcp ...` where present); prefer dedicated GCP tooling otherwise.

## 5. Output layout — always read loot/

```
cloudfox-output/aws/<profile>-<accountID>/
  table/   # human-readable, what the terminal showed
  csv/     # grep/sort friendly
  json/    # machine-readable — feed to parse_cloudfox.py
  loot/    # READY-TO-RUN follow-up commands and raw loot
```

`loot/` is the handoff. Typical files and what to do:

- `pull-secrets-commands.txt` — exact `aws secretsmanager get-secret-value` /
  `aws ssm get-parameter --with-decryption` lines. Run them, pipe values to `trufflehog`.
- `bucket-commands.txt` — `aws s3 ls/cp` per bucket. Run or hand to `cloud-storage-exposure`.
- `instances-ec2PrivateIPs.txt` / `instances-ec2PublicIPs.txt` — target lists for port scans.
- `instances-ssm-GetUserData-commands.txt` (or similar) — pull user-data per instance;
  user-data routinely contains bootstrap credentials.
- `ecr-pull-commands.txt`, `lambda-get-function-commands.txt`, EC2 Instance Connect /
  SSM `start-session` command files — direct shell/loot paths.
- `role-trusts-*.txt` — assume-role command stubs for assumable roles.

Review every loot file; execute what the current credential permits; anything that
fails with AccessDenied is a privesc objective for `pmapper`/`pacu`.

## 6. Parse to work units (rupu handoff)

```
python3 scripts/run_cloudfox.py --profile target --outdir ./cloudfox     # or --skip-run
python3 scripts/parse_cloudfox.py --dir ./cloudfox --out out/work-units.json --assets out/assets.json
```

`parse_cloudfox.py` walks the `json/` outputs and emits a bare JSON array of work
units — one per public endpoint, per bucket, per principal-with-privesc-lead
(instance profiles, cross-account/wildcard role trusts), per secret/env-var —
each `{"id","title","targets","hints":{"module","account","region",...}}` — plus an
assets list (endpoints, instances, buckets, principals, secrets). Fan-out wiring,
`assets.mark`, and `findings.report` usage: `references/rupu.md`.

## 7. Chain to sibling skills

- **IAM privesc**: `permissions`, `role-trusts`, `principals` output → `pmapper`
  (graph who-can-become-whom) and `pacu` (exploit the path).
- **Buckets**: `buckets` + `loot/bucket-commands.txt` → `cloud-storage-exposure`.
- **Secrets**: `secrets`, `env-vars`, CloudFormation params, pulled user-data →
  `trufflehog` to validate/expand every credential found.
- **Instances**: `instances` + instance profiles → `metadata-ssrf-pivot` (IMDS cred
  theft from any code-exec/SSRF on the box); public IPs → network/web skills.
- Everything rolls back up to the `cloud-security` umbrella skill.
