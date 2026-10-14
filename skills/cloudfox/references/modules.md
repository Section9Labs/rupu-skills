# CloudFox AWS modules — full reference, output interpretation, handoffs

Invocation pattern for every module:

```
cloudfox aws --profile <profile> <module> [flags] --outdir ./cloudfox
```

Output lands in `cloudfox-output/aws/<profile>-<acct>/{table,csv,json,loot}/<module>.*`.
Add `-v2` to see which API calls were denied (a denied call means the column is
blank, not that the resource doesn't exist — re-run after privesc).

---

## Attack-surface modules

### endpoints
Enumerates every public endpoint across: APIGateway (REST+HTTP APIs, incl. private
flag), ALB/NLB/Classic ELB, CloudFront distributions, Elastic Beanstalk environments,
Lightsail instances/containers, App Runner services, RDS endpoints, Redshift,
OpenSearch, MQ, Grafana, EKS API endpoints, Cognito user pools, S3 website endpoints.
Columns: service, region, name, endpoint URL, port, protocol, public (true/false).

**Interpret**: `public=true` rows are internet attack surface. API Gateway rows show
stage + route; CloudFront rows show origin (origin may be an "internal" ALB or
private bucket reachable only through the distribution — test both).
**Handoff**: endpoint URLs → web/API testing skills; hostnames → DNS/TLS recon;
the parse script makes one work unit per endpoint.

### inventory
Per-region, per-service resource counts plus total ARNs collected (`json/inventory.json`
is the richest ARN dump). Use it to pick regions; empty regions cost you nothing again.

### instances
EC2 instances: ID, name tag, AZ, state, public IP, private IP, **instance profile ARN**.
Flags: `--instance-id`, `--userdata` (dump user-data inline for one/all instances).

**Interpret**: instance profile attached = the box holds live role credentials at
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`. Any RCE,
SSRF, or SSM access on it yields that role. Compare the profile's role against
`permissions` output to rank targets.
**Loot**: public/private IP lists; GetUserData commands (user-data is base64 —
decode; it very often contains bootstrap secrets); SSM `start-session` and EC2
Instance Connect command stubs for boxes you can reach.
**Handoff**: `metadata-ssrf-pivot` for IMDS theft; port-scan the IP lists.

### elastic-network-interfaces
Every ENI with private/public IP, attached resource type and ID, VPC/subnet.
This is the IP→resource rosetta stone: given an IP from a scan or a log, find what
owns it; given a Lambda/RDS/NAT, find its IPs.

### route53
All hosted zones (public+private) and records. Look for: records pointing at
deprovisioned resources (takeover), internal naming conventions, `dev/staging`
hosts, third-party CNAMEs.

### api-gateway
APIs, stages, routes/resources, and **API keys** where readable. Build full invoke
URLs: `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>`.
Private APIs are reachable from inside the VPC — note them for post-pivot.

---

## Loot modules

### buckets
All S3 buckets, region, and policy summary where readable.
**Loot**: `bucket-commands.txt` — `aws s3 ls s3://<bucket> --profile target` and
sync/cp stubs per bucket. **Handoff**: `cloud-storage-exposure` for public-access
testing and content triage.

### secrets
SecretsManager secret names/ARNs + SSM parameter names (values are NOT pulled —
listing is quiet, GetSecretValue is the loud call you choose to make).
**Loot**: `pull-secrets-commands.txt` with exact per-secret commands:
`aws secretsmanager get-secret-value --secret-id <arn>` and
`aws ssm get-parameter --name <name> --with-decryption`.
**Handoff**: pulled values → `trufflehog` (validate keys, find more creds inside).

### env-vars
Environment variables **with values** from Lambda functions, ECS task definitions,
SageMaker, App Runner. The single highest-yield secret source in most accounts:
`DB_PASSWORD`, `STRIPE_KEY`, `AWS_SECRET_ACCESS_KEY` (yes, hardcoded cross-account
keys appear here). **Handoff**: every value → `trufflehog`; AWS keys found here →
start this skill again against the new principal.

### cloudformation
Stacks with **parameters** and **outputs** (and template availability). Parameters
marked NoEcho still leak via drift/template; outputs commonly expose endpoints,
and parameters expose passwords passed at deploy time.

### ecr
Repositories, URIs, latest tags, push dates. **Loot**: login+pull command stubs
(`aws ecr get-login-password | docker login ...; docker pull <uri>:<tag>`).
Pulled images → `trufflehog filesystem` / docker-layer secret hunting.

### lambda
Functions, runtime, role, public-access flag where resource policy allows.
`aws lambda get-function --function-name X` returns a **presigned S3 URL** to the
code zip — download and grep. Loot file contains these commands.

### sns / sqs
Topics/queues with resource policies. Flags: `cloudfox aws sns --profile target`
checks for principals `*` (public subscribe/publish) — public SQS receive leaks
message bodies (often webhooks with tokens).

### filesystems
EFS filesystems and FSx shares + mount targets and whether an access policy gates
them. Mountable from any compromised VPC host: `mount -t nfs4 <mt-ip>:/ /mnt/efs`.

### databases
RDS/Aurora, Redshift, DocDB, Neptune endpoints + engine + public flag. Pair with
creds from `env-vars`/`secrets`/CloudFormation params.

### ram
AWS Resource Access Manager shares — resources shared *to* or *from* this account.
Inbound shares = resources in other accounts you can already touch; outbound shares
map the organization.

### tags
All tagged resources. Grep tags for `owner`, `env`, `project` — targeting intel.

---

## IAM / privesc modules

### permissions
Effective permissions per principal, expanded from attached+inline policies (and
group membership). Filter: `--principal arn:aws:iam::123456789012:role/app-role`.
**Interpret**: hunt for `*` on Action or Resource, `iam:PassRole` + `ec2:RunInstances`
/ `lambda:CreateFunction`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`,
`sts:AssumeRole` on broad resources, `ssm:SendCommand`, `secretsmanager:GetSecretValue`.
**Handoff**: this table seeds `pmapper` queries and `pacu` privesc modules.

### role-trusts
Every role's trust policy decomposed: trusted AWS principals (account root, user,
role), trusted services, OIDC/SAML federation (incl. GitHub Actions `sub` claims —
check for wildcard repo patterns), external-ID requirements.
**Interpret**:
- Trusted principal in **another account** → cross-account pivot; if you control the
  trusted side, `aws sts assume-role --role-arn <arn> --role-session-name x`.
- Trusted principal `*` or whole-account root with no external ID → anyone in that
  account (or anyone at all) can assume.
- `cognito-identity` / OIDC trusts with weak conditions → unauthenticated assumption.
**Handoff**: `pmapper` edges; direct `sts assume-role` attempts.

### principals
All IAM users and roles (names + ARNs). Baseline list for `pmapper --create-graph`.

### access-keys
Every user's access key IDs, status, create date. Match an `AKIA...` you found in
code/logs to its owning user; old-but-Active keys are rotation-failure targets.

### outbound-assumed-roles
From CloudTrail: AssumeRole events *initiated by* this account's principals toward
other accounts. Maps the real cross-account mesh (role-trusts shows inbound; this
shows outbound). Each foreign role ARN is a new objective.

### resource-trusts
Resource-based policies (S3, SNS, SQS, KMS, Lambda, ECR...) that trust external
principals or `*` — resource-level cross-account access that IAM-only review misses.

### iam-simulator
Runs `iam:SimulatePrincipalPolicy` style checks for interesting actions per
principal: `cloudfox aws iam-simulator --principal <arn> --action s3:GetObject --resource '*'`.
Use to confirm a suspected permission without performing the action itself.

### workloads
Compute workloads (EC2/ECS/Lambda/etc.) ranked by the privilege of their attached
role — "which box do I pop for admin". Prioritize shells accordingly.

---

## Azure modules

- `whoami` — current principal, tenant, subscriptions reachable.
- `rbac --tenant <tid>` — role assignments per principal per scope; hunt Owner,
  Contributor, User Access Administrator, and custom roles with `*` actions.
- `storage --subscription <sub>` — storage accounts, containers, **public access
  level**; public containers → `cloud-storage-exposure`.
- `instances --subscription <sub>` — VMs, public/private IPs, managed identities
  (managed identity = Azure's instance profile; same IMDS theft logic at
  `169.254.169.254/metadata/identity/oauth2/token`).
- `inventory` — resource counts per subscription.

---

## Module → sibling skill handoff map

| CloudFox output | Hand to |
|---|---|
| permissions, role-trusts, principals, iam-simulator | `pmapper`, `pacu` |
| buckets (+ loot bucket-commands), azure storage | `cloud-storage-exposure` |
| secrets values, env-vars, user-data, CFN params, ECR images, lambda code | `trufflehog` |
| instances + instance profiles, azure instances + managed identities | `metadata-ssrf-pivot` |
| endpoints, api-gateway, route53 | web/API/DNS skills via `cloud-security` |
| outbound-assumed-roles, ram, resource-trusts | new-account targeting → rerun this skill |
