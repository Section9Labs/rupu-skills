# Cloud Assessment Methodology — Full Flow

Companion depth for the `cloud-security` umbrella. Load the sub-skills named
per phase; this file holds the discipline that makes the loop converge.

## 0. The loop, restated precisely

```
┌─> credential
│      │ Phase 1: cloud-credential-enumeration (recognize + whoami)
│      v
│   identity (account/tenant/project + principal)
│      │ Phase 2: prowler / scoutsuite / cloudsploit / steampipe
│      v
│   posture failures (leads)
│      │ Phase 3: cloudfox / aws-enumeration / azure-enumeration /
│      │          azure-entra-id / gcp-enumeration
│      v
│   resource & attack-surface map
│      │ Phase 4: pmapper / pacu / cloud-privilege-escalation
│      v
│   escalated principal ──────────────────────────┐
│      │ Phase 5: cloud-storage-exposure          │
│      │ Phase 6: trufflehog + native stores      │
│      │ Phase 7: metadata-ssrf-pivot             │
│      v                                          │
└── NEW credentials <─────────────────────────────┘
```

Invariant: **every** new credential, token, SAS URL, SA key, or assumed role
re-enters at Phase 1 whoami. No exceptions — a credential run through phases
2–7 under an assumed identity poisons your map.

## 1. Phase 1 — credential discovery & identity

Sub-skill: `cloud-credential-enumeration`.

Checklist per credential:

1. Classify material (see table in SKILL.md). For JWTs, base64-decode the
   payload and read `aud`, `tid`, `oid`, `appid`, `scp`/`roles`, `exp`.
2. whoami:
   - AWS: `aws sts get-caller-identity` — note Account, Arn, UserId. For
     `ASIA` keys the session token is mandatory
     (`AWS_SESSION_TOKEN`). If `sts` is denied, try
     `aws sts get-access-key-info --access-key-id AKIA...` from any other
     credential to learn the account id without touching the target key's
     CloudTrail.
   - Azure: `az login --service-principal -u <appId> -p <secret> --tenant
     <tid>` then `az account show`, `az account list --all`. For raw tokens:
     call `https://management.azure.com/subscriptions?api-version=2022-12-01`
     or Microsoft Graph `/v1.0/me` depending on `aud`.
   - GCP: `gcloud auth activate-service-account --key-file sa.json`,
     `gcloud auth list`, `gcloud projects list`. For `ya29.` tokens:
     `https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=...` gives
     scopes and the bound SA email.
3. Record in the credential graph (below) **before** heavy enumeration.
4. Enumerate your own permissions early: AWS
   `iam list-attached-user-policies`/`get-user` (or pacu
   `iam__enum_permissions`), Azure `az role assignment list --assignee <id>
   --all`, GCP `gcloud projects get-iam-policy` or `testIamPermissions`
   brute-force via `gcp-enumeration`.

## 2. Phase 2 — posture scanners, when to use which

| Tool / skill | Shape | Use when |
|---|---|---|
| `prowler` | Check library, CIS/NIST/compliance mapped, OCSF JSON + HTML | Default breadth pass; machine-parsable seed for work units |
| `scoutsuite` | Collect-then-render per-service HTML model | You want to browse/understand the environment, screenshot evidence |
| `cloudsploit` | Node plugin scanner, JSON/CSV | Fast repeat/diff runs between loop iterations, CI-style |
| `steampipe` | SQL over live APIs + CIS benchmark mods | Targeted questions; joining across services (e.g. instances × SGs × public IPs) |

Prioritize these failure classes into Phase 3–7 work units:
public storage → `cloud-storage-exposure`; wildcard/overbroad IAM →
`pmapper`/`cloud-privilege-escalation`; logging disabled (CloudTrail off,
diagnostic settings missing, audit sinks absent) → note as T1562.008 and as a
stealth opportunity; open security groups / public endpoints → attack-surface
map; IMDSv1 allowed → `metadata-ssrf-pivot`.

## 3. Phase 3 — iteration discipline (all regions / subscriptions / projects)

**AWS — all regions, every service that is regional:**

```sh
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' -o text); do
  aws ec2 describe-instances --region "$r" ...
done
```

Also check for regions disabled-by-default being enabled
(`aws account list-regions`). Lambda, EC2, secrets, SSM parameters are all
regional; IAM and S3 namespaces are global but S3 buckets live in regions.
`cloudfox` handles multi-region automatically — still verify its region list.

**Azure — all subscriptions, plus the directory plane:**

```sh
az account list --all --query '[].{id:id,name:name}' -o table
for s in $(az account list --all --query '[].id' -o tsv); do
  az resource list --subscription "$s" -o table
done
```

Management groups (`az account management-group list`) show inheritance —
a role assignment at MG level cascades to every child subscription. Entra ID
(`azure-entra-id`) is enumerated once per tenant, not per subscription.

**GCP — all projects + folder/org level:**

```sh
gcloud projects list --format='value(projectId)'
gcloud organizations list
gcloud resource-manager folders list --organization=ORG_ID
for p in $(gcloud projects list --format='value(projectId)'); do
  gcloud compute instances list --project "$p" ...
done
```

IAM is additive down the hierarchy: org → folder → project → resource. An
org-level `roles/editor` grant invisible at project level is a classic miss.
Check `gcloud projects get-ancestors-iam-policy` where permitted.

The thing that escalates you is almost always in the region/subscription/
project that the defenders forgot. Enumerate all of them, every loop pass.

## 4. Phase 4 — IAM graph & privesc

Order of operations on AWS:

1. `pmapper graph create` with the current credential → full account IAM
   graph.
2. `pmapper query 'preds of policy arn:aws:iam::aws:policy/AdministratorAccess'`
   and `pmapper argquery --preset privesc --skip-admin` → candidate paths.
3. Hand the chosen path to `pacu`: `run iam__privesc_scan` (confirms + can
   execute), or run the specific module for the edge (e.g.
   `iam__backdoor_users_keys`, `lambda__backdoor_new_roles`,
   PassRole-to-Lambda/EC2/CloudFormation chains).
4. New keys / assumed role → Phase 1.

Azure: `azure-entra-id` for directory-role paths (Application Administrator →
add credential to a privileged SP; Privileged Role Admin; group-owner on
role-assignable group), `cloud-privilege-escalation` for ARM paths (Owner /
User Access Administrator / `Microsoft.Authorization/roleAssignments/write`,
VM run-command, automation accounts, managed-identity theft).

GCP: `cloud-privilege-escalation` for `iam.serviceAccounts.actAs` +
compute/cloudfunctions/run deploy chains, `iam.serviceAccountKeys.create`,
`setIamPolicy` at any hierarchy level, `iam.serviceAccounts.getAccessToken`
(impersonation), and cloudbuild/dataflow default-SA abuse.

## 5–7. Loot phases

- Storage (`cloud-storage-exposure`): test anonymous AND cross-account/
  any-authenticated access (AWS AuthenticatedUsers ACL, Azure
  "allow public" + SAS, GCS allUsers/allAuthenticatedUsers). Prize files:
  `*.tfstate`, `.env`, `*.pem/ppk`, CI config, DB dumps, `credentials`,
  `kubeconfig`.
- Secrets (`trufflehog`): point at loot directories, cloned repos
  (`trufflehog git`), buckets (`trufflehog s3/gcs`), images
  (`trufflehog docker`); trust `--only-verified` hits as live. Then dump
  native stores with the credential you have: Secrets Manager
  `list-secrets`/`get-secret-value`, SSM `get-parameters-by-path --recursive
  --with-decryption`, Key Vault `az keyvault secret list/show` (watch for
  vault access policies vs RBAC), GCP `gcloud secrets versions access latest`.
- Metadata (`metadata-ssrf-pivot`): from SSRF/RCE/shell, pull instance
  credentials; from inside a container check the ECS endpoint
  (`169.254.170.2` + `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and the
  pod-level service account.

## ATT&CK (Enterprise v18, IaaS/Identity-Provider/SaaS/Office-Suite) × CIS × loop

| Loop phase | ATT&CK techniques (representative) | CIS Foundations area |
|---|---|---|
| 1 Credential/identity | T1078.004 Valid Accounts: Cloud; T1552.001 Credentials in Files; T1606 Forge Web Credentials | 1.x Identity & access |
| 2 Posture | (defender view of all below); T1562.008 Disable/Modify Cloud Logs as a lead | 3.x Logging, 4.x Monitoring |
| 3 Enumeration | T1580 Cloud Infrastructure Discovery; T1526 Cloud Service Discovery; T1087.004 Account Discovery: Cloud | — (discovery) |
| 4 Privesc | T1098.001/.003 Account Manipulation (keys, roles); T1484 Domain/Tenant Policy Modification; T1548.005 Abuse Elevation (temp cloud access) | 1.x IAM hardening |
| 5 Storage | T1530 Data from Cloud Storage; T1619 Cloud Storage Object Discovery | 2.x Storage |
| 6 Secrets | T1552.001/.004/.006 Unsecured Credentials; T1555.006 Cloud Secrets Mgmt Stores | 1.x / 2.x |
| 7 Metadata | T1552.005 Cloud Instance Metadata API | 2.x/5.x Compute & network |
| Loop re-entry | T1078.004 again — the dominant vector, every pass | — |

## Credential → identity graph discipline

Maintain one table/graph for the whole engagement:

```
cred_id | material (type, redacted ref) | provider | account/tenant/project
        | principal (ARN / objectId / SA email) | obtained_from (cred_id + how)
        | perms summary | status (live/expired/revoked) | first/last used
```

Rules:

1. Node = credential; edge = "obtained_from". The root nodes are whatever the
   operator started with; the tree depth is your privesc narrative and goes
   straight into `findings.report` evidence.
2. Never enumerate under a credential not yet in the table.
3. On expiry (`ExpiredToken`, 401), check whether its edge is replayable
   (re-run the SSRF, re-read the secret, re-assume the role) before dropping
   it.
4. Dedup by principal: two keys for the same user are one principal, two
   nodes. Phase 2–4 runs are per-principal, not per-key.
5. Loop exit: a full pass adds zero nodes and zero new
   accounts/subscriptions/projects.

Record every node with `assets.mark` and the merged units with
`scripts/merge_work_units.py` — wiring in `references/rupu.md`.
