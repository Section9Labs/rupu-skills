# Profile cheat sheet — kinds, coordinates, ladders, payloads

Everything an agent needs to mark an asset correctly in any built-in
engagement profile. All payloads are the `assets.mark` argument shape
`{kind, coordinates, depth, label?}`; the same `kind` + `coordinates` block is
what goes in `findings.report`'s `asset`.

## Coordinate encoding table (authoritative)

Every coordinate is `{"t": <tag>, "v": <value>}`. Copy these exactly.

| Tag | `v` type | Example |
|-----|----------|---------|
| `path` | string | `{"t":"path","v":"src/auth/login.py"}` |
| `line_range` | object | `{"t":"line_range","v":{"start":10,"end":24}}` |
| `symbol` | string | `{"t":"symbol","v":"parse_token"}` |
| `commit` | string | `{"t":"commit","v":"9fceb02d0ae598e95dc970b74767f19372d61af8"}` |
| `sha256` | string (64 hex) | `{"t":"sha256","v":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}` |
| `offset` | integer | `{"t":"offset","v":4096}` |
| `address` | integer | `{"t":"address","v":4198400}` (not a hex string — decimal int) |
| `host` | string | `{"t":"host","v":"198.51.100.20"}` or `{"t":"host","v":"vpn.example.com"}` |
| `port` | object | `{"t":"port","v":{"number":8443,"proto":"tcp"}}` — proto ∈ `tcp`,`udp`,`other` |
| `url` | string | `{"t":"url","v":"https://shop.example.com"}` |
| `http_route` | object | `{"t":"http_route","v":{"method":"POST","path":"/cart/apply"}}` |
| `param` | string | `{"t":"param","v":"coupon"}` |
| `resource_id` | object | `{"t":"resource_id","v":{"scheme":"arn","id":"arn:aws:s3:::acme-logs"}}` |

Common mistakes that fork or break assets: port as a bare integer; `address`
as `"0x401000"`; URL once with and once without a trailing slash; `http_route`
path with query string baked in (put the query key in a `param` coordinate
instead); `resource_id` as a plain string.

A locator can be empty (`"coordinates": []`) — e.g. `threat-model:component`.

## Asset identity

`id = <kind> + hash(sorted locator)` → `<kind>:<16 hex>`. Consequences:

- Same host+port → same asset, across agents, runs, reruns. Marking again
  advances depth, never duplicates.
- Different coordinate *values* → different asset. Normalize before marking:
  one canonical hostname per host (IP or FQDN — pick one per engagement),
  URL = scheme + host (+ non-default port) with no path, route path templated
  (`/v1/users/{id}`, not `/v1/users/42`).
- Extra coordinates change the id: `web:route` with a `param` is a different
  asset from the same route without it. Decide per engagement whether routes
  are tracked per-param or per-route and stick to it.

## network — Network security assessment

Ladder: `discovered → enumerated → tested → exploited`

| Kind | Coordinates | Rung guidance |
|------|-------------|---------------|
| `network:host` | host | discovered = responds / in scan output; enumerated = ports swept; tested = services probed; exploited = foothold |
| `network:service` (child of host) | host, port | discovered = open port seen; enumerated = version/banner/scripts done; tested = vuln checks / auth attacks run; exploited = working exploit |

```json
{ "kind": "network:service",
  "coordinates": [ { "t": "host", "v": "198.51.100.20" },
                   { "t": "port", "v": { "number": 445, "proto": "tcp" } } ],
  "depth": "tested",
  "label": "198.51.100.20:445 SMB" }
```

Finding completeness: locator needs **host AND port** (`service_identified`),
report needs `root_cause` and a CVE or CWE classification. Evidence blocks
accepted: text, table, scan_output, http_exchange, pcap_ref.

## web — Web application assessment

Ladder: `mapped → crawled → tested → exploited`

| Kind | Coordinates |
|------|-------------|
| `web:site` | url |
| `web:route` (child of site) | url, http_route, param |

```json
{ "kind": "web:route",
  "coordinates": [ { "t": "url", "v": "https://shop.example.com" },
                   { "t": "http_route", "v": { "method": "POST", "path": "/cart/apply" } },
                   { "t": "param", "v": "coupon" } ],
  "depth": "exploited",
  "label": "coupon apply — SQLi" }
```

Finding completeness: `http_route` or `url` in the locator, an
**http_exchange** evidence block, OWASP or CWE classification.

## api — API security assessment

Ladder: `mapped → tested → exploited` (no `crawled` rung — don't reuse web's)

| Kind | Coordinates |
|------|-------------|
| `api:service` | url |
| `api:endpoint` (child of service) | url, http_route, param |

```json
{ "kind": "api:endpoint",
  "coordinates": [ { "t": "url", "v": "https://api.example.com" },
                   { "t": "http_route", "v": { "method": "GET", "path": "/v1/users/{id}" } } ],
  "depth": "tested" }
```

Finding completeness: `http_route` required, plus an http_exchange block.
Taxonomies: OWASP-API, CWE.

## cloud — Cloud configuration review

Ladder: `inventoried → policy-evaluated → validated`

| Kind | Coordinates |
|------|-------------|
| `cloud:account` | resource_id |
| `cloud:resource` (child of account) | resource_id |

```json
{ "kind": "cloud:resource",
  "coordinates": [ { "t": "resource_id",
                     "v": { "scheme": "arn", "id": "arn:aws:iam::123456789012:role/ci-deployer" } } ],
  "depth": "validated",
  "label": "ci-deployer role — AssumeRole from *" }
```

Account example: `{"scheme":"arn","id":"arn:aws:organizations::123456789012:account/o-ex/123456789012"}`.
Non-AWS: use the provider's native scheme (`gcp`, `azure`, …) with the full
resource path as `id`. Finding completeness: resource_id + CIS or CWE.

## code — Source code review (default profile)

Ladder: `unreviewed → reviewed`

| Kind | Coordinates |
|------|-------------|
| `code:repo` | path |
| `code:file` (repo) | path, line_range |
| `code:function` (file) | path, symbol, line_range |

```json
{ "kind": "code:function",
  "coordinates": [ { "t": "path", "v": "src/auth/login.py" },
                   { "t": "symbol", "v": "verify_token" },
                   { "t": "line_range", "v": { "start": 88, "end": 131 } } ],
  "depth": "reviewed" }
```

Finding completeness: `path` in locator, `root_cause` filled.

## binary — Binary reverse engineering

Ladder: `located → disassembled → analyzed`

| Kind | Coordinates |
|------|-------------|
| `binary:binary` | sha256 |
| `binary:function` (binary) | sha256, address, symbol |

```json
{ "kind": "binary:function",
  "coordinates": [ { "t": "sha256", "v": "9b74c9897bac770ffc029102a200c5de3f93f4504f4f70bd7f5f1dd9b6f3e8a2" },
                   { "t": "address", "v": 4210224 },
                   { "t": "symbol", "v": "parse_packet" } ],
  "depth": "analyzed" }
```

Finding completeness: a `disasm` or `hexdump` evidence block, `root_cause`, a
CWE.

## container — Container image assessment

Ladder: `inventoried → scanned → triaged`. Kinds: `container:image` → sha256;
`container:layer` (image) → sha256, path; `container:package` (image) →
resource_id (a purl):

```json
{ "kind": "container:package",
  "coordinates": [ { "t": "resource_id",
                     "v": { "scheme": "purl", "id": "pkg:deb/debian/openssl@3.0.11-1" } } ],
  "depth": "triaged" }
```

Finding completeness: resource_id or path, plus a CVE.

## sca — Software composition analysis

Ladder: `inventoried → resolved → triaged`. Kinds: `sca:repo` → path;
`sca:dependency` (repo) → path, resource_id (purl). Finding completeness:
resource_id (a purl) + CVE or GHSA.

```json
{ "kind": "sca:dependency",
  "coordinates": [ { "t": "path", "v": "package-lock.json" },
                   { "t": "resource_id", "v": { "scheme": "purl", "id": "pkg:npm/lodash@4.17.20" } } ],
  "depth": "triaged" }
```

## secrets — Secret scanning

Ladder: `scanned → triaged → confirmed` (confirmed = the credential works).
Kinds: `secrets:repo` → path; `secrets:secret` (repo) → path, line_range,
commit. Finding completeness: path AND line_range + a CWE.

```json
{ "kind": "secrets:secret",
  "coordinates": [ { "t": "path", "v": "deploy/settings.py" },
                   { "t": "line_range", "v": { "start": 14, "end": 14 } },
                   { "t": "commit", "v": "9fceb02d0ae598e95dc970b74767f19372d61af8" } ],
  "depth": "confirmed" }
```

## redteam — Red team operation

Ladder: `planned → executed → validated`. Kinds: `redteam:host` → host;
`redteam:objective` (host) → host, resource_id (objective id — pick an
engagement-local scheme). Finding completeness: an ATT&CK classification +
`description` narrative.

```json
{ "kind": "redteam:objective",
  "coordinates": [ { "t": "host", "v": "203.0.113.15" },
                   { "t": "resource_id", "v": { "scheme": "objective", "id": "dc-dump-ntds" } } ],
  "depth": "executed" }
```

## Remaining profiles, briefly

| Profile | Kinds → coordinates | Ladder |
|---------|---------------------|--------|
| `firmware` | image → sha256; partition → sha256, path; file → path, sha256; function → path, address, symbol | acquired → extracted → unpacked → analyzed |
| `iac` | repo → path; resource (repo) → path, line_range | mapped → reviewed |
| `threat-model` | system → (none); component (system) → (none) | modeled → reviewed |
| `mobile` | package → sha256 (composite: also all `binary` and `web` kinds) | unpacked → static → dynamic |
| `pentest` | composite of `network` + `web`; no kinds or ladder of its own — mark with `network:*` and `web:*` kinds | — |

## Depth semantics recap

- `depth` must be a rung of the owning profile's ladder; anything else errors
  and the error lists the ladder.
- Forward-only. The returned `effective_depth` is the recorded rung — if it's
  higher than what you sent, another agent already went deeper.
- Depth is independent of findings: an asset can be `exploited` with zero
  findings recorded, or `discovered` with ten. Mark both honestly.
