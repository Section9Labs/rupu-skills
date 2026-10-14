---
name: coverage-assets
description: Record every asset the fleet touches (hosts, services, routes, endpoints, cloud resources, files, binaries) into rupu's engagement asset ledger with correct kinds, typed coordinates, and depth rungs, then track assessed-vs-gap coverage. Use whenever an engagement profile is active and you have examined anything — mark it with assets.mark or attach it to findings.report, and consume work-units inventories to mark scope wholesale.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# coverage-assets — the shared asset & coverage ledger

Every skill in the fleet imports this one by name. Its contract: **anything you
examine gets marked as an asset at the depth you actually reached**, so
`coverage.status`, the operator CLI, and agentiflow coverage goals can tell
assessed scope from gaps. Siblings: `work-units` (upstream — supplies the
normalized target inventory you mark), `finding-report` (writes the finding
body; THIS skill owns the `asset` / coordinate part of a finding).

## 1. The asset model

An **asset** is the thing a finding or an examination is about: a service on a
host, a route on a site, an API endpoint, a cloud resource, a file, a function
in a binary. An asset has:

- a **kind** — namespaced `<profile>:<kind>`: `network:service`, `web:route`,
  `api:endpoint`, `cloud:resource`, `code:file`, `binary:function`, …
- a **locator** — a list of typed coordinates (may be empty, e.g. a
  threat-model component)
- an optional **label** (free text; shown in the UI)
- a **depth** — a rung on the owning profile's ladder

### The 13 coordinate types

Every coordinate is encoded `{"t": <tag>, "v": <value>}`. Exact encodings:

| Tag | Encoding | Use |
|-----|----------|-----|
| `path` | `{"t":"path","v":"src/auth/login.py"}` | file or archive path |
| `line_range` | `{"t":"line_range","v":{"start":10,"end":24}}` | lines in a file |
| `symbol` | `{"t":"symbol","v":"parse_token"}` | function/symbol name |
| `commit` | `{"t":"commit","v":"9fceb02d"}` | VCS commit |
| `sha256` | `{"t":"sha256","v":"e3b0c442…"}` | hash of binary/image/package |
| `offset` | `{"t":"offset","v":4096}` | byte offset (integer) |
| `address` | `{"t":"address","v":4198400}` | virtual address (integer) |
| `host` | `{"t":"host","v":"198.51.100.20"}` | hostname or IP |
| `port` | `{"t":"port","v":{"number":443,"proto":"tcp"}}` | proto is `tcp`\|`udp`\|`other` |
| `url` | `{"t":"url","v":"https://shop.example.com"}` | URL |
| `http_route` | `{"t":"http_route","v":{"method":"POST","path":"/cart/apply"}}` | HTTP method + path |
| `param` | `{"t":"param","v":"coupon"}` | request parameter |
| `resource_id` | `{"t":"resource_id","v":{"scheme":"arn","id":"arn:aws:s3:::acme-logs"}}` | cloud resource, purl, objective id |

Never hand-encode these — `python3 scripts/build_coordinates.py` prints the
exact JSON for any of them (see §5).

### Built-in profiles (key rows)

| Profile | Asset kinds → coordinates | Depth ladder |
|---------|---------------------------|--------------|
| `network` | `host` → host; `service` (host) → host, port | discovered → enumerated → tested → exploited |
| `web` | `site` → url; `route` (site) → url, http_route, param | mapped → crawled → tested → exploited |
| `api` | `service` → url; `endpoint` (service) → url, http_route, param | mapped → tested → exploited |
| `cloud` | `account` → resource_id; `resource` (account) → resource_id | inventoried → policy-evaluated → validated |
| `code` | `repo` → path; `file` → path, line_range; `function` → path, symbol, line_range | unreviewed → reviewed |
| `binary` | `binary` → sha256; `function` → sha256, address, symbol | located → disassembled → analyzed |
| `container` | `image` → sha256; `layer` → sha256, path; `package` → resource_id | inventoried → scanned → triaged |
| `sca` | `repo` → path; `dependency` → path, resource_id | inventoried → resolved → triaged |
| `secrets` | `repo` → path; `secret` → path, line_range, commit | scanned → triaged → confirmed |
| `redteam` | `host` → host; `objective` (host) → host, resource_id | planned → executed → validated |

`pentest` is a composite of `network` + `web`; `mobile` composes `binary` +
`web` and adds `mobile:package` (sha256, unpacked → static → dynamic). Full
per-profile cheat sheet with ready-to-send payloads:
[references/profiles.md](references/profiles.md).

### Engagement must be active

`assets.mark` and the `asset` argument of `findings.report` exist only under an
active engagement: `rupu run --engagement-profile <id>`, a workflow started
with `--engagement-profile`, or an agentiflow with `engagement_profiles:`.
**With no engagement active, `assets.mark` is not offered at all and any
`asset` on `findings.report` is silently ignored** — your coverage is lost.
Confirm the engagement before marking. Both tools are injected automatically
for every agent in an engagement run; no `tools:` entry is needed.

## 2. Recording assets — the two writers

Both writers append to the target's ledger
`.rupu/coverage/<target>/assets.jsonl`.

### `assets.mark { kind, coordinates[], depth, label? }`

Records how far an asset was examined. `depth` must be a rung of the owning
profile's ladder — any other value errors, and the error message lists the
ladder, so you can self-correct. **Depth only moves forward**: marking an
`exploited` service as `tested` leaves it at `exploited`. The tool returns the
rung actually recorded as `effective_depth` — read it; if it is higher than
what you sent, someone already went deeper and you can skip re-testing.

Mark on discovery, then re-mark the SAME coordinates as you go deeper:

```json
{ "kind": "network:host",
  "coordinates": [ { "t": "host", "v": "198.51.100.20" } ],
  "depth": "discovered" }
```

After nmap service/version scripts complete, the service rung:

```json
{ "kind": "network:service",
  "coordinates": [ { "t": "host", "v": "198.51.100.20" },
                   { "t": "port", "v": { "number": 8443, "proto": "tcp" } } ],
  "depth": "enumerated",
  "label": "198.51.100.20:8443 admin console" }
```

…then `"depth": "tested"` after vuln checks, `"depth": "exploited"` after a
working exploit. A web route after crawling, then after injection testing:

```json
{ "kind": "web:route",
  "coordinates": [ { "t": "url", "v": "https://shop.example.com" },
                   { "t": "http_route", "v": { "method": "POST", "path": "/cart/apply" } },
                   { "t": "param", "v": "coupon" } ],
  "depth": "crawled" }
```

An API endpoint and a cloud resource:

```json
{ "kind": "api:endpoint",
  "coordinates": [ { "t": "url", "v": "https://api.example.com" },
                   { "t": "http_route", "v": { "method": "GET", "path": "/v1/users/{id}" } } ],
  "depth": "tested" }
```
```json
{ "kind": "cloud:resource",
  "coordinates": [ { "t": "resource_id",
                     "v": { "scheme": "arn", "id": "arn:aws:s3:::acme-prod-backups" } } ],
  "depth": "policy-evaluated" }
```

**Identity.** The asset id is `<kind>:<16 hex>`, derived from the kind plus the
*sorted* locator. The same host:port always maps to the same asset — across
agents, runs and reruns. Marking it again never duplicates; it just advances
depth. So always use canonical coordinate values (same URL origin, same host
string) that the rest of the fleet uses, or you'll fork the asset.

### `findings.report` with an `asset`

When you report a finding about something, attach the asset — the finding is
**routed** by the kind's namespace to the owning profile, which runs its
**required completeness checks** against the report + locator, then **stamps
the asset** in the ledger (keeping its existing depth/parent/label unless you
pass a new label):

```json
{ "scope": "edge-sweep",
  "report": { "...": "complete finding report — see the finding-report skill" },
  "asset": {
    "kind": "network:service",
    "coordinates": [ { "t": "host", "v": "198.51.100.20" },
                     { "t": "port", "v": { "number": 8443, "proto": "tcp" } } ],
    "label": "198.51.100.20:8443 admin console" } }
```

Key completeness checks (fail → finding rejected, error lists the unmet
checks; fix and resubmit): `network` needs **host AND port** in the locator,
plus root_cause and a CVE/CWE; `web` needs an **http_route or url** plus an
**http_exchange evidence block** plus OWASP/CWE; `api` needs http_route + an
http_exchange block; `cloud` needs resource_id + CIS/CWE. Full table in
[references/profiles.md](references/profiles.md). If no active profile owns
the kind, the call fails and the error names the active set.

An asset stamped via a finding and one marked via `assets.mark` with the same
kind + coordinates are the SAME ledger entry — a finding keeps advancing the
asset you discovered earlier. Use `finding-report` (sibling skill) for the
report body; this skill owns getting the `asset` block right.

## 3. Tracking coverage

Agent-side tools (injected, no `tools:` entry): **`coverage.status`** — call it
periodically and before declaring a unit done; it summarizes assessed-vs-gap
progress so you know what's left. **`coverage.remaining`** — on code-path runs,
lists in-scope files still lacking an assertion; drain it to zero. Adjacent but
not this skill's focus: on `concerns:` runs, `coverage.mark` records a
`(concern, file)` verdict with evidence — that is per-concern code coverage,
distinct from the asset ledger, and it coexists with asset marking on hybrid
engagements.

Operator CLI views over the same data:

```bash
rupu coverage list                     # targets under .rupu/coverage/
rupu coverage show <target>            # files touched + assertions + findings
rupu coverage audit <target>           # full report: per-concern coverage, gaps, serendipity
rupu coverage gap <target>             # just the gaps
rupu --format json coverage audit <target>   # machine-readable, for pipelines
```

**The ledger.** `assets.jsonl` is append-only; each line is one full asset
(`id`, `kind`, `parent?`, `locator`, `label`, `depth?`, `attributes`); on read,
the **last line per id wins**. Remote units' lines stream to the coordinator
via `coverage.jsonl` and are merged. The control plane reads it at
`GET /api/assets`: **Security → Assets** lists every asset across workspaces
with profile, kind, label, coordinates, depth; an agentiflow's **Assets** tab
filters by `?ws_id=` / `?target=`.

**Agentiflow coverage goals** measure this ledger — a goal can require a
fraction of a kind's assets to reach a depth rung:

```yaml
goals:
  - coverage: { reach: 0.9, depth: tested, kinds: [network:service] }
  - coverage: { reach: 1.0, depth: crawled, kinds: [web:route] }
```

If you don't mark assets, these goals read zero and the flow never converges.
Mark early (first rung at discovery) and re-mark at every escalation.

## 4. The pipeline: work-units → assets.mark → coverage.status

1. `work-units` (sibling) splits scope into a normalized JSON array of
   `{id,title,targets,hints}` units, e.g. `reports/units.json`.
2. Convert each unit's targets into mark payloads:
   `python3 scripts/assets_from_inventory.py --profile network reports/units.json -o reports/marks.json`
   — or fan out with `for_each: "{{ read_file('reports/units.json') }}"` and
   have each agent call `assets.mark` per target at the first rung on receipt,
   then re-mark as it works.
3. Each agent advances depth as it enumerates/tests/exploits, and attaches the
   asset to every `findings.report`.
4. Call `coverage.status` to decide what's left; the operator audits with
   `rupu coverage audit <target>` and the Security → Assets view; agentiflow
   coverage goals gate completion.

Workflow and agentiflow wiring (YAML snippets, dispatch, remote-unit merge):
[references/rupu.md](references/rupu.md).

## 5. Scripts

- `python3 scripts/assets_from_inventory.py --profile network --depth discovered reports/units.json -o reports/marks.json`
  — turns a work-units array (or a plain host/service/url/path list) into a
  JSON array of ready-to-send `assets.mark` payloads
  `{kind, coordinates, depth, label}` with correct per-profile kinds and
  encodings. `--depth` defaults to the profile's first rung; the ladder is
  validated. Reads stdin if no file given.
- `python3 scripts/build_coordinates.py service 198.51.100.20 8443 --proto tcp`
  — prints the exact `coordinates` JSON array for a given thing. Subcommands:
  `host`, `service`, `url`, `route`, `resource`, `file`. Importable as a
  library too. Use it whenever you'd otherwise hand-write a `{"t","v"}` pair.

## Checklist

- [ ] Engagement active? (`assets.mark` offered) — if not, coverage is lost
- [ ] Every target from the inventory marked at the first rung on receipt
- [ ] Same canonical coordinates reused everywhere (ids are kind + sorted locator)
- [ ] Depth re-marked at every escalation; `effective_depth` read back
- [ ] Every finding carries its `asset`; completeness checks satisfied
- [ ] `coverage.status` clean / coverage goals met before declaring done
