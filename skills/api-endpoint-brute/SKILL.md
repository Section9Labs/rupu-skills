---
name: api-endpoint-brute
description: Brute-force hidden API routes and operations with kiterunner (kr scan/brute using .kite request corpora) and ffuf as a plain-path fallback, when no complete OpenAPI/Swagger spec exists; normalizes hits into rupu work units, marks api:service/api:endpoint coverage, and hands gated routes to authorization testing. Use as phase 1 of the api-testing flow whenever endpoint discovery is incomplete.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Endpoint Brute-Forcing

Discover undocumented API routes when the spec is missing or incomplete. The
primary tool is **kiterunner** (`kr`, by Assetnote): unlike a plain path
brute-forcer, it replays *full requests* — method + path + path/query
parameters + headers — from a compiled `.kite` route database, so it finds
routes that only answer to `POST /v1/orders` with a JSON body, not just
`GET`-able paths. **ffuf** is the fallback for raw path discovery.

Full flag reference and `.kite` internals: `references/kiterunner.md`.
rupu wiring (fan-out, assets, findings): `references/rupu.md`.

## Workflow

1. **Setup** — install `kr`, fetch `.kite` wordlists.
2. **Scan** — `kr scan` with `routes-large.kite` (or `routes-small.kite` for a
   fast first pass) against each API host.
3. **Brute** — `kr brute` with a text wordlist for paths outside the route DB;
   ffuf for anything kr can't express.
4. **Spec merge** — if any spec fragment was found, compile it to `.kite` and
   scan with it too, so documented and brute-forced coverage combine.
5. **Parse & hand off** — `scripts/parse_kr.py` normalizes hits, emits
   `reports/api-units.json` work units, you mark assets and dispatch.

## 1. Setup

```sh
# Release binary (preferred)
wget https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_linux_amd64.tar.gz
tar xzf kiterunner_linux_amd64.tar.gz && mv kr /usr/local/bin/

# Or build from source (Go >= 1.16)
git clone https://github.com/assetnote/kiterunner && cd kiterunner && make build
ln -s "$(pwd)/dist/kr" /usr/local/bin/kr

# Route databases (Assetnote wordlists, hosted at wordlists.assetnote.io)
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
tar xzf routes-large.kite.tar.gz; tar xzf routes-small.kite.tar.gz
```

Or let kr fetch Assetnote wordlists by alias: `kr wordlist list` shows the
catalogue; `-A=apiroutes-210328` downloads/caches and uses one inline.
Append `:N` to head-limit (e.g. `-A=apiroutes-210328:20000` = top 20k routes).

**Caveat:** the `.kite` protobuf format is version-unstable — after upgrading
`kr`, recompile any custom `.kite` files from their Kitebuilder JSON sources
(`kr kb compile in.json out.kite`). Also ignore third-party guides showing
`-u`/`-c` flags; they are not in the official README.

## 2. Primary scan — `kr scan`

```sh
# Single host
kr scan https://api.example.com -w routes-large.kite -o json \
  | tee kr-api.json

# Many hosts (one per line in targets.txt; schemes/ports auto-expanded)
kr scan targets.txt -w routes-large.kite \
  -x 10 -j 50 --fail-status-codes 400,401,404,403,501,502,426,411 \
  -o json | tee kr-fleet.json

# Authenticated scan — repeatable -H; note kr sends
# "x-forwarded-for: 127.0.0.1" by default, override/augment as needed
kr scan https://api.example.com -w routes-large.kite \
  -H 'Authorization: Bearer eyJ...' -H 'x-api-key: k3y' -o json
```

Key flags (full list in `references/kiterunner.md`):

- `-w`/`--kitebuilder-list` — the `.kite` corpus (repeatable).
- `-A`/`--assetnote-wordlist` — alias form, `:N` head-limit.
- `-x`/`--max-connection-per-host` (default 3) — per-host concurrency; raise
  to 5–20 against robust targets.
- `-j`/`--max-parallel-hosts` (default 50) — fleet width.
- `--max-redirects` (default 3).
- `--fail-status-codes` — statuses treated as "not found".
- `--ignore-length` — drop responses of given sizes/ranges (e.g.
  `--ignore-length 34,500-600`) to kill wildcard/decoy noise.
- `-d`/`--preflight-depth` (default 1) — directory depths probed for
  wildcard detection calibration.
- `--delay` — inter-request delay per connection (e.g. `--delay 500ms`).
- `-o`/`--output json|text|pretty` (default pretty). Always use `json` when
  the output will be parsed.

### Reading kr output

Pretty mode:

```
GET     403 [    218,   10,    1] https://api.example.com/v1/admin/users 0cc39f...
POST    200 [   1034,   22,    5] https://api.example.com/v1/orders 7ab1e2...
```

Columns: method, status, `[content-length, words, lines]`, full URL, and the
route checksum. Triage:

- **200/201/2xx** — live route. Enumerate deeper: replay with varied params,
  feed to `api-fuzzing` for parameter/body fuzzing.
- **401/403** — *route exists but is gated*. These are the highest-value
  discovery hits: hand them to the `api-authorization` skill (auth bypass,
  IDOR, method/verb tampering, path-confusion like `/v1/admin;/` or
  `/%2e/v1/admin`).
- **405** — path exists, wrong verb; retry the other methods manually.
- **301/302** — follow and re-scan the redirected base.
- **429/5xx bursts** — lower `-x`, add `--delay`, re-run the slice.
- Identical lengths across many paths — a decoy/catch-all; rerun with
  `--ignore-length <len>`.

## 3. Plain brute — `kr brute` and ffuf

For raw path lists (raft, SecLists api directories, target-specific words
mined from JS bundles):

```sh
kr brute https://api.example.com -w raft-large-words.txt -x 10 -o json
kr brute https://api.example.com -A=raft-large-words -o json
```

`brute` only GETs each line — use it for directory/path discovery, not
operation discovery. For status/size/regex matching flexibility, use ffuf:

```sh
ffuf -u https://api.example.com/FUZZ -w api-paths.txt -mc all -fc 404 \
     -H 'Authorization: Bearer eyJ...' -of json -o ffuf-api.json
# Version-sweep known resources
ffuf -u https://api.example.com/VER/users -w versions.txt:VER -mc all -fc 404
```

Full ffuf depth (recursion, matchers, rate shaping, POST bodies) lives in the
`api-fuzzing` skill — import it rather than re-deriving flags.

## 4. Merge a found spec

If recon surfaced any OpenAPI/Swagger JSON (even partial), convert it to a
Kitebuilder schema and compile, so kr replays the documented operations with
correct methods/params alongside the brute corpus:

```sh
# Swagger 2.0 / OpenAPI 3 -> kitebuilder JSON (assetnote/kitebuilder tooling),
# then compile and validate:
kr kb convert swagger.json spec.kb.json      # if the build includes kb convert
kr kb compile spec.kb.json spec.kite
kr kb parse spec.kite                        # sanity-check the compiled routes
kr scan https://api.example.com -w spec.kite -w routes-large.kite -o json
```

The spec document itself should also be split per resource for parallel
spec-driven testing — use the reporting pack's `work-units` skill
(`split.py openapi`) for that; do not write a splitter here.

## 5. Parse, record, fan out

```sh
python3 scripts/parse_kr.py kr-api.json -o reports/api-units.json \
  --endpoints reports/api-endpoints.json
```

`parse_kr.py` accepts kr `-o json` output (JSON lines) and also tolerates
pretty/text lines. It emits:

- `reports/api-endpoints.json` — normalized `{method, path, url, status,
  length, host}` records (deduped).
- `reports/api-units.json` — a JSON array of work units grouped per first
  path segment (resource), written atomically, ready for a rupu
  `for_each: "{{ read_file('reports/api-units.json') }}"` fan-out or
  per-child `dispatch`.

Then, per `references/rupu.md`:

1. `assets.mark` the service (`api:service`, depth `mapped`) and every
   discovered route (`api:endpoint`, depth `mapped`; raise to `tested` once a
   route has been probed beyond discovery).
2. Fan out one work unit per resource to child agents.
3. Route 401/403 hits into `api-authorization`; 2xx hits into `api-fuzzing`.
4. Verified issues → `findings.report` under the `api` profile, pinned to the
   endpoint's `http_route` coordinate with an `http_exchange` evidence block
   (contract: imported `finding-report` skill).

## Quick decision table

| Situation | Action |
|---|---|
| No spec at all | `kr scan` with `routes-large.kite`, then `kr brute` + ffuf |
| Partial spec found | compile to `.kite`, scan with spec + routes-large |
| Massive host list | `routes-small.kite` or `-A=apiroutes-210328:20000` first pass, `routes-large.kite` on live hosts |
| Decoy 200s everywhere | `--ignore-length`, tune `--fail-status-codes`, raise `-d` |
| Needs auth context | repeat scan per credential/role with distinct `-H` sets, diff the hit lists (authz leads) |
