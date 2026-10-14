# Kiterunner reference

Assetnote's `kr` — contextual API content discovery. Source and README:
`github.com/assetnote/kiterunner`.

## Why kr beats plain path brute-forcing

A text wordlist brute-forcer sends `GET /path` for every line. Modern APIs
404 (or 400) unless the request carries the right **method**, **path
parameters**, **query parameters**, **headers**, and sometimes a minimal
body. Kiterunner's `.kite` corpora are compiled from tens of thousands of
real OpenAPI/Swagger documents (the Kitebuilder dataset), so each entry is a
full request template: `POST /v1/users/{id}/roles?include=perms` with the
right content type, placeholder values substituted into `{id}`-style path
params. `kr scan` replays those templates; `kr brute` degrades to plain GET
path brute (use ffuf if you need richer matching there).

## Install

```sh
# Release binary
wget https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_linux_amd64.tar.gz
tar xzf kiterunner_linux_amd64.tar.gz && install -m755 kr /usr/local/bin/

# From source (Go >= 1.16)
git clone https://github.com/assetnote/kiterunner
cd kiterunner && make build        # binary at dist/kr
```

## Wordlists

### Compiled `.kite`

```sh
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
```

- `routes-large.kite` — full route DB (~900k+ routes). Thorough; heavy.
- `routes-small.kite` — pruned set for triage/wide sweeps.

### Kitebuilder JSON

The uncompiled schema (`routes-large.json.tar.gz`, `routes-small.json.tar.gz`
on the same CDN) is an array of API objects with `ksuid`, `url`, `securityDefinitions`,
and `paths` keyed by path, each holding methods with parameter definitions —
essentially flattened Swagger. Compile and inspect:

```sh
kr kb compile routes.json routes.kite    # JSON -> protobuf .kite
kr kb parse routes.kite                  # print routes in a .kite
kr kb parse spec.kb.json                 # also parses raw kitebuilder JSON
```

**`.kite` is version-unstable protobuf.** After any `kr` upgrade, recompile
custom corpora from JSON; a stale `.kite` can silently misparse.

### Assetnote alias wordlists

```sh
kr wordlist list                 # catalogue: alias, filename, source
kr wordlist save apiroutes-210328   # pre-download to ~/.cache/kiterunner/
kr scan targets.txt -A=apiroutes-210328          # use by alias
kr scan targets.txt -A=apiroutes-210328:20000    # only the first 20000 routes
```

Aliases ending in kitebuilder data behave as `.kite`; plain-text aliases
(e.g. `raft-large-words`) work with `brute`. The `:N` head-limit applies to
both `-A` and `-w`.

## `kr scan` — full flags

```
kr scan <target | targets.txt> [flags]
```

Targets: a URL, a `host:port`, or a file (one target per line). Bare hosts
are expanded across default schemes/ports during preflight.

| Flag | Default | Purpose |
|---|---|---|
| `-w, --kitebuilder-list` | — | `.kite` (or kitebuilder JSON) corpus; repeatable; `:N` head-limit |
| `-A, --assetnote-wordlist` | — | wordlist by alias (auto-download/cache); `:N` head-limit |
| `-x, --max-connection-per-host` | 3 | concurrent connections per host |
| `-j, --max-parallel-hosts` | 50 | hosts scanned in parallel |
| `--max-redirects` | 3 | redirect-following depth |
| `-H, --header` | `x-forwarded-for: 127.0.0.1` | extra header; repeatable; replaces the default set when given |
| `--fail-status-codes` | — | treat these statuses as misses (e.g. `400,401,404,403,501,502,426,411`) |
| `--success-status-codes` | — | whitelist mode: only these count as hits |
| `--ignore-length` | — | drop responses with these body lengths; accepts values and ranges (`34,500-600`) |
| `-d, --preflight-depth` | 1 | path depth used for wildcard-detection preflight |
| `--delay` | 0s | delay between requests on a connection (`500ms`, `2s`) |
| `--timeout` | 3s | per-request timeout |
| `--user-agent` | Chrome UA | override UA |
| `--force-method` | — | force every request to one HTTP method |
| `--kitebuilder-full-scan` | off | replay all routes, skip the PHFM optimization |
| `--filter-api` | — | restrict scan to specific API ksuid(s) within the corpus |
| `--blacklist-domain` | — | never touch these domains even if redirected to |
| `--disable-precheck` | off | skip host liveness preflight |
| `--profile-name` | — | config profile |
| `-o, --output` | pretty | `json`, `text`, `pretty` |
| `-v, --verbose` | info | `debug`, `trace` for request-level logging |
| `-q, --quiet` | off | suppress progress bar/banner |

Caveats: `-u` and `-c` appear in some third-party tutorials but are **not**
in the official README/CLI — do not use them. The default
`x-forwarded-for: 127.0.0.1` header is an intentional ACL-bypass probe; when
you pass your own `-H` headers, re-add it explicitly if you still want it.

### Two-phase workflow (wide then deep)

```sh
# Phase A: cheap sweep of many hosts
kr scan targets.txt -A=apiroutes-210328:20000 -x 5 -j 100 -o json > phase-a.json

# Phase B: full corpus against hosts that produced hits
python3 scripts/parse_kr.py phase-a.json --endpoints hits.json \
  -o reports/api-units.json
jq -r '.[].host' hits.json | sort -u > live.txt     # or extract in Python
kr scan live.txt -w routes-large.kite -x 10 -o json > phase-b.json
```

## `kr brute`

```
kr brute <target | targets.txt> -w wordlist.txt [flags]
```

Same connection/host/output flags as `scan`; `-w` here is a plain text
wordlist and every entry is requested as `GET /<line>`. Good for raft lists,
JS-mined custom words, and version strings. Prefer ffuf when you need
matchers/filters beyond status and length:

```sh
ffuf -u https://api.example.com/FUZZ -w api-paths.txt -mc all -fc 404 \
     -ac -of json -o ffuf-api.json
```

(Full ffuf methodology: the `api-fuzzing` skill.)

## Ingesting an existing OpenAPI/Swagger spec

Any Swagger 2.0 / OpenAPI document can be turned into a scan corpus so kr
replays the documented operations with correct methods and parameters:

1. Convert the spec to kitebuilder JSON. Builds that include the converter
   expose `kr kb convert swagger.json out.kb.json`; otherwise use the
   Assetnote `kitebuilder` tool from the same repo ecosystem, or hand-shape
   the JSON (the schema is a thin wrapper: `[{"ksuid": "...", "url": "...",
   "paths": {<swagger paths object>}}]`).
2. `kr kb compile out.kb.json spec.kite`
3. `kr kb parse spec.kite` to verify routes compiled.
4. `kr scan https://api.example.com -w spec.kite -w routes-large.kite -o json`

This merges spec-driven and brute coverage into one output stream, which
`parse_kr.py` normalizes uniformly. The spec document itself should also go
to the reporting pack's `work-units` skill (`split.py openapi`) to produce
per-resource units for spec-driven testing.

## Output formats and triage

- `pretty` (default): `METHOD  STATUS [length, words, lines] URL checksum`,
  with redirect chains shown as `-> URL`.
- `text`: same minus colour — grep-friendly.
- `json`: one JSON object per result line — the only format scripts should
  parse. Fields include the method, final status code, response body length,
  and the full URL/route that matched (exact key names vary slightly across
  releases; `scripts/parse_kr.py` handles the known variants).

Triage ladder:

| Signal | Meaning | Next step |
|---|---|---|
| 2xx | live, reachable operation | `api-fuzzing` (params, bodies, injection) |
| 401 | exists, needs auth | retry with each credential set; `api-authorization` |
| 403 | exists, gated | bypass attempts: verb switch, `X-Forwarded-For`, path tricks (`/v1/./admin`, `//v1/admin`, `/v1/admin;a=b`, trailing `%2f`), then `api-authorization` |
| 405 | path exists, wrong verb | OPTIONS it; retry GET/POST/PUT/PATCH/DELETE |
| 301/302 | relocation | follow; re-scan new base path |
| uniform length across hits | wildcard/decoy | rerun with `--ignore-length <len>`, raise `-d` |
| 429 / 5xx waves | server pushback | lower `-x`, add `--delay`, resume |

Differential auth scanning: run the identical scan once unauthenticated and
once per role/credential (`-H` sets), then diff the endpoint lists from
`parse_kr.py`. Routes visible to role A but 403 to role B (or vice versa) are
direct authorization-testing leads.
