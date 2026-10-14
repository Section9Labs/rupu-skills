---
name: api-param-discovery
description: Discover hidden/undocumented HTTP parameters that an API accepts but does not advertise, using arjun across GET query strings and POST/JSON/XML bodies (with auth headers passed through); enriches the normalized request set from api-spec-discovery and emits rupu work units routing each parameter class to the right follow-up skill (api-authorization, api-injection, api-ssrf). Use as phase 1 of the api-testing flow, right after endpoint/spec enumeration, before any authz/injection testing.
license: Apache-2.0
compatibility: Requires arjun >= 2.2 on PATH (pipx install arjun) and Python 3.8+. Network reach to the target API.
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Hidden Parameter Discovery (arjun)

Undocumented parameters are the highest-leverage finding class in API testing: a
single accepted-but-unadvertised name (`admin`, `debug`, `role`, `user_id`,
`callback`, `fields`) unlocks mass assignment, debug toggles, injection sinks,
and BOLA surface that no spec-driven scan will ever touch. This skill runs
**arjun** over every known endpoint, confirms which hidden parameters the server
actually processes, merges them into the normalized request set produced by
`api-spec-discovery`, and fans the enriched endpoints out as rupu work units.

Imported skills (do not re-implement): `work-units` (splitting / unit schema),
`coverage-assets` (asset recording wiring), `finding-report` (finding contract).

## Inputs and outputs

**In:** the normalized request set from `api-spec-discovery`
(`reports/api-spec-requestset.json` by convention — a JSON list of operations
with `method`, `url`, `params`), or a flat list of endpoint URLs, or a Burp
export / raw request file (arjun `-i` auto-detects all three).

**Out:**
- `reports/arjun-results.json` — per-endpoint confirmed parameters (from `run_arjun.py`).
- `reports/api-param-requestset.json` — the request set with discovered params merged in (`source: "arjun"`).
- `reports/api-param-units.json` — work-unit array for rupu fan-out (see `references/rupu.md`).
- `assets.mark` calls raising each probed `api:endpoint` to `tested` (wiring in `references/rupu.md`).

## Methodology

### 1. Baseline the target first

Before fuzzing parameters, send one clean request per endpoint with the real
auth headers and note status/length. Arjun's anomaly engine diffs responses, so
a broken session token or a WAF block page makes every result garbage. If the
baseline is a 401/403, fix auth (`--headers`) before anything else.

Mark the service and each known endpoint `mapped` with `assets.mark` if
`api-spec-discovery` has not already (exact shapes in `references/rupu.md`).

### 2. Run arjun per endpoint, per method type

Arjun bins candidate names into chunks (default 500 per request), replays the
request with each chunk injected, and **binary-searches** any chunk whose
response differs from baseline — reflected value, status change, length/word
delta — down to the individual accepted name. Fewer, larger chunks = fewer
requests; smaller chunks = resilience to URL-length limits and noisy diffs.
Full mechanics and every flag: `references/arjun.md`.

Canonical single-endpoint invocations:

```sh
# Query string params
arjun -u https://api.example.com/v1/orders -m GET \
      --headers "Authorization: Bearer eyJ...\nX-Api-Version: 2" \
      -oJ reports/arjun-orders-get.json

# Form body
arjun -u https://api.example.com/v1/orders -m POST \
      --headers "Authorization: Bearer eyJ..." -oJ reports/arjun-orders-post.json

# JSON body (most modern APIs) — keep known-required fields on every request
arjun -u https://api.example.com/v1/orders -m JSON \
      --include '{"item_id":"42"}' \
      --headers "Authorization: Bearer eyJ..." -oJ reports/arjun-orders-json.json

# XML body
arjun -u https://api.example.com/v1/legacy -m XML -oJ reports/arjun-legacy-xml.json
```

Rules of thumb:
- Run **every endpoint with every method type it plausibly accepts** — GET for
  reads, POST+JSON for writes. A POST handler often reads query params too; a
  GET handler may parse a JSON body. Hidden params frequently live in the
  method/body combination the docs never mention.
- Header parameters are tested by *supplying* headers via `--headers` (auth,
  version pins, tenant selectors) — there is **no `-m headers` mode**.
- `-w` wordlist: default dict (~25,890 names) is the right first pass; use
  `-w large`, or SecLists `burp-parameter-names.txt`, for a second pass on
  high-value endpoints. `--casing` matches the detected naming convention.
- Unstable or rate-limited target: `--stable`, or `-d 2` (forces 1 thread), or
  `--ratelimit 10`. URL-length errors (414/400 on GET): drop `-c` to 100–250.
- `--passive example.com` mines CommonCrawl/OTX/Wayback for parameter names
  seen historically on the domain — zero traffic to the target, great seed.
- Batch mode: `-i endpoints.txt` (also accepts Burp XML exports and raw
  request files, auto-detected). `-oB 127.0.0.1:8080` streams confirmed
  requests into Burp.

Drive the whole sweep with the helper:

```sh
python3 scripts/run_arjun.py \
    --request-set reports/api-spec-requestset.json \
    --methods GET,POST,JSON \
    --headers "Authorization: Bearer eyJ..." \
    --ratelimit 20 \
    -o reports/arjun-results.json
```

It invokes arjun once per (endpoint, method), captures each `-oJ`, and writes
one combined, deduplicated results file atomically.

### 3. Read the results — classify every confirmed parameter

Arjun's `-oJ` output maps each URL to the confirmed parameter list plus the
method and headers used. Every name in that list is a parameter the server
**demonstrably processes**. Triage by class — this routing decides which skill
gets the endpoint next:

| Parameter class | Examples | Why it matters | Route to |
|---|---|---|---|
| Object/tenant identifiers | `id`, `user_id`, `account`, `order_id`, `org`, `tenant` | BOLA/IDOR — swap IDs across principals | `api-authorization` |
| Privilege/state toggles | `admin`, `is_admin`, `role`, `debug`, `test`, `verified`, `internal` | Mass assignment, debug modes, BOPLA | `api-authorization` (BOPLA) |
| Outbound-fetch params | `url`, `callback`, `redirect`, `webhook`, `target`, `dest`, `uri` | SSRF, open redirect | `api-ssrf` |
| Response shaping | `fields`, `include`, `expand`, `format`, `filter`, `select` | Excessive data exposure, property-level leaks | `api-authorization` (BOPLA) + manual review |
| Free-value sinks | `q`, `search`, `sort`, `order`, `name`, `comment`, anything string-valued | SQLi/NoSQLi/SSTI/command injection | `api-injection` |
| JSONP/eval | `callback`, `jsonp` | XSSI/response hijack | `api-injection` |

A reflected default value (arjun's probe string echoed back) additionally marks
the param as a reflection sink — flag it for injection testing regardless of
name.

### 4. Merge params into the request set and fan out

Never leave discovered params in a side file — fold them into the canonical
request set so **every downstream skill fuzzes the real, full parameter
surface** (ffuf value fuzzing, injection payloads, mass-assignment bodies,
authz ID swaps all read this file):

```sh
python3 scripts/merge_params.py \
    --request-set reports/api-spec-requestset.json \
    --arjun reports/arjun-results.json \
    --merged-out reports/api-param-requestset.json \
    -o reports/api-param-units.json
```

`merge_params.py` matches arjun results to operations by method+URL, appends
each new param with `"source": "arjun"` and its class tag, and atomically emits
`reports/api-param-units.json` — one work unit per endpoint-with-new-params,
with `hints` carrying the routing class from the table above. A rupu workflow
step fans out with `for_each: "{{ read_file('reports/api-param-units.json') }}"`,
or a lead agent dispatches one unit per child. For splitting an original
OpenAPI/Swagger document per resource, use the imported `work-units` skill
(`split.py openapi`) — do not re-implement splitting here. Full wiring:
`references/rupu.md`.

### 5. Record coverage and findings

- After arjun has probed an endpoint (any method), raise its `api:endpoint`
  asset to `depth: "tested"` via `assets.mark` — wiring per the imported
  `coverage-assets` skill, exact shapes in `references/rupu.md`.
- Parameter *discovery* alone is coverage, not a finding. A finding is filed
  only once a downstream skill (or you, directly) confirms impact — e.g.
  `debug=1` returns stack traces with secrets, `role=admin` escalates, `fields`
  leaks other users' PII. File it with `findings.report` under the `api`
  profile, pinned to the endpoint's `http_route` coordinate, with an
  `http_exchange` evidence block — field contract per the imported
  `finding-report` skill. Confirming real impact is also what justifies
  raising the endpoint to `exploited`.

## Pitfalls

- **Auth decay**: long runs outlive tokens. A mid-run 401 turns every later
  chunk into a false anomaly. Use long-lived tokens or re-run affected endpoints.
- **WAF/rate-limit noise**: wildly varying results between runs → `--stable`.
- **GET on huge chunks**: 414/431 responses mean the chunk exceeded URL limits
  — rerun with `-c 100`.
- **Non-idempotent endpoints**: arjun *sends real requests*; a POST discovery
  run against `/v1/orders` creates orders. Prefer harmless required values in
  `--include` and note side effects in the unit hints.
- **Per-param rediscovery**: dedupe — if `debug` works on every endpoint it is
  one framework-level behavior, not fifty findings.
