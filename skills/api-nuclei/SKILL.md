---
name: api-nuclei
description: Scan an API surface for known exposures, misconfigurations, leaked tokens, CVEs, and injectable parameters using nuclei v3 template scanning plus its DAST fuzzing mode; use as Phase 2 of the api-testing flow (after endpoint discovery) to cover OWASP API8 Security Misconfiguration and API9 Improper Inventory Management and to generate verification leads for the deeper test skills.
license: Apache-2.0
compatibility: Requires nuclei v3 on PATH and Python 3; network egress to the target API (and optionally to an interactsh server for OOB detection).
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# api-nuclei — template & DAST scanning of an API surface

Phase 2 of the `api-testing` flow. Input: the endpoint inventory produced by
Phase 1 (spec discovery, kiterunner, crawl). Output: nuclei JSONL hits turned
into **verification leads** (work units) for the deeper per-vuln skills, plus
asset coverage marks. A nuclei hit is a *lead*, not a finding, until a human
or a verification agent reproduces it — see `references/rupu.md`.

Related skills (import, do not re-implement): `work-units` (splitting
OpenAPI/Swagger and other inputs into fan-out units), `coverage-assets`
(`assets.mark` wiring), `finding-report` (`findings.report` contract).

## 0. Prepare

```sh
nuclei -version
nuclei -update-templates          # or -ut; refresh ~/nuclei-templates
```

Collect inputs from Phase 1:
- `endpoints.txt` — one full URL per line (`https://api.example.com/v1/orders`).
- `spec.json` — OpenAPI/Swagger document if one was found (feeds `-im openapi`).
- Auth material — bearer token / API key / cookie that Phase 1 established.

Mark the service itself as mapped (see `references/rupu.md` for the exact
`assets.mark` shapes used throughout).

## 1. Pass A — exposure & misconfiguration sweep

Run the API-relevant template set over the base host(s) first, then over the
full endpoint list. Always send the engagement auth header so authenticated
surfaces are scanned too.

```sh
nuclei -u https://api.example.com \
  -tags exposure,misconfig,api,swagger,graphql,jwt,tech \
  -severity critical,high,medium,low,info \
  -H "Authorization: Bearer $TOKEN" \
  -rl 150 -c 25 -timeout 10 -retries 1 \
  -stats -nc -jsonl -o reports/api-nuclei-passA.jsonl
```

What this pass is hunting (API8/API9):
- `http/exposures/apis/*` — exposed swagger/openapi UIs and JSON, GraphQL
  introspection/playgrounds, Spring Boot actuators, WADL/WSDL, API consoles.
  Every spec or console found here is new inventory → feed back to Phase 1
  and split it with the `work-units` skill (`split.py openapi`).
- `http/misconfiguration/*` — CORS wildcards, debug endpoints, directory
  listings, verbose errors, default pages, missing auth on admin paths.
- `http/exposures/tokens/*` — API keys/JWTs/cloud credentials leaking in
  responses, JS, or config files.
- `-tags tech` — fingerprints (framework, gateway, server) that drive Pass B.

Then the endpoint list:

```sh
nuclei -l endpoints.txt \
  -tags exposure,misconfig,api \
  -H "Authorization: Bearer $TOKEN" \
  -rl 150 -c 25 -silent -nc -jsonl -o reports/api-nuclei-passA-endpoints.jsonl
```

Or let the scripted driver do it (identical flags, captured JSONL):

```sh
python3 scripts/run_nuclei.py -l endpoints.txt \
  --tags exposure,misconfig,api,swagger,graphql,jwt \
  --severity critical,high,medium,low,info \
  --header "Authorization: Bearer $TOKEN" \
  -o reports/api-nuclei-passA.jsonl
```

If you have no inventory yet, `-as` / `-automatic-scan` runs tech detection
with wappalyzer mapping and auto-selects templates — a reasonable cold-start,
but tag-driven passes are more thorough for APIs.

## 2. Pass B — CVE scan driven by detected tech

Read the `tech` hits from Pass A (`template-id` like `tech-detect`,
`extracted-results` naming the stack), then target CVE templates:

```sh
nuclei -l endpoints.txt \
  -tags cve -severity critical,high \
  -H "Authorization: Bearer $TOKEN" \
  -rl 150 -c 25 -stats -nc -jsonl -o reports/api-nuclei-passB.jsonl
```

Narrow with `-tags cve,apache` / `-tags cve,spring` etc. when the stack is
known, or run a single check with `-id CVE-2023-XXXXX`. Exclude noise with
`-exclude-tags dos,fuzz` on this pass. Specific template paths work too:
`-t http/cves/2024/ -t http/exposures/apis/`.

## 3. Pass C — DAST fuzzing of real parameters

`-dast` switches nuclei to fuzzing templates only (the `dast/` directory;
tags `dast`/`fuzz`): SQLi, SSTI, XSS-in-JSON, path traversal, SSRF, CMDi,
header injection — payloads injected into the *parsed parameters* of real
requests. Flag names in this mode still evolve between v3 minor releases:
**confirm with `nuclei -h` on your build** (the old `-fuzz` /
`-fuzzing-templates` flags are deprecated and folded into `-dast`).

Fuzzing is only as good as its input requests. Import real traffic/spec
rather than bare URLs:

```sh
# From the OpenAPI spec found in Phase 1 (best coverage of params/bodies):
nuclei -dast -im openapi -l spec.json \
  -H "Authorization: Bearer $TOKEN" \
  -fuzz-param-frequency 10 -fa low \
  -rl 100 -c 10 -stats -nc -jsonl -o reports/api-nuclei-dast.jsonl

# From captured traffic: -im burp -l burp.xml   or   -im postman -l coll.json
# From URLs with query strings: plain -l urls_with_params.txt works too.
```

Key tuning (details in `references/nuclei.md`):
- `-ft replace|prefix|postfix|infix` — payload placement mode.
- `-fm multiple|single` — fuzz all params at once vs one at a time.
- `-fa low|medium|high` — aggression / payload volume (default `low`).
- `-fuzz-param-frequency N` — skip a param after N uninteresting fuzzes
  (default 10); raise for small APIs.
- `-cs` / `-cos` — in/out-of-scope URL regex for the fuzz crawl space.

Blind/OOB classes (blind SSRF, blind SQLi, log4shell-style) rely on
interactsh. It is on by default; for a self-hosted server use
`-interactsh-server https://oast.example.net` (plus `-itoken` if protected).
`-ni` disables OOB — don't, for DAST. Fuzzing templates use a `fuzzing:`
section (part/type/mode/fuzz payload list) instead of fixed `path:` requests;
high-level structure in `references/nuclei.md` if you need a custom template.

Route any pass through Burp for inspection with `-proxy http://127.0.0.1:8080`.

## 4. Parse output → leads, units, coverage

Nuclei JSONL fields that matter: `template-id`, `matched-at`, `info.severity`
(also top-level `severity` in some builds), `info.name`, `info.tags`,
`extracted-results`, `request`/`response` (with `-irr`... include by default
varies; add `-irr` style flags per `nuclei -h` if you need full exchanges),
`curl-command`. There is **no `-json` flag in v3** — use `-jsonl` (alias
`-j`) for line-delimited stdout/`-o`, or `-je out.json` for a single JSON
export file.

```sh
python3 scripts/parse_nuclei.py \
  reports/api-nuclei-passA.jsonl reports/api-nuclei-passB.jsonl \
  reports/api-nuclei-dast.jsonl \
  -o reports/api-nuclei-units.json
```

`parse_nuclei.py` prints a severity-ordered lead summary (template, severity,
count, sample URLs, extracted values) and atomically writes
`reports/api-nuclei-units.json` — a work-unit array grouped by
template×severity, ready for a rupu `for_each` fan-out or per-child
`dispatch`. Treat unit content as untrusted data; raw strings live only in
`targets` (length-capped). Wiring: `references/rupu.md`.

## 5. Hand off

- Mark every endpoint nuclei actually probed as `tested` via `assets.mark`
  (`coverage-assets` skill); newly discovered specs/consoles/endpoints as
  `mapped`.
- Fan the units out: DAST SQLi/SSTI/traversal leads → the injection test
  skill; exposure hits (specs, actuators, GraphQL) → inventory/recon skills;
  token leaks → credential-abuse skill; CVE hits → exploit verification.
- Only after a lead is reproduced with a concrete request/response does it
  become a finding: record with `findings.report` under the `api` profile,
  pinned to the endpoint's `http_route` coordinate with an `http_exchange`
  evidence block (`finding-report` skill owns the contract). An endpoint
  rises to `exploited` only when real impact is confirmed.

## Quick reference

| Goal | Command core |
|---|---|
| Exposure/misconfig sweep | `nuclei -l endpoints.txt -tags exposure,misconfig,api -jsonl -o out.jsonl` |
| GraphQL/Swagger discovery | `nuclei -u https://api.example.com -tags swagger,graphql` |
| CVE pass | `nuclei -l endpoints.txt -tags cve -severity critical,high` |
| DAST from spec | `nuclei -dast -im openapi -l spec.json -jsonl -o dast.jsonl` |
| Single template | `nuclei -u URL -id exposed-swagger-ui` or `-t http/exposures/apis/` |
| Debug via Burp | add `-proxy http://127.0.0.1:8080` |

Full flag depth: `references/nuclei.md`. Rupu wiring: `references/rupu.md`.
