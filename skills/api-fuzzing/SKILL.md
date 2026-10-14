---
name: api-fuzzing
description: Spec-driven HTTP fuzzing of an API with ffuf — fuzz paths, parameter names, parameter values, HTTP methods, and JSON request bodies generated from a parsed OpenAPI/Swagger request set; cluster responses, isolate anomalies, and hand hits to authorization/injection testing. Use as phase 2 of the api-testing flow, after api-spec-discovery has produced a normalized request set.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Fuzzing with ffuf

Phase 2 of the `api-testing` flow. Input: the normalized request set emitted by
`api-spec-discovery` (one JSON record per operation: method, URL, params, headers,
body skeleton). Output: ffuf anomaly hits, `reports/api-fuzzing-units.json` work
units for fan-out, assets marked `tested`, and findings for verified issues.

Flag-level depth: `references/ffuf.md`. Spec→template patterns: `references/templates.md`.
rupu wiring (assets, units, findings): `references/rupu.md`.

## Workflow

### 1. Ingest the request set and generate tasks

```
python3 scripts/spec_to_ffuf.py reports/api-requests.json -o reports/ffuf \
  --header 'Authorization: Bearer eyJ...' --proxy http://127.0.0.1:8080
```

This emits `reports/ffuf/commands.sh` + `reports/ffuf/manifest.json` plus input
files (`ids.txt`, `values.txt`, `methods.txt`, per-field body templates). Per
operation it generates one task per fuzz class:

| Class | What is fuzzed | Example |
|---|---|---|
| `path-segment` | unknown routes under each base path | `-u https://api.example.com/v1/FUZZ -recursion -recursion-depth 2` |
| `path-id` | each `{param}` in the route | `-u https://api.example.com/v1/orders/FUZZ -w reports/ffuf/ids.txt:FUZZ` |
| `param-name` | undocumented query/body parameter names | `-u 'https://api.example.com/v1/orders?FUZZ=1' -w burp-parameter-names.txt:FUZZ` |
| `param-value` | documented parameter values | `-u 'https://api.example.com/v1/orders?status=FUZZ' -w reports/ffuf/values.txt:FUZZ` |
| `body-field` | one JSON body field value at a time | `-X POST -H 'Content-Type: application/json' -d '{"id":FUZZ}' -w reports/ffuf/ids.txt:FUZZ` |
| `method` | verb tampering per route | `-X FUZZ -w reports/ffuf/methods.txt:FUZZ -u https://api.example.com/v1/orders/1` |

Review `manifest.json` before running; drop or edit tasks as needed, then run
`sh reports/ffuf/commands.sh` or execute tasks selectively.

### 2. Baseline before you trust matchers

APIs lie: soft-404s return 200, auth walls return 200 with an error JSON. For each
host, start wide and calibrate:

```
ffuf -u https://api.example.com/v1/FUZZ -w routes.txt \
  -mc all -fc 404 -ac -t 40 -o reports/ffuf/out/base.json -of json
```

- `-mc all -fc 404` — see everything except hard 404s first.
- `-ac` — auto-calibration: ffuf sends junk probes, learns the "not found" response
  shape, and filters it (handles soft-404 / constant-200 APIs). Add `-acc <string>`
  for a custom calibration keyword per path style.
- Then refine with `-fs <size>` / `-fw <words>` / `-fl <lines>` / `-fr <regex>`
  against whatever constant noise remains (e.g. `-fr '"error":"not_found"'`).
- `-mt '>500'` / `-ft` catch time-based anomalies (blind injection, heavy queries).

### 3. Multi-position fuzzing with named keywords and modes

Named keywords (`-w list:KEYWORD`) unlock multi-axis API fuzzing:

```
# path × id — every route against every id (clusterbomb = cartesian, the default)
ffuf -u https://api.example.com/v1/W1/W2 -w routes.txt:W1 -w ids.txt:W2 \
  -mode clusterbomb -mc all -fc 404 -ac

# param-name × param-value
ffuf -u 'https://api.example.com/v1/orders?NAME=VAL' \
  -w burp-parameter-names.txt:NAME -w values.txt:VAL -mode clusterbomb -ac

# pitchfork: 1-to-1 pairing — line i of each list together (e.g. user:their-own-id
# pairs for authz baselines, or token:userid pairs)
ffuf -u https://api.example.com/v1/users/UID -H 'Authorization: Bearer TOK' \
  -w ids.txt:UID -w tokens.txt:TOK -mode pitchfork

# sniper: one list, injected into each marked position in turn
ffuf -u 'https://api.example.com/v1/§orders§/§1§' -w payloads.txt -mode sniper
```

`-recursion` (URL must end in `FUZZ`) + `-recursion-depth 2` walks nested REST
paths (`/v1/FUZZ` → `/v1/admin/FUZZ`). JSON body fuzzing is just `-d` with the
keyword in the raw body:

```
ffuf -X POST -u https://api.example.com/v1/orders \
  -H 'Content-Type: application/json' -d '{"id":FUZZ,"qty":1}' \
  -w reports/ffuf/ids.txt:FUZZ -mc all -fc 404 -ac -of json -o out/body-id.json
```

Note the wordlist entries replace FUZZ *raw*: for JSON string values the list
entries must carry their own quotes (`"admin"`), numerics/null/bool go bare.

### 4. Run hygiene

- Auth: `-H 'Authorization: Bearer ...'`, `-H 'X-Api-Key: ...'`, `-b 'session=...'`
  for cookie auth. Repeat `-H` for multiple headers.
- Evidence: `-x http://127.0.0.1:8080` to proxy through Burp; `-od reports/ffuf/dump`
  to save full request/response pairs for findings; `-v` prints full URLs; `-s`
  silent for piping.
- Throughput: `-t 40` threads, `-rate 100` req/s cap, `-p 0.1-0.5` random delay,
  `-timeout 10`, `-maxtime 600` / `-maxtime-job 120` to bound long jobs.
- Always `-o out/<task>.json -of json` so parsing is mechanical (`-of all` also
  writes csv/html alongside).

### 5. Parse output and read the signal

```
python3 scripts/parse_ffuf.py 'reports/ffuf/out/*.json' \
  --manifest reports/ffuf/manifest.json \
  --hits reports/api-fuzzing-hits.json -o reports/api-fuzzing-units.json
```

The parser clusters each run's results by (status, size) and flags the outliers —
the response that *differs* is the story:

- `path-id` run of mostly 404/403 with one 200 → a valid/accessible object id
  → hand to `api-authorization` (IDOR check with a second identity).
- `param-name` run where one name changes size/status (`debug`, `admin`, `fields`)
  → undocumented parameter → hand to `api-param-discovery` (arjun overlaps here —
  arjun brute-forces names smartly; ffuf wins when you need name×value matrices)
  and to `api-injection` for value probing.
- 500s or `-mt` time outliers on a `param-value`/`body-field` run → injection
  suspect → hand to `api-injection` with the exact request from `-od`.
- `method` run where PUT/DELETE/PATCH return non-405 on a read-only route → verb
  tampering candidate.

### 6. rupu hand-off (see references/rupu.md for exact wiring)

- Mark every fuzzed endpoint `tested` with `assets.mark` (`api:endpoint`, coordinates
  `url` + `http_route`); the service stays `mapped` from phase 1. Asset-recording
  details: import the **`coverage-assets`** skill.
- `reports/api-fuzzing-units.json` is a clean JSON array of
  `{"id","title","targets","hints"}` work units written atomically — fan out with
  `for_each: "{{ read_file('reports/api-fuzzing-units.json') }}"` or `dispatch`
  one unit per child agent. For splitting a raw OpenAPI document per resource,
  import the **`work-units`** skill (`split.py openapi`); this skill's scripts
  only emit the normalized intermediate.
- Verified issues (confirmed IDOR, injection, exposed debug route) → `findings.report`
  under the `api` profile, pinned to the endpoint's `http_route` coordinate, with an
  `http_exchange` evidence block from the `-od` dump. Full contract: import the
  **`finding-report`** skill.
