# ffuf reference for API fuzzing

ffuf (Fuzz Faster U Fool) substitutes keywords anywhere in the request: URL,
method, headers, cookies, body. Default keyword is `FUZZ`; `-w list:NAME` binds a
wordlist to any custom keyword.

## Core request flags

| Flag | Meaning | API example |
|---|---|---|
| `-u` | target URL, contains keyword(s) | `-u https://api.example.com/v1/orders/FUZZ` |
| `-w` | wordlist, optional `:KEYWORD` | `-w ids.txt:ID -w routes.txt:R` |
| `-X` | HTTP method (keyword allowed) | `-X POST`, `-X FUZZ -w methods.txt:FUZZ` |
| `-H` | header, repeatable, keyword allowed | `-H 'Authorization: Bearer eyJ...' -H 'Content-Type: application/json'` |
| `-d` | request body, keyword allowed | `-d '{"id":FUZZ,"qty":1}'` |
| `-b` | cookie data | `-b 'session=abc123; csrf=xyz'` |
| `-x` | upstream proxy | `-x http://127.0.0.1:8080` (Burp, for evidence capture) |
| `-r` | follow redirects | useful when API 302s to canonical routes |
| `-H 'Host: FUZZ'` | vhost fuzzing | find per-tenant API vhosts |

Keywords work in *any* of these simultaneously — e.g. fuzz a header value against
a body field:

```
ffuf -u https://api.example.com/v1/me -X POST \
  -H 'X-User-Id: UID' -d '{"action":"ACT"}' \
  -H 'Content-Type: application/json' \
  -w ids.txt:UID -w actions.txt:ACT -mode clusterbomb
```

## Matchers and filters

Matchers (`-m*`) select what to show; filters (`-f*`) remove from the matched set.
Status/size/words/lines accept comma lists and ranges (`200,201,400-403`, `>500`).

| Match | Filter | Dimension |
|---|---|---|
| `-mc` | `-fc` | HTTP status (`-mc all` = everything) |
| `-ms` | `-fs` | response size in bytes |
| `-mw` | `-fw` | word count |
| `-ml` | `-fl` | line count |
| `-mr` | `-fr` | regex over response body |
| `-mt` | `-ft` | response time ms (`-mt '>500'`) |

Baseline recipe for APIs: `-mc all -fc 404`, run once, note the constant noise
(same size/words on every miss), then add `-fs 87` or `-fr '"error":"not_found"'`
and rerun. Match operator for combining (`-mmode and|or`, `-fmode and|or`) when
you need e.g. "status 200 AND regex".

### Auto-calibration

- `-ac` — before fuzzing, ffuf sends randomized junk inputs, records the response
  shape (status/size/words/lines), and auto-filters anything matching it. Essential
  against soft-404 APIs that answer 200 `{"error":"not found"}` to everything.
- `-acc <string>` — custom calibration keyword (repeatable); use a junk value in
  the same format as real inputs (e.g. a random UUID when fuzzing UUID ids) so the
  calibration probe exercises the same code path.
- `-ach` — calibrate per host (multi-host runs); `-acs <strategy>` to pick
  calibration strategy (`basic`, `advanced`).

## Modes (verified semantics)

- `-mode clusterbomb` (default) — cartesian product of all keyword lists. 3 routes ×
  1000 ids = 3000 requests. Use for name×value, path×id matrices.
- `-mode pitchfork` — parallel 1-to-1: request i uses line i of *every* list; stops
  at the shortest list. Use for paired data (token_i with its own user_i).
- `-mode sniper` — single wordlist, no keyword binding; mark positions with `§...§`
  in the request; each position is fuzzed in turn while others keep their original
  value: `ffuf -u 'https://api.example.com/§v1§/orders/§1§' -w payloads.txt -mode sniper`.

## Recursion

`-recursion` re-queues hits as new fuzz bases — the URL must end in `FUZZ`:

```
ffuf -u https://api.example.com/api/FUZZ -w routes.txt \
  -recursion -recursion-depth 2 -recursion-strategy greedy \
  -mc all -fc 404 -ac
```

`greedy` recurses on every hit, `default` only on redirects. Keep depth ≤2 on APIs;
REST nesting is shallow and ids explode the tree — prefer explicit path-id tasks
for `{param}` positions.

## Rate / performance

| Flag | Meaning |
|---|---|
| `-t 40` | concurrent threads (default 40) |
| `-rate 100` | max requests per second |
| `-p 0.1` or `-p 0.1-0.5` | fixed/random delay between requests, seconds |
| `-timeout 10` | per-request timeout |
| `-maxtime 600` | hard cap for the whole run |
| `-maxtime-job 120` | cap per recursion job |
| `-se` | stop on spurious errors |
| `-sa` | stop on all error cases (403 spike, etc.) |

## Output

| Flag | Meaning |
|---|---|
| `-o out.json` | output file |
| `-of json` | format: `json`, `ejson`, `csv`, `ecsv`, `html`, `md`, `all` |
| `-od dir/` | dump full request+response of every match to dir (evidence!) |
| `-v` | verbose: full URLs + redirect targets |
| `-s` | silent: results only, pipe-friendly |
| `-json` | stream results as JSON lines to stdout (live parsing) |

`-of json` structure: top-level `commandline`, `time`, `config` (full request
config incl. `method`, `url`, `data`, `headers`), and `results[]` with per-hit
`input` (keyword→value map), `position`, `status`, `length`, `words`, `lines`,
`duration`, `url`, `host`, `resultfile` (when `-od` used). `scripts/parse_ffuf.py`
consumes exactly this.

## Interactive mode

Press ENTER mid-run for the interactive console: `fc 403` / `fs 1234` to add
filters live, `queueshow`/`queuedel` to manage recursion jobs, `savejson file`
to snapshot results. Ideal for taming a noisy run without restarting.

## API recipes

```
# 1. Route discovery under a versioned base, soft-404 API
ffuf -u https://api.example.com/v2/FUZZ -w api-routes.txt \
  -H 'Authorization: Bearer eyJ...' -mc all -fc 404 -ac \
  -recursion -recursion-depth 1 -rate 80 -o out/routes.json -of json -od out/dump

# 2. Numeric IDOR sweep on a path param
ffuf -u https://api.example.com/v1/invoices/FUZZ -w ids.txt:FUZZ \
  -H 'Authorization: Bearer eyJ...' -mc all -fc 404 -ac \
  -o out/invoice-ids.json -of json

# 3. Hidden query parameter names (overlaps with arjun)
ffuf -u 'https://api.example.com/v1/orders?FUZZ=1' \
  -w burp-parameter-names.txt:FUZZ -mc all -ac -fs 0 \
  -o out/order-params.json -of json

# 4. JSON body field value fuzz (raw substitution — quotes live in the wordlist)
ffuf -X PUT -u https://api.example.com/v1/users/42 \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer eyJ...' \
  -d '{"role":FUZZ,"name":"a"}' -w roles.txt:FUZZ \
  -mc all -fc 404 -ac -o out/role-values.json -of json

# 5. Method tampering
ffuf -X FUZZ -w methods.txt:FUZZ -u https://api.example.com/v1/orders/42 \
  -H 'Authorization: Bearer eyJ...' -mc all -fc 405 -o out/methods.json -of json

# 6. Time-based anomaly hunt on a search param
ffuf -u 'https://api.example.com/v1/search?q=FUZZ' -w sqli-time.txt:FUZZ \
  -mt '>3000' -o out/timing.json -of json
```
