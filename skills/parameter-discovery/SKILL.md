---
name: parameter-discovery
license: Apache-2.0
description: Discover hidden/unlinked HTTP parameters (GET query keys, POST body fields, JSON keys, headers) that an endpoint processes but never links, using arjun as primary fuzzer, x8 for high-rate/templated fuzzing, mined per-target wordlists, and ffuf as fallback; use after crawling on each interesting endpoint and before injection/IDOR/SSRF testing, since hidden params are where those bugs live.
metadata:
  author: Section9Labs
---

# parameter-discovery

Find the inputs the app accepts but does not advertise. Crawlers only see
parameters that appear in links and forms; the ones that matter most —
`debug`, `admin`, `url`, `redirect`, `user_id`, `role`, `template`, `callback`
— are usually unlinked and only reachable by guessing names and watching the
response change. This skill produces, for each endpoint, the set of parameters
the server actually processes, then hands those parameterized endpoints to the
injection / access-control / SSRF skills.

Inputs: a list of live endpoints (from the crawl/route map), optionally auth
headers/cookies, optionally historical URLs (gau/waybackurls output) and
downloaded JS files for mining.

## 0. Build the per-target param wordlist first

Arjun ships a strong default list (~25k names) — use it as the base. Augment
with names mined from the target itself; app-specific names (`csrfToken`,
`accountRef`, `tenant_id`) are never in generic lists but appear in the app's
own URLs and JS. Full mining recipes: `references/x8-and-mining.md`.

1. Query keys from every URL you have (crawl output + gau/wayback):
   split on `?`/`&`/`=`, keep the keys, dedupe.
2. JS mining: grep downloaded JS for `name="..."`, object keys in
   `fetch`/`XHR`/`axios` bodies, `params[...]`, `searchParams.get("...")`.
3. SecLists baseline: `Discovery/Web-Content/burp-parameter-names.txt`.
4. Concatenate, lowercase-dedupe but keep original casing variants, write
   `params-example.com.txt`.

The helper script merges mined query keys automatically (`--urls` flag, step 4).

## 1. arjun — primary parameter fuzzer

Arjun confirms a parameter by **differential response analysis**: it fetches
the page several times to learn a stable baseline (length, status, reflected
content, plaintext/HTML comparison), then sends parameters in large chunks
(default 500 per request) with random values. If a chunk changes the response
(status flip, length delta beyond jitter, value reflection, new/removed
content), it binary-searches inside the chunk down to the single parameter
that caused it. That means a found param is already *evidence-backed*: the
server demonstrably reads it.

Per endpoint, one method at a time (results differ per method — run all that
the endpoint plausibly accepts):

```sh
arjun -u "https://example.com/api/profile" -m GET  -oJ arjun-get.json  -t 10 -q
arjun -u "https://example.com/api/profile" -m POST -oJ arjun-post.json -t 10 -q
arjun -u "https://example.com/api/profile" -m JSON -oJ arjun-json.json -t 10 -q
arjun -u "https://example.com/api/profile" -m XML  -oJ arjun-xml.json  -t 10 -q
```

Key flags (full matrix and output-reading guide in `references/arjun.md`):

- `-i endpoints.txt` — import many targets (also takes Burp XML).
- `-w params-example.com.txt` — your merged wordlist; or `-w small|medium|large`.
- `--headers "Cookie: session=...\nAuthorization: Bearer ..."` — authenticated
  fuzzing finds a different (usually larger) param set; run both authed and
  unauthed and diff them.
- `--include 'token=abc&ref=1'` or `--include '{"token":"abc"}'` — static data
  the endpoint requires on every request (keeps the baseline valid).
- `-c 250` — smaller chunk when the server trips on huge query strings
  (414/431/400 on baseline chunks); `-d 2` delay, `-t` threads.
- `--stable` — slow mode for jittery apps (dynamic content, load balancing);
  use when arjun reports an unstable baseline or floods false positives.
- `--passive` / `--passive example.com` — no fuzzing: mines param names from
  wayback/CommonCrawl/OTX for the host. Run it anyway and merge into the
  wordlist even when you also fuzz.
- Output: `-oJ out.json` (JSON — what the parser wants), `-oT out.txt`,
  `-oB 127.0.0.1:8080` (replay findings through Burp). **There is no plain `-o`.**

Reading results: arjun prints `[+] parameter detected: id, based on: body length`
style lines; the JSON maps each URL to its confirmed params and method. A
param confirmed "based on: reflection" is an immediate XSS/injection lead;
"status code" flips often mean auth/debug toggles; "body length" means the
param changes server-side behavior — all worth prioritizing in the hints.

## 2. x8 — high-performance / templated fuzzing

Use x8 (Rust) when you need speed on big wordlists, **header-name fuzzing**,
or precise control over how params are injected (custom body templates, params
inside JSON sub-objects, non-standard separators). Full flag reference and
template examples: `references/x8-and-mining.md`.

```sh
# GET + POST query/body fuzzing, JSON output
x8 -u "https://example.com/api/profile" -w params-example.com.txt \
   -X GET POST -O json -o x8-profile.json

# JSON body fuzzing against an API
x8 -u "https://example.com/api/update" -X POST -b '{"%s"}' -t json \
   -w params-example.com.txt -O json -o x8-update.json

# header-name fuzzing (find trusted/debug headers: X-Forwarded-For, X-Debug…)
x8 -u "https://example.com/admin" --headers -w headers.txt -O json -o x8-hdr.json

# custom injection point / template
x8 -u "https://example.com/search?q=test&%s" --param-template "%k=%v" -w params.txt
```

x8 learns the page the same differential way (multiple baseline requests,
`--learn-requests-count` to raise accuracy) and reports *why* each param was
kept (`reason`: different body/code/reflects). Prefer x8 over arjun when:
headers are the injection point, the body template is unusual, or you have
>100k candidate names and arjun is too slow.

## 3. ffuf fallback — raw differential fuzzing

When arjun/x8 misbehave (aggressive WAF, exotic encoding, multipart bodies),
fall back to ffuf one-param-per-request. Establish the baseline size first
(request the URL with a junk param), then filter it out:

```sh
# GET: baseline is 4532 bytes
ffuf -u "https://example.com/page?FUZZ=xray1337" \
     -w params-example.com.txt -mc all -fs 4532 -o ffuf-get.json -of json

# POST form body
ffuf -u "https://example.com/login" -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "FUZZ=xray1337" -w params.txt -mc all -fs 1203 -o ffuf-post.json -of json

# JSON body keys
ffuf -u "https://example.com/api/v2/user" -X POST \
     -H "Content-Type: application/json" -d '{"FUZZ":"xray1337"}' \
     -w params.txt -mc all -fs 88 -o ffuf-json.json -of json
```

Remember: ffuf `-mc` has a default allow-set — always use `-mc all` and filter
with `-fs/-fw/-fl/-fc` against the measured baseline. Add `-ac` to
auto-calibrate on dynamic pages. Also fuzz param *values* on anything found
(`?debug=FUZZ` with `true,1,yes,on`) — a param that only reacts to the right
value is invisible to name-only fuzzing.

## 4. Parse, merge, hand off (rupu — required)

Every parse step ends in rupu-ingestible output. Exact JSON shapes and tool
call formats: `references/rupu.md`.

Normalize and merge all sources with the helper script:

```sh
python3 scripts/parse_arjun.py \
    arjun-get.json arjun-post.json x8-profile.json ffuf-get.json \
    --urls all-crawled-urls.txt \
    --merged params-merged.json \
    --work-units param-work-units.json \
    --assets assets-mark.json
```

- `--merged` — normalized `[{url, method, params[]}]` per endpoint; attach
  this to the route map.
- `--work-units` — clean JSON array (first char `[`), one unit per
  endpoint+method with `hints.params`, ready for a rupu workflow `for_each:`
  or lead-agent `dispatch`. Hand the array to the `work-units` skill for
  canonical splitting/normalizing before fan-out to the injection, IDOR, SSRF
  and open-redirect skills.
- `--assets` — one `assets.mark` payload per discovered param:
  kind `web:route`, coordinates `url` + `http_route` + `param`, depth
  `tested` (you fuzzed the endpoint). Record them via the `coverage-assets`
  skill. Endpoints fuzzed with zero params found still get a `web:route` mark
  at `tested` (coverage, no param coordinate).

Triage the merged params before dispatch — these name patterns pre-classify
the follow-on test:

| param pattern | hand to |
|---|---|
| `url, uri, dest, redirect, next, return, callback, feed, host` | SSRF / open-redirect |
| `id, uid, user_id, account, number, order, doc, key` | IDOR / access control |
| `q, s, search, query, name, sort, order_by, filter` | SQLi / NoSQLi |
| `template, view, page, file, path, include, lang` | LFI / SSTI |
| `debug, test, admin, enable, show, env, trace, verbose` | debug/backdoor toggles |
| `cmd, exec, command, run, func, action` | command injection |

Put the classification into each work unit's `hints` (the script tags
`hints.lead` from this table) so child agents start with the right test.

If any single fuzz run *already* demonstrates a vulnerability (e.g. `debug=1`
dumps a stack trace with secrets), do not wait for the downstream skill:
record it immediately with `findings.report` (scope `endpoint`, HTTP exchange
in evidence, OWASP/CWE classification) via the `finding-report` skill — shape
in `references/rupu.md`.

## Order of operations (per endpoint)

1. Build/refresh the per-target wordlist (step 0; rerun `--passive` per new host).
2. arjun GET, then POST/JSON/XML if the endpoint is an API or accepts bodies.
3. x8 for headers, and as a second opinion on high-value endpoints.
4. ffuf fallback where 2–3 were unstable; value-fuzz boolean-looking params.
5. `parse_arjun.py` → merged map + work units + assets.mark (step 4).
6. Dispatch work units to input-testing skills; record coverage and any
   immediate findings.
