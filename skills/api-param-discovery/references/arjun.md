# arjun — full reference

Arjun (s0md3v) discovers HTTP parameters a server accepts by injecting large
batches of candidate names and diffing responses against a baseline. It is the
standard tool for hidden-parameter discovery. Install: `pipx install arjun`
(or `pip install arjun`). Verify: `arjun --help`.

## How the chunking / bisection engine works

1. Arjun requests the target a few times with no candidates to learn a stable
   **baseline** (status code, content length, word/line counts, reflections of
   a canary value, and page "factors" that stay constant).
2. The wordlist is split into **chunks** of `-c` names (default **500**). Each
   chunk is injected into one request (query string for GET, form body for
   POST, JSON object for JSON, XML doc for XML), every candidate carrying a
   unique random value.
3. Any chunk whose response **deviates from baseline** — different status,
   length/word delta, a canary value reflected, an error signature appearing or
   disappearing — contains at least one accepted parameter. Arjun **bisects**:
   splits the chunk in half, retests each half, and recurses until single
   names are isolated. Each isolated name is re-verified individually before
   being reported.
4. Cost model: a clean endpoint with the default dict costs roughly
   `ceil(25890/500) ≈ 52` requests plus baseline. Every accepted parameter adds
   ~`log2(500) ≈ 9` bisection requests. Lowering `-c` multiplies the base cost
   but shrinks each request (needed when GET URLs hit server length limits —
   414/431/400 responses) and makes diffs less noisy on dynamic pages.

Anomaly classes to understand when reading verbose output:
- **reflection** — the injected random value appears in the response body: the
  param is read and echoed (also an injection/reflection sink).
- **status/length/word change** — the handler branches on the param's presence
  (`debug`, `admin`, `format` typically show here).
- **error delta** — a param whose presence suppresses or triggers an error
  (e.g. a required hidden field).

## Flags

### Core

| Flag | Meaning |
|---|---|
| `-u URL` | Single target URL. |
| `-i FILE` | Import multiple targets: plain text (one URL per line), **Burp export** (XML), or a **raw HTTP request** file. Format is auto-detected. Raw-request import preserves method, path, headers, and body template. |
| `-m GET\|POST\|JSON\|XML` | Where candidates are injected: query string (default), urlencoded form body, JSON body, XML body. **There is no header mode** — headers are supplied (not fuzzed) via `--headers`. |
| `-w WORDLIST` | Wordlist. Built-ins: `small`, `medium`, `large`; the default dict is ~25,890 names. A file path works too — SecLists `Discovery/Web-Content/burp-parameter-names.txt` is the common external choice. |
| `-oJ FILE` | JSON output. Shape: `{"<url>": {"params": ["a","b"], "method": "GET", "headers": {...}}}`. |
| `-oT FILE` | Text output: one full URL-with-params per line. |
| `-oB [host:port]` | Replay confirmed requests to a proxy/Burp (default `127.0.0.1:8080`). |

### Tuning

| Flag | Default | Meaning |
|---|---|---|
| `-c N` | 500 | Candidates per request (chunk size). Lower to 100–250 for GET against URL-length-limited servers or very dynamic pages; raise to 1000+ for fast, stable targets to cut request count. |
| `-t N` | 2 | Threads. |
| `-T SECONDS` | 15 | Per-request timeout. |
| `-d N` | 0 | Fixed delay (seconds) between requests. **Forces threads=1.** |
| `--ratelimit N` | — | Max requests per second (note: no hyphen inside the word). |
| `--stable` | off | Stability mode: threads=1 plus a random 6–12 s delay between requests. For targets behind aggressive WAF/rate limiting or with jittery responses. |
| `--headers "H1: v\nH2: v"` | — | Extra headers on every request — auth tokens, cookies, tenant/version headers. Multiple headers separated by `\n`. With no value, arjun opens an interactive editor; always pass the string in automation. |
| `--include 'DATA'` | — | Static data merged into every request: `'{"api_key":"x"}'` (JSON) or `'a=1&b=2'` (query/form). Use it to keep required fields valid so the baseline is a working request, not a 400. |
| `--disable-redirects` | off | Do not follow 3xx. Use when a redirect masks the handler's real diff behavior (login bounces, trailing-slash normalizers). |
| `--casing` | off | Generate candidates in the casing style detected on the target (camelCase, snake_case, UPPER, kebab-case, etc.). |
| `--passive [domain]` | — | Passive mode: collect parameter names for the target's domain from CommonCrawl, AlienVault OTX, and the Wayback Machine instead of probing. `--passive example.com` pins the domain. Zero target traffic; use the result as a custom `-w` seed or as a first pass. |
| `-q` | off | Quiet (suppress banner/noise — useful when parsing stdout). |

## Method matrix per endpoint

For each endpoint from the request set, run the methods it plausibly handles —
and one it "shouldn't", because frameworks often parse all sources:

```sh
U=https://api.example.com/v1/users/42
H='Authorization: Bearer eyJ...'
arjun -u "$U" -m GET  --headers "$H" -oJ /tmp/a_get.json
arjun -u "$U" -m POST --headers "$H" -oJ /tmp/a_post.json
arjun -u "$U" -m JSON --headers "$H" --include '{"name":"x"}' -oJ /tmp/a_json.json
```

PHP (`$_REQUEST`), Rails (merged params), Express (body-parser + query), and
Spring (`@RequestParam` fallback) all commonly accept the same name from
multiple sources — a param rejected in the query may be accepted in the JSON
body, and vice versa.

## Batch and passive examples

```sh
# All endpoints from a text file, JSON bodies, polite pacing, Burp mirror
arjun -i reports/endpoints.txt -m JSON --headers "$H" \
      --ratelimit 10 -oJ reports/arjun-batch.json -oB 127.0.0.1:8080

# Raw request file captured from the app (keeps exact headers/body template)
arjun -i reports/orders-post.raw -oJ reports/arjun-orders.json

# Passive seed, then targeted active pass with the mined names
arjun --passive example.com -oT reports/passive-params.txt
arjun -u https://api.example.com/v1/orders -w reports/passive-params.txt \
      -m GET --headers "$H" -oJ reports/arjun-orders-seeded.json
```

## Output parsing

`-oJ` JSON (one object; keys are URLs; values include the confirmed list):

```json
{
  "https://api.example.com/v1/orders": {
    "params": ["debug", "fields", "user_id"],
    "method": "JSON",
    "headers": {"Authorization": "Bearer eyJ..."}
  }
}
```

Older arjun versions emit `{"url": [params...]}` — `scripts/run_arjun.py`
handles both shapes. Treat every listed name as **server-confirmed**: it
changed observable behavior and was individually re-verified. What it does with
the value is the next skill's job.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Zero params everywhere, instantly | Baseline unstable or auth broken | Check `--headers`; try `--stable`; confirm baseline manually with curl |
| 414 / 431 / request-too-long errors | GET chunk exceeds URL limit | `-c 100` (or 50) |
| Results differ run to run | Dynamic content / rate limiting | `--stable`, `-d 2`, `--ratelimit 5`; retest the union |
| Everything "found" (hundreds of params) | WAF block page or error page diffing against itself | Fix the baseline: auth, `--include` required fields, `--disable-redirects` |
| JSON mode finds nothing but API is JSON | Missing required fields → 400 baseline | `--include '{"required_field":"value"}'` |
