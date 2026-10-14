# x8 and param-name mining — full reference

## x8 (Rust parameter discoverer)

Install: `cargo install x8`, or grab a release binary from the project's
GitHub releases. Verify flags with `x8 --help` — the tool evolves.

x8 uses the same differential idea as arjun (learn the page over multiple
requests, send many params per request, bisect anomalies) but is faster and
gives much finer control over *where and how* params are injected.

### Core flags

| flag | meaning |
|---|---|
| `-u URL` | target. Put `%s` in the URL/body to pin the exact injection point |
| `-w FILE` | wordlist of candidate names |
| `-X GET POST PUT` | methods to test (space-separated, one scan each) |
| `-b BODY` | request body; `%s` marks where fuzzed params go, e.g. `-b '{"%s"}'` |
| `-t json\|urlencoded` | body/param encoding type |
| `--headers` | fuzz **header names** instead of query/body params |
| `-H "Name: value"` | add static headers (cookies, auth) |
| `--param-template "%k=%v"` | how each key/value pair is rendered (`%k` key, `%v` value) — handles exotic separators like `%k:%v` or `%k[]=%v` |
| `-m N` / `--max N` | params per request (chunk size); default is tuned per method — lower it when the server rejects long requests |
| `--learn-requests-count N` | baseline requests used to learn page stability (raise on dynamic pages) |
| `-c N` | concurrency |
| `-x http://127.0.0.1:8080` | proxy (Burp) |
| `--follow-redirects` | follow 3xx while learning/fuzzing |
| `-O json\|url\|request` | output format; `json` for parsing |
| `-o FILE` | output file |
| `--verify` | re-check every found param (fewer false positives) |
| `--reflected-only` | keep only reflecting params (fast XSS-lead sweep) |

### Recipes

```sh
# Query params, two methods
x8 -u "https://example.com/api/items" -w params.txt -X GET POST -O json -o x8-items.json

# JSON body keys
x8 -u "https://example.com/api/items" -X POST -b '{"%s"}' -t json \
   -w params.txt --verify -O json -o x8-items-json.json

# Nested JSON injection point (params inside "filters" object)
x8 -u "https://example.com/api/search" -X POST \
   -b '{"query":"test","filters":{"%s"}}' -t json -w params.txt -O json -o x8-nested.json

# Header-name discovery (debug/trust headers)
x8 -u "https://example.com/admin" --headers -w headers.txt -O json -o x8-headers.json

# Append to existing query string, custom template
x8 -u "https://example.com/report?id=5&%s" --param-template "%k=%v" -w params.txt
```

### x8 JSON output

An array of result objects, roughly:

```json
[
  {
    "method": "GET",
    "url": "https://example.com/api/items",
    "status": 200,
    "size": 4312,
    "found_params": [
      {"name": "debug", "value": null, "diffs": "", "status": 200,
       "size": 5120, "reason_kind": "Changed body"}
    ]
  }
]
```

`reason_kind` values map to arjun's "based on": changed body / changed code /
reflects. `scripts/parse_arjun.py` consumes this shape.

### When to prefer x8 over arjun

- Fuzzing **header names** (arjun cannot).
- Non-trivial injection points: nested JSON, arrays, custom separators,
  params that must land mid-URL (`%s` placement, `--param-template`).
- Very large wordlists (100k+) where Rust throughput matters.
- You want `--reflected-only` as a fast XSS pre-filter.

## Mining a per-target param wordlist

Generic lists miss app-specific names. Mine the target:

### 1. Query keys from known URLs

Feed every URL you have (katana/gospider/hakrawler crawl output, plus
`gau --subs example.com` and `waybackurls` history) through a key extractor.
`scripts/parse_arjun.py --urls urls.txt` does this inline; standalone:

```sh
cat all-urls.txt | tr '?&;' '\n\n\n' | grep '=' | cut -d= -f1 | sort -u > mined-query.txt
```

Historical URLs are gold: parameters removed from the UI years ago often
still work server-side.

### 2. JS files

Download every JS file from the crawl, then extract candidate names:

```sh
grep -rhoE '"[a-zA-Z_][a-zA-Z0-9_]{1,30}":' js/ | tr -d '":'   > mined-js.txt   # JSON keys in fetch/axios bodies
grep -rhoE "name=[\"'][a-zA-Z_][a-zA-Z0-9_-]+[\"']" js/ | cut -d'"' -f2 >> mined-js.txt
grep -rhoE "searchParams\.get\([\"'][^\"']+[\"']\)" js/ | grep -oE "[\"'][^\"']+[\"']" | tr -d "\"'" >> mined-js.txt
grep -rhoE "(params|data|body)\[[\"'][^\"']+[\"']\]" js/ | grep -oE "[\"'][^\"']+[\"']" | tr -d "\"'" >> mined-js.txt
sort -u mined-js.txt -o mined-js.txt
```

Tools like LinkFinder/xnLinkFinder automate this; the regexes above cover the
bulk with no dependencies.

### 3. HTML forms and hidden inputs

`grep -oE '<input[^>]+name="[^"]+"'` over saved pages — hidden inputs
(`type="hidden"`) are literally the app telling you its parameter names.

### 4. Baseline lists

- `SecLists/Discovery/Web-Content/burp-parameter-names.txt` (~6.5k, highest hit rate)
- arjun's bundled default list (used automatically when `-w` is omitted)
- `samlists` / `OneListForAll` param lists for exhaustive runs

### 5. Assemble

```sh
cat mined-query.txt mined-js.txt mined-forms.txt burp-parameter-names.txt \
  | sort -u > params-example.com.txt
```

Keep casing variants (`userId` vs `userid` vs `user_id` can behave
differently); dedupe exact matches only. Rebuild the list whenever the crawl
or passive sources grow.
