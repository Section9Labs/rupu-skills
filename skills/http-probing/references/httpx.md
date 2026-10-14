# httpx (ProjectDiscovery) — full reference

The Go binary from `projectdiscovery/httpx`. If `httpx -version` errors or shows
a Python package, you have the wrong `httpx` on PATH — install with
`go install github.com/projectdiscovery/httpx/cmd/httpx@latest` and ensure
`~/go/bin` precedes any Python shim.

## Input

| Form | Example |
|---|---|
| stdin | `cat hosts.txt \| httpx` |
| list file | `httpx -l hosts.txt` |
| single | `httpx -u 192.0.2.10` |
| request file | `-rr requests.txt` (raw HTTP requests, Burp export style) |

Inputs may be hostnames (`app.example.com`), IPs, CIDRs (`198.51.100.0/24` —
httpx expands them), or full URLs. CIDR + `-p` is a fast "what web services live
here" sweep after network recon.

Scheme handling: by default httpx probes **HTTPS first and falls back to HTTP**
per input. `-nf`/`-no-fallback` probes and reports **both** schemes. `-nfs`
(`-no-fallback-scheme`) probes **only** the scheme present in the input URL.

## Ports

- `-p 80,443,8080,8443` — explicit list. Ranges work: `-p 8000-8100`.
- `-p http:80,https:443` — pin scheme per port.
- Curated sets worth keeping handy:
  - Baseline: `80,443,8080,8443`
  - Extended: `80,81,443,591,2082,2087,2095,3000,4443,5000,7001,8000,8008,8080,8081,8443,8834,8888,9090,9443`
  - Management/dev: `3000,4200,5000,5601,8000,8081,8161,8888,9000,9090,9200,15672`

## Probe/display flags

| Flag | Field(s) in JSON | Notes |
|---|---|---|
| `-sc` / `-status-code` | `status_code` | |
| `-title` | `title` | HTML `<title>` |
| `-td` / `-tech-detect` | `tech[]` | Wappalyzer fingerprint dataset embedded in httpx |
| `-server` / `-web-server` | `webserver` | Server header |
| `-cl` / `-content-length` | `content_length` | |
| `-ct` | `content_type` | |
| `-location` | `location` | Location header of a 30x |
| `-ip` | `host`, `a[]` | resolved IP(s) |
| `-cname` | `cname[]` | CNAME chain |
| `-cdn` | `cdn`, `cdn_name`, `cdn_type` | **on by default**; detects cdn/waf/cloud |
| `-method` | `method` | final method after redirects |
| `-websocket` | `websocket` | |
| `-rt` | `time` | response time |
| `-lc -wc` | `lines`, `words` | body line/word counts |
| `-favicon` | `favicon` | mmh3 hash of /favicon.ico |
| `-jarm` | `jarm` | active TLS fingerprint |
| `-hash sha256` | `hash.body_sha256`, `hash.header_sha256` | also md5/mmh3/simhash |
| `-fr` / `-follow-redirects` | `final_url`, `chain_status_codes` | `-maxr <n>` cap; `-fhr` follow on same host only |
| `-probe` | `failed` | print result for dead hosts too (`failed: true`) |
| `-irr` / `-include-response` | `request`, `response`/raw fields | full exchange in JSON — use when you need HTTP evidence |
| `-irh` | response headers only | lighter than `-irr` |
| `-include-chain` | `chain[]` | redirect chain bodies |

## Matchers / filters (output pruning)

- `-mc 200,401,403` / `-fc 404,502` — match/filter status codes.
- `-ms <len>` / `-fs <len>` — match/filter exact content length.
- `-mr '<regex>'` / `-fr-` style `-fe` — match regex in body / filter by error page.
- `-ml` / `-fl` — match/filter line count; `-mw`/`-fw` word count.
- `-mfc` — match favicon hash list (pivot hunting: probe wide, keep only hosts
  whose favicon matches a known app's mmh3).
- `-mdc` / `-fdc` — DSL conditions, e.g. `-mdc 'status_code==200 && contains(title,"Admin")'`.

## Output

- `-json` — **JSON Lines** (one object per line). The canonical machine form.
  `-jsonl` is accepted as an alias in current builds; `-json` is the documented
  spelling.
- `-o out.file` — write to file (works with `-json` and `-csv`).
- `-csv` — CSV with header row.
- `-silent` — results only, no banner. `-nc` strips ANSI color.
- `-sr -srd responses/` — store response bodies+headers to disk, one file per
  endpoint, with an `index.txt`. Grep this corpus for secrets, comments,
  endpoints: `grep -ri "api_key\|internal\." responses/`.
- `-screenshot` (+ `-system-chrome` to use installed Chrome) — PNG per endpoint
  under `output/screenshot/`; `-esb -ehb` to exclude body/headers from JSON when
  screenshotting at scale.

## Performance / network

- `-threads <n>` (default 50), `-rl <req/sec>` rate limit, `-rlm` per-minute.
- `-timeout <sec>` (default 10), `-retries <n>`, `-delay <dur>`.
- `-x GET,POST` probe methods; `-body '<data>'` request body.
- `-H 'Cookie: session=abc'` custom headers (repeatable) — probe authenticated.
- `-proxy http://127.0.0.1:8080` — route through Burp for a recorded pass.
- `-random-agent` on by default in recent builds; `-H 'User-Agent: ...'` to pin.
- `-pa` probe all resolved IPs (multi-A targets); `-r resolvers.txt` custom DNS.

## JSON field guide (what to parse)

```json
{
  "timestamp": "...",
  "url": "https://app.example.com:8443",
  "input": "app.example.com",
  "scheme": "https",
  "port": "8443",
  "method": "GET",
  "status_code": 200,
  "title": "Example Admin",
  "webserver": "nginx/1.24.0",
  "content_type": "text/html",
  "content_length": 4821,
  "tech": ["Nginx:1.24.0", "React", "Express"],
  "host": "203.0.113.7",
  "a": ["203.0.113.7"],
  "cname": ["edge.cdn.example.net"],
  "cdn": true,
  "cdn_name": "cloudflare",
  "cdn_type": "waf",
  "location": "/login",
  "final_url": "https://app.example.com:8443/login",
  "chain_status_codes": [302, 200],
  "favicon": "-1588080585",
  "jarm": "29d29d15d29d29d00042d42d0000005af340b78d2db5e9...",
  "hash": {"body_sha256": "...", "header_sha256": "..."},
  "words": 320, "lines": 41, "time": "212ms",
  "failed": false
}
```

Parsing rules of thumb:
- Key off `url` for identity; keep `input` to trace back to the scope line.
- `port` is a **string** in the JSON; coerce.
- `tech` entries may be `Name` or `Name:version` — split on the first `:`.
- Skip lines where `failed` is true (only present with `-probe`).
- `host` is the primary resolved IP; `a` lists all.

## Favicon & JARM pivoting

- Favicon: `-favicon` emits the mmh3 hash Shodan uses. Pivot:
  `http.favicon.hash:-1588080585` in Shodan finds every exposed instance of the
  same app — great for locating forgotten staging copies of a scoped app.
  Known-hash lists map hashes → products (e.g. Jenkins, GitLab, Grafana).
- JARM: `-jarm` fingerprints the TLS server stack. Identical JARM across scoped
  IPs ⇒ same load balancer/app tier; a JARM matching a known C2/product
  fingerprint identifies the software even when HTTP is mute. Pivot JARM values
  through Shodan `ssl.jarm:` / internet-scan datasets.

## Recipes

```sh
# Dead-or-alive sweep of a /24 after nmap
echo 198.51.100.0/24 | httpx -silent -p 80,443,8080,8443 -sc -title -json -o sweep.jsonl

# Dedupe mass-vhost wildcard noise by body hash
cat subs.txt | httpx -silent -hash sha256 -sc -cl -json | \
  python3 -c 'import sys,json;seen=set()
for l in sys.stdin:
  d=json.loads(l);h=(d.get("hash") or {}).get("body_sha256")
  if h in seen: continue
  seen.add(h);print(d["url"])'

# Authenticated probe through Burp with evidence capture
cat live_urls.txt | httpx -silent -H 'Cookie: session=REDACTED' \
  -proxy http://127.0.0.1:8080 -irr -json -o authed.jsonl

# Visual triage
cat live_urls.txt | httpx -silent -screenshot -system-chrome
```
