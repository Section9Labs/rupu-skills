---
name: http-probing
description: Live-host triage and technology fingerprinting with httpx, whatweb, and webanalyze — turns raw host/domain/URL lists into a probed, fingerprinted inventory of live web endpoints; use as the first active step of a web assessment to learn which targets speak HTTP(S), on which ports, what stack they run, and which deserve deeper testing.
license: Apache-2.0
compatibility: Linux/macOS agents with httpx (ProjectDiscovery Go binary), whatweb, webanalyze installed; Python 3 for the parsing scripts
metadata:
  author: Section9Labs
---

# HTTP Probing & Technology Fingerprinting

Goal: given targets from scope, subdomain enumeration (`subdomain-enum`), or network
recon, produce a triaged inventory of **live web endpoints** with status, title,
server, IP/CDN, and technology stack — then hand that inventory to crawling,
content discovery, tech-specific scanning, and TLS testing.

Pipeline: **probe (httpx) → filter to live → fingerprint (httpx -td / whatweb /
webanalyze) → normalize → record assets + emit work units**.

Every parse step ends in rupu-ingestible output (work-units array, `assets.mark`,
or `findings.report`) — see `references/rupu.md` for the exact shapes.

## Step 1 — Probe the raw target list with httpx

This is the ProjectDiscovery **Go binary** (`projectdiscovery/httpx`), NOT the
Python `httpx` library. Verify with `httpx -version`.

Inputs: pipe on stdin or use `-l hosts.txt`. Inputs may be bare hostnames, IPs,
CIDRs, or full URLs. By default httpx tries HTTPS first then falls back to HTTP;
use `-nf`/`-no-fallback` to probe both schemes independently, or `-nfs` to keep
the scheme exactly as given in the input.

Core probe over the common web ports, JSON Lines out:

```sh
cat hosts.txt | httpx -silent \
  -p 80,443,8080,8443,8000,8888,3000,9090 \
  -sc -title -server -cl -location -ip -cname -td \
  -fr -timeout 10 -retries 1 -threads 50 \
  -json -o httpx.jsonl
```

Flag intent (full reference: `references/httpx.md`):
- `-p` / `-ports` — port set; expand to `-p -` style big sets only when the
  engagement calls for it (see the reference for curated port lists).
- `-sc -title -server -cl -location -ip -cname` — status code, page title, Server
  header, content length, redirect target, resolved IP, CNAME chain.
- `-td` — Wappalyzer-dataset tech detection; populates `tech[]` in the JSON.
- `-fr` — follow redirects (fills `final_url`); without it you see the raw 30x.
- `-cdn` is **on by default**: `cdn`, `cdn_name`, `cdn_type` appear in JSON.
- `-json` — JSON **Lines** output (one object per line). This is the
  machine-readable form everything downstream parses. `-csv` for spreadsheets.
- `-rl <n>` rate limit (req/sec), `-threads`, `-timeout`, `-retries` — tuning.

Enrichment passes worth running on interesting targets:
- `-favicon` — mmh3 favicon hash; pivot it through Shodan `http.favicon.hash:` to
  find siblings of the same app.
- `-jarm` — TLS fingerprint; clusters infrastructure (C2 frameworks, shared
  stacks) across IPs.
- `-hash sha256` — body hash; dedupe identical default pages across many vhosts.
- `-sr -srd responses/` — store full responses to disk for offline grepping.
- `-screenshot` — headless Chrome screenshots for fast visual triage of hundreds
  of endpoints.
- `-irr` (`-include-response`) / `-irh` — include raw request/response (or just
  headers) in the JSON when you need the exchange as evidence.
- `-method` — report the final method after redirects.

Response filtering when the list is huge: `-mc 200,201,204,301,302,401,403,405`
match status, `-fc 404` filter status, `-ms`/`-fs` match/filter by length, `-mr`
match body regex (e.g. `-mr 'admin|login'`).

### Reading the JSON Lines

Each line is one live endpoint. Key fields: `url` (probed URL), `input` (what you
fed in), `scheme`, `port`, `status_code`, `title`, `webserver`, `tech` (array
from `-td`), `content_length`, `host` (resolved IP), `a` (all A records),
`cname`, `cdn`/`cdn_name`, `location`, `final_url`, `failed`. Full field guide in
`references/httpx.md`.

Triage heuristics:
- `401`/`403` on an admin-looking title or path → content discovery + auth testing.
- `tech` containing a CMS (WordPress, Joomla, Drupal) → `cms-testing`.
- Identical `content_length` + `hash` across many hosts → one app, test once.
- `cdn: true` → origin is fronted; port scans / direct-IP tricks go to the origin
  IP (via `cname`/historic DNS), not the CDN edge.
- Non-standard ports (8080/8443/3000/9090) → dev consoles, APIs, management UIs;
  usually the softest targets.

## Step 2 — Parse, normalize, emit work units

Run the bundled parser on the JSONL:

```sh
python3 scripts/parse_httpx.py httpx.jsonl \
  -o endpoints.json --work-units units.json
```

- `endpoints.json` — flat normalized array: one record per live endpoint
  (`url, input, host, ip, port, scheme, status, title, server, tech[], cdn,
  content_length, location, final_url`).
- `units.json` — rupu work-units JSON array (first char `[`), one unit per live
  site: `{"id","title","targets":[url],"hints":{"tech":[...],"status":...,"server":...}}`.
  Hand this to the `work-units` skill for normalization/splitting, then a rupu
  workflow `for_each:` or a lead agent `dispatch` fans out one child per site.

Record every live endpoint as an asset:

```sh
python3 scripts/httpx_to_assets.py endpoints.json
```

This prints one `assets.mark` payload per endpoint — kind `web:site`, coordinates
`[{"t":"url","v":"https://..."}]`, depth `mapped` — ready to pass to the tool.
Use the `coverage-assets` skill conventions; exact shapes in `references/rupu.md`.

## Step 3 — Fingerprint the live set

httpx `-td` already gives a Wappalyzer-based baseline. Deepen it on the live set:

### whatweb

```sh
whatweb -a 3 --log-json=whatweb.json --log-brief=whatweb.txt -i live_urls.txt
# or pipe: cat live_urls.txt | whatweb -a 3 -i /dev/stdin --log-json=whatweb.json
```

- Aggression `-a`: **1 = Stealthy (default), 3 = Aggressive, 4 = Heavy** (2 is
  unused). Level 1 is one request; 3 fires extra plugin-guided requests when a
  level-1 match suggests more (version-revealing paths); 4 hits every plugin URL.
  Use `-a 3` on the live set, `-a 4` only on priority targets.
- `--log-json=FILE` needs the optional charset/rchardet gems to be reliable; keep
  `--log-brief` as a text fallback. `-U` sets the User-Agent.
- Output is plugin matches: CMS + version, frameworks, JS libs, server modules,
  cookies, email addresses, country. Versions here (e.g. `WordPress[5.8.1]`,
  `Apache[2.4.49]`) are direct inputs to CVE lookup and `nuclei` template choice.

### webanalyze (the maintained Wappalyzer substitute)

The official Wappalyzer npm CLI is **deprecated** and its fingerprint DB was
locked down. Use `rverton/webanalyze` (DB now mirrored via enthec) or httpx
`-td`; keep the Wappalyzer **browser extension** for manual confirmation.

```sh
webanalyze -update                      # fetch technologies.json once
webanalyze -hosts live_urls.txt -crawl 1 -worker 8 \
  -apps technologies.json -output json > webanalyze.json
```

`-host` for a single target, `-hosts <file>` for many, `-crawl <n>` follows n
same-site links (catches tech only visible on subpages), `-worker <n>` is
singular, `-apps <file>` points at the fingerprint DB (NOT `-technologies`).

Merge the three sources (httpx `tech`, whatweb plugins, webanalyze apps) per URL;
union the tech names, keep the most specific version string. Reading guidance and
tech→follow-on-skill mapping: `references/fingerprinting.md`.

**rupu handoff for this step:** fold the merged tech into each endpoint's
work-unit `hints.tech`, re-mark fingerprinted sites with `assets.mark` (still
depth `mapped` — probing/fingerprinting is mapping), and if fingerprinting itself
proves an issue (e.g. verbose version disclosure that is policy-reportable, an
exposed admin console on a non-standard port), file it with `findings.report`
(scope `endpoint`, HTTP exchange in evidence, OWASP/CWE id) via the
`finding-report` skill. Shapes in `references/rupu.md`.

## Step 4 — Hand off the triaged inventory

Route each endpoint by what you learned:

| Signal | Next skill |
|---|---|
| Any live site | `web-crawling` (katana/hakrawler/gospider on `targets[0]`) |
| 200/301/401/403, thin tech data | `content-discovery` (ffuf/feroxbuster/dirsearch) |
| Tech/version identified | `nuclei` with `-as` (tech-driven) or tag-matched templates |
| WordPress / Joomla / Drupal in tech | `cms-testing` (wpscan / joomscan / droopescan) |
| Any HTTPS endpoint | `tls-testing` (testssl.sh / sslscan) |
| CDN-fronted | origin discovery before host-level testing |

The `units.json` array is the carrier: each unit's `hints` tells the child agent
which of these to run first. Dispatch via the `work-units` skill.

## Quick one-liner reference

```sh
# scope list -> live inventory in one pass
cat scope.txt | httpx -silent -p 80,443,8080,8443 -sc -title -td -server -ip -cdn -fr -json -o httpx.jsonl
python3 scripts/parse_httpx.py httpx.jsonl -o endpoints.json --work-units units.json --urls live_urls.txt
python3 scripts/httpx_to_assets.py endpoints.json
whatweb -a 3 -i live_urls.txt --log-json=whatweb.json
webanalyze -hosts live_urls.txt -crawl 1 -output json > webanalyze.json
```
