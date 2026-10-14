# katana — full reference

ProjectDiscovery's crawler. Install: `go install github.com/projectdiscovery/katana/cmd/katana@latest`.

## Input

| Flag | Meaning |
|---|---|
| `-u`, `-list` | target URL / file of targets (comma-separated accepted) |
| stdin | `cat live.txt \| katana -silent` |
| `-resume` | resume from a previous `resume.cfg` |
| `-e`, `-exclude` | exclude targets (cdn name, cidr, cdn, file) |

## Crawl configuration

| Flag | Meaning |
|---|---|
| `-d`, `-depth` | max depth (default 3). robots/sitemap seeding needs `-d >= 3` |
| `-jc`, `-js-crawl` | parse JS files/endpoints — always use this |
| `-jsl`, `-jsluice` | jsluice-based JS parsing (memory-heavy, finds more) |
| `-kf`, `-known-files` | `robotstxt,sitemapxml` or `all` — seed from known files |
| `-fx`, `-form-extraction` | extract form metadata (action, method, fields) into output |
| `-aff`, `-automatic-form-fill` | auto-fill + submit forms (experimental; reaches post-form pages) |
| `-mdc` | match conditions (DSL), `-fdc` filter conditions |
| `-ct`, `-crawl-duration` | time-box the crawl, e.g. `-ct 10m` |
| `-timeout` | per-request timeout seconds (default 10) |
| `-retry` | retries (default 1) |
| `-proxy` | HTTP/SOCKS5 proxy, e.g. `-proxy http://127.0.0.1:8080` (route through Burp) |
| `-H`, `-headers` | custom header/cookie, repeatable: `-H 'Cookie: s=x' -H 'X-K: v'` |
| `-config`, `-fc` | config file / form-config file |
| `-sf`, `-store-field` | store per-field files under `katana_field/` (url,path,fqdn,qurl,qpath,file,ufile,key,value,kv,dir,udir) |
| `-tlsi`, `-tls-impersonate` | enable experimental client-hello (ja3) randomization |
| `-dr`, `-disable-redirects` | do not follow redirects (followed by default) |

## Scope

| Flag | Meaning |
|---|---|
| `-fs`, `-field-scope` | `fqdn` (exact host), `rdn` (root domain + subs, **default**), `dn` (domain-name keyword) |
| `-cs`, `-crawl-scope` | in-scope regex (repeatable or file) |
| `-cos`, `-crawl-out-scope` | out-of-scope regex |
| `-ns`, `-no-scope` | disable all scoping (follow everything — use with `-ct`) |
| `-do`, `-display-out-scope` | print out-of-scope URLs seen as references (good for third-party inventory) |

## Headless

| Flag | Meaning |
|---|---|
| `-hl`, `-headless` | headless Chrome crawling — required for SPAs that render links client-side |
| `-sc`, `-system-chrome` | use the installed Chrome instead of the bundled one |
| `-sb`, `-show-browser` | show the browser window |
| `-ho`, `-headless-options` | extra chrome flags (repeatable) |
| `-nos`, `-no-sandbox` | needed when running as root in containers |
| `-cwu`, `-chrome-ws-url` | attach to an already-running Chrome via DevTools websocket |
| `-xhr`, `-xhr-extraction` | extract XHR request URL+method (headless mode) |

Headless is ~5-10x slower; run it only on hosts where the plain crawl returns
suspiciously few URLs or the tech stack says React/Vue/Angular.

## Rate limits / concurrency

| Flag | Meaning |
|---|---|
| `-c`, `-concurrency` | concurrent fetchers (default 10) |
| `-p`, `-parallelism` | concurrent targets (default 10) |
| `-rd`, `-delay` | seconds between requests |
| `-rl`, `-rate-limit` | max requests/second (default 150) |
| `-rlm` | max requests/minute |

## Passive sources

| Flag | Meaning |
|---|---|
| `-ps`, `-passive` | passive-only mode (no requests to target) |
| `-pss`, `-passive-source` | `waybackarchive,commoncrawl,alienvault` |

## Output

| Flag | Meaning |
|---|---|
| `-o`, `-output` | output file (plain URLs unless `-jsonl`) |
| `-jsonl`, `-j` | JSON Lines with full request/response objects |
| `-or` / `-ob` | omit raw request/response / omit body in jsonl (keep files sane) |
| `-ot`, `-output-template` | custom template, e.g. `-output-template '{{url}} {{status_code}}'` — **use this instead of the deprecated `-f`/`-field`** |
| `-em` / `-ef` | extension match / filter, e.g. `-em js,json` or `-ef png,css` |
| `-mr` / `-fr` | regex match / filter on output |
| `-silent` | URLs only, no banner |
| `-srd`, `-store-response-dir` | store full responses to disk |

## JSONL schema (what to parse)

```json
{"timestamp":"...",
 "request":{"method":"GET","endpoint":"https://example.com/search?q=1","tag":"a","attribute":"href","source":"https://example.com/"},
 "response":{"status_code":200,"headers":{...},"technologies":["Nginx"],"forms":[{"method":"POST","action":"/login","parameters":["user","pass"]}]}}
```

- URL = `.request.endpoint` (older builds used top-level `.endpoint`).
- `.request.source` tells you which page linked it (useful for auth-boundary mapping).
- `.response.forms[]` (with `-fx`) gives POST parameters that never appear in query strings — feed these names into `param_names.txt` and parameter discovery.

## Recipes

```sh
# Deep crawl, one host, everything on:
katana -u https://example.com -d 5 -jc -kf all -fx -fs fqdn -jsonl -or -ob -o k.jsonl

# JS endpoints only:
katana -u https://example.com -d 3 -jc -em js -silent -o js-urls.txt

# Query-URLs via field store:
katana -u https://example.com -d 3 -jc -sf qurl -silent
# -> katana_field/qurl.txt

# Through Burp with auth:
katana -u https://example.com -proxy http://127.0.0.1:8080 \
  -H 'Cookie: session=abc' -d 3 -jc -jsonl -o k-auth.jsonl

# SPA:
katana -u https://198.51.100.10:8443 -hl -system-chrome -xhr -d 3 -jc -jsonl -o spa.jsonl
```

Hand `k.jsonl` to `scripts/merge_urls.py`, then end the step with
`scripts/urls_to_work_units.py` output per `references/rupu.md`.
