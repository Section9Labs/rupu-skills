# hakrawler, gospider, gau, waybackurls, uro, qsreplace

## hakrawler

Stdin-only, pipe-friendly Go crawler. Fast, shallow, good second opinion.

```sh
echo https://example.com | hakrawler
cat live.txt | hakrawler -d 3 -u -subs -insecure -json > hak.jsonl
```

| Flag | Meaning |
|---|---|
| `-d` | depth (default 2) |
| `-u` | unique URLs only |
| `-subs` | include subdomains in scope; **without it a cross-host redirect (even www→apex) drops the whole target out of scope** — a common cause of empty output |
| `-insecure` | skip TLS verification |
| `-json` | JSON lines: `{"Source":"href","URL":"https://example.com/x"}` (`Source` ∈ href/script/form/iframe/wayback...) |
| `-h` | headers, **double-semicolon** separated: `-h "Cookie: s=abc;;X-Key: v"` |
| `-proxy` | proxy URL |
| `-t` | threads (default 8) |
| `-timeout` | seconds |
| `-dr` | don't follow redirects |
| `-i` | crawl inside-scope only (path-pinned) |
| `-s` | show source in plain output |
| `-size` | max response size |

Empty output? Check: input must include scheme (`https://`), and add `-subs`.

## gospider

```sh
gospider -s https://example.com -d 3 -c 10 -t 20 --json -o out/
gospider -S live.txt -d 2 -c 5 -a --include-subs --sitemap --robots --js -o out/
```

| Flag | Meaning |
|---|---|
| `-s` / `-S` | single site / file of sites |
| `-d` | depth, default 1; **`-d 0` = infinite** |
| `-c` | concurrent requests per site (default 5) |
| `-t` | parallel sites (default 1) |
| `-a`, `--other-source` | ALSO pull from archive.org, commoncrawl, VirusTotal, OTX |
| `-w` | include other-source URLs in crawl queue (not just output) |
| `-r` | include third-party/external URLs in output |
| `--include-subs` | subdomains in scope |
| `--subs` | include subdomains found from other sources |
| `--sitemap` / `--robots` | parse sitemap.xml / robots.txt (robots on by default) |
| `--js` | find links in JS files (on by default) |
| `--cookie` | `--cookie 'session=abc'` |
| `-H`, `--header` | repeatable header |
| `--json` | JSON lines — format undocumented upstream; current builds emit `{"input":"...","source":"body","type":"url","output":"https://..."}`; **verify with a test run before parsing other keys** |
| `-o` | output DIRECTORY (one file per site) |
| `-q` | quiet: URLs only |
| `--blacklist` / `--whitelist` | URL regex filters |
| `-p` | proxy |
| `-u` | user-agent: `web`, `mobi`, or a string |
| `--timeout`, `-k` | timeout seconds / delay seconds |

Plain output lines are prefixed (`[url] - [code-200] - https://...`,
`[javascript] - ...`, `[form] - ...`, `[subdomains] - ...`); strip the
bracket prefix or use `--json` and take `.output`.

## gau (getallurls, lc/gau v2)

Passive URL harvest from Wayback, Common Crawl, OTX, URLScan. **Double-dash
flags only**, and output is `--o` (not `-o`). Beware oh-my-zsh aliasing
`gau` → `git add -u`; call the binary by path if in doubt.

```sh
gau example.com --subs --threads 5 \
  --providers wayback,commoncrawl,otx,urlscan \
  --blacklist png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot \
  --o gau.txt
cat domains.txt | gau --subs --json --o gau.jsonl
```

| Flag | Meaning |
|---|---|
| `--subs` | include subdomains |
| `--providers` | comma list: `wayback,commoncrawl,otx,urlscan` |
| `--blacklist` | drop extensions |
| `--fc` / `--mc` | filter / match (archived) status codes, e.g. `--fc 404,302` |
| `--ft` / `--mt` | filter / match MIME types |
| `--from` / `--to` | date range `YYYYMM` |
| `--json` | lines of `{"url":"..."}` |
| `--o` | output file |
| `--threads` | worker count |
| `--fp` | probe-free: remove duplicates differing only by params? (verify in `--help`; versions vary) |
| `--retries`, `--timeout`, `--proxy` | plumbing |

Config: `~/.gau.toml` (API keys for urlscan raise completeness).

## waybackurls

Wayback CDX only; newline URLs, **no JSON**.

```sh
cat domains.txt | waybackurls > wayback.txt
echo example.com | waybackurls -no-subs
echo example.com | waybackurls -dates          # prefix snapshot timestamp
echo example.com | waybackurls -get-versions   # archived snapshot URLs for diffing
```

Use `-get-versions` on interesting dead URLs (old config files, removed admin
panels) and fetch the archive copy to recover secrets/structure.

## Post-processing: uro and qsreplace

**uro** collapses near-duplicate URLs (same route, different param values,
incrementing IDs, blog slugs, static junk):

```sh
cat all-urls.txt | uro > reduced.txt
cat all-urls.txt | uro --whitelist php asp aspx jsp   # keep only these exts
cat all-urls.txt | uro --blacklist png jpg svg        # drop these exts
cat all-urls.txt | uro --filters hasparams            # only URLs with params
# other filters: noparams, hasext, noext, keepcontent, keepslash, vuln
```

**qsreplace** rewrites every query value to a fixed string so each unique
(route, param-set) becomes one fuzzable URL:

```sh
cat params.txt | qsreplace 'FUZZ' | sort -u > fuzz-targets.txt
cat params.txt | qsreplace '"><svg onload=confirm(1)>' > xss-probe.txt
cat params.txt | qsreplace -a 'PAYLOAD'   # -a: append instead of replace
```

`scripts/merge_urls.py --dedupe-params` performs a uro-like reduction
(dedupe on host+path+sorted-param-names) in pure stdlib if uro is absent.

## Authenticated crawling

1. Log in via browser or curl; capture `Cookie:` and/or `Authorization:`.
2. Re-crawl with headers:
   - katana: `-H 'Cookie: session=abc' -H 'Authorization: Bearer eyJ...'`
   - hakrawler: `-h "Cookie: session=abc;;Authorization: Bearer eyJ..."`
   - gospider: `--cookie 'session=abc' -H 'Authorization: Bearer eyJ...'`
3. Exclude logout URLs or the crawler kills its own session:
   katana `-cos '.*logout.*'`, gospider `--blacklist 'logout|signout'`.
4. Merge auth + unauth runs separately, diff:
   `comm -13 <(sort unauth.txt) <(sort auth.txt) > auth-only.txt` —
   `auth-only.txt` seeds access-control testing.

Every merge/parse step here must end in rupu output — see `references/rupu.md`.
