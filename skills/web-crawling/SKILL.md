---
name: web-crawling
description: Map a live web target's full URL and attack surface by combining active crawling (katana, hakrawler, gospider) with passive URL harvesting (gau, waybackurls), then normalize, dedupe, and split the firehose into parameterized URLs, paths, and static assets ready for parameter discovery, content discovery, and vulnerability testing. Use after HTTP probing, when live web endpoints are known and you need their routes, query parameters, JS-referenced endpoints, forms, and historical URLs.
license: Apache-2.0
metadata:
  author: Section9Labs
  category: web-discovery
  stage: post-probing
---

# Web Crawling & URL Harvesting

Goal: turn a list of live web endpoints into a deduplicated, normalized URL +
parameter inventory. Active crawlers find what the app serves *now* (links, JS
endpoints, forms); passive sources find what it served *ever* (old params,
forgotten endpoints, debug routes). Always run both and merge.

Inputs: live base URLs from the probing phase (e.g. httpx output), one per line
in `live.txt`. Outputs: `merged.json` (inventory), `params.txt`, `paths.txt`,
`param_names.txt`, rupu work units + asset marks (see `references/rupu.md`).

## 1. Active crawl — katana (primary)

Standard crawl with JS parsing and known-file seeding (robots/sitemap need
depth >= 3):

```sh
katana -u https://example.com -d 3 -jc -kf robotstxt,sitemapxml \
  -fx -timeout 10 -c 10 -p 10 -rl 150 -silent -jsonl -o katana.jsonl
```

- `-jc`/`-js-crawl` parses JavaScript files for endpoints — this is where most
  hidden API routes come from. Add `-jsl` (jsluice) for deeper JS analysis.
- `-fx`/`-form-extraction` records discovered forms (fields = parameters);
  `-aff` auto-fills and submits forms to reach post-auth-form pages.
- Scope: default `-fs rdn` (root domain + subdomains). Use `-fs fqdn` to pin to
  the exact host, or `-crawl-scope`/`-crawl-out-scope` regexes for custom scope.
- `-jsonl` gives JSON Lines with full request/response; `-or`/`-ob` omit raw
  bodies to keep files small. For plain URLs use `-silent -o urls.txt`.
  **`-f`/`-field` is deprecated** — extract fields with
  `-output-template '{{url}}'` or filter extensions with `-em`/`-ef`.
- Headless for SPA/JS-heavy apps: `katana -u https://example.com -hl
  -system-chrome -d 3 -jc` (needs Chrome installed).
- Passive mode: `katana -u example.com -ps -pss waybackarchive,commoncrawl,alienvault`
  pulls URLs from archives without touching the target (overlaps with gau).
- Multiple targets: `katana -list live.txt ...` or pipe stdin.

Read the output: query-URLs (`?a=b`) are your prime vuln-testing targets; `.js`
URLs feed JS secret/endpoint analysis; form entries give POST parameters.

Full flag reference, scope control, headless and auth detail:
`references/katana.md`.

## 2. Active crawl — hakrawler and gospider (second opinions)

Different parsers find different links; run at least one alongside katana.

```sh
cat live.txt | hakrawler -d 3 -u -subs -insecure -json > hakrawler.jsonl
```

hakrawler is stdin-only. `-u` unique, `-subs` include subdomains (also keeps
cross-host redirects in play — without it they are dropped), `-h "Cookie:
session=abc;;X-Api-Key: k"` for headers (double-semicolon separated).

```sh
gospider -S live.txt -d 3 -c 10 -t 20 --include-subs --sitemap --robots \
  -a --js --json -o gospider-out/
```

`-a`/`--other-source` also pulls archive.org/commoncrawl/VirusTotal/OTX URLs
inline; `-r` shows third-party/external URLs; `-d 0` means **infinite** depth —
only use it deliberately. `--json` format is undocumented; the merge script
handles its `{"output": "..."}` lines, but test before relying on other keys.

Details and authenticated-crawl recipes: `references/passive-and-pipe.md`.

## 3. Passive harvest — gau and waybackurls

```sh
gau example.com --subs --providers wayback,commoncrawl,otx,urlscan \
  --blacklist png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,css \
  --threads 5 --o gau.txt
```

All gau v2 flags are **double-dash**, and the output flag is `--o` (not `-o`).
`--fc 404` / `--mc 200` filter by (archived) status code. `--json` wraps each
URL as `{"url": "..."}`.

```sh
cat domains.txt | waybackurls > wayback.txt
```

waybackurls hits only the Wayback CDX API — newline URLs, no JSON. `-no-subs`
to pin to the apex, `-dates` to prefix snapshot timestamps, `-get-versions` to
list archived copies for diffing old vs new content.

Passive URLs are historical: many are dead, but dead URLs still leak parameter
names, path structure, and old API versions (`/api/v1/` when prod is v3).
Re-probe interesting ones with httpx before deep testing.

## 4. Merge, normalize, reduce

Combine everything with the bundled script (handles plain lists and the JSONL
formats of katana/hakrawler/gospider/gau automatically):

```sh
python3 scripts/merge_urls.py katana.jsonl hakrawler.jsonl \
  gospider-out/* gau.txt wayback.txt \
  --scope example.com --dedupe-params \
  --json merged.json --out-dir inventory/
```

This normalizes (strip fragments, lowercase scheme/host, drop default ports),
dedupes, optionally collapses near-duplicates by (host, path, param-name set)
like uro does, and writes:

- `inventory/params.txt` — URLs with query strings → vuln testing
- `inventory/paths.txt` — parameterless dynamic paths → content discovery seed
- `inventory/static.txt` — static assets (images/fonts/css) → low priority,
  but keep `.js` out of this bucket: JS files go in paths for endpoint mining
- `inventory/param_names.txt` — unique parameter names → wordlist for arjun
- `merged.json` — full structured inventory

If available, external reducers help further:

```sh
cat inventory/params.txt | uro > params.reduced.txt          # kill near-dupes
cat params.reduced.txt | qsreplace 'FUZZ' > params.fuzz.txt  # one payload slot per URL
```

uro/qsreplace usage detail: `references/passive-and-pipe.md`.

## 5. Authenticated crawling

Unauthenticated crawls miss the majority of most apps. Capture a session
cookie/token, then re-crawl:

```sh
katana -u https://example.com -d 3 -jc -H 'Cookie: session=abc123' \
  -H 'Authorization: Bearer eyJ...' -jsonl -o katana-auth.jsonl
cat live.txt | hakrawler -d 3 -u -h 'Cookie: session=abc123' > hak-auth.txt
gospider -s https://example.com -d 3 --cookie 'session=abc123' \
  -H 'Authorization: Bearer eyJ...' --json -o gospider-auth/
```

Diff authenticated vs unauthenticated inventories — URLs present only in the
authenticated set are candidates for access-control testing. Merge both sets
through `merge_urls.py` (tag the runs by filename).

## 6. Handoff (rupu — required)

Every parse step ends in rupu-ingestible output. Exact JSON shapes:
`references/rupu.md`.

1. **Work units** — fan the inventory out for downstream testing:

```sh
python3 scripts/urls_to_work_units.py merged.json --group host \
  --work-units crawl-units.json --assets assets-marks.json
```

`crawl-units.json` is a clean JSON array (first char `[`) of
`{"id","title","targets",["hints"]}` elements for a rupu `for_each:` or a lead
agent `dispatch`. Hand the array to the `work-units` skill for canonical
splitting/normalization. Use `--group route` for one unit per parameterized
route (fine-grained fuzzing fan-out).

2. **Assets** — mark each crawled site/route via `assets.mark` using the
`web:site` / `web:route` kinds at depth `crawled` (`assets-marks.json`
contains ready payloads); record coverage via the `coverage-assets` skill.

3. **Findings** — crawling itself occasionally surfaces direct findings
(exposed `.git/`, backup files, debug endpoints, secrets in JS). Verify with a
raw request, then record via the `finding-report` skill / `findings.report`
with scope `endpoint`, the HTTP exchange in evidence, and an OWASP/CWE id.

Routing of the inventory:
- `inventory/params.txt` → `parameter-discovery` (arjun seed), `xss-testing`,
  `sqli-testing`, `ssrf-testing`, open-redirect checks (pick by param name:
  `url=`, `redirect=`, `path=` → SSRF/redirect; `q=`, `s=` → XSS; `id=` → SQLi/IDOR).
- `inventory/paths.txt` directory prefixes → `content-discovery`
  (ffuf/feroxbuster recursion roots).
- `inventory/param_names.txt` → arjun custom wordlist (`-w`).
- `.js` URLs → JS analysis for secrets and additional API endpoints; feed any
  new endpoints back through step 4.
