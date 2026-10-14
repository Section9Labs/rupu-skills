# Technology fingerprinting — whatweb, webanalyze, httpx -td

Three sources, one merged picture. Run httpx `-td` on everything (free — it rides
the probe), whatweb `-a 3` on the live set, webanalyze where you want crawl-depth
detection. Merge per URL: union tech names, keep the most specific version.

## whatweb

Ruby; ~1800 plugins. Each plugin matches on headers, cookies, body regexes, URL
paths, favicon hashes, and can extract versions, accounts, modules.

### Aggression levels (`-a`)

| Level | Name | Behavior |
|---|---|---|
| 1 | Stealthy (default) | one HTTP request per target (+ redirects) |
| 2 | — | unused |
| 3 | Aggressive | if a level-1 plugin match suggests it, send that plugin's extra URL requests (e.g. hit `/wp-content/...` to pin a WordPress version) |
| 4 | Heavy | send every plugin's aggressive requests regardless of level-1 hits — noisy, thorough |

Strategy: `-a 1` for a quiet first pass, `-a 3` for the standard assessment pass,
`-a 4` reserved for priority targets where exact versions matter.

### Invocation

```sh
whatweb -a 3 https://app.example.com
whatweb -a 3 -i live_urls.txt --log-json=whatweb.json --log-brief=whatweb.txt
cat live_urls.txt | whatweb -a 3 -i /dev/stdin --log-json=whatweb.json
whatweb -a 3 -U 'Mozilla/5.0 (pentest)' --header 'Cookie: session=abc' https://app.example.com
whatweb --proxy 127.0.0.1:8080 https://app.example.com   # record in Burp
```

- `--log-json=FILE` — JSON log; needs the optional `charset`/`rchardet` gem setup
  to be reliable on odd encodings — always keep `--log-brief` text as fallback.
- `--list-plugins` / `--info-plugins <name>` — see what a plugin matches.
- `-v` verbose explains *why* each plugin matched (which regex/header).
- `--max-threads <n>` for list input; `--follow-redirect` modes if defaults bite.

### Reading output

Brief form:

```
https://app.example.com [200 OK] Apache[2.4.49], Country[UNITED STATES][US],
HTTPServer[Apache/2.4.49 (Unix)], JQuery[1.12.4], MetaGenerator[WordPress 5.8.1],
PHP[7.4.3], Title[Example Corp], WordPress[5.8.1], Cookies[PHPSESSID]
```

- `Plugin[value]` — value is usually a version or extracted string.
- High-signal plugins: `HTTPServer`, `X-Powered-By`, `MetaGenerator`,
  CMS plugins (`WordPress`, `Joomla`, `Drupal`), `JQuery`/JS libs (old versions ⇒
  known XSS/prototype-pollution CVEs), `Cookies` (session cookie names reveal
  frameworks: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `laravel_session`,
  `connect.sid`), `Email`, `Open-Redirect`, `WWW-Authenticate` (realm names),
  `UncommonHeaders`.
- JSON log: one object per request with `target`, `http_status`, and `plugins`
  as `{name: {"version": [...], "string": [...], "module": [...]}}` — a redirect
  chain yields multiple objects per input; the last one is the final page.

## webanalyze (Wappalyzer substitute)

The official Wappalyzer npm CLI is deprecated and the upstream fingerprint repo
was taken private; `rverton/webanalyze` is the maintained Go port, pulling its DB
from the enthec mirror of the fingerprints.

```sh
webanalyze -update                              # writes technologies.json in CWD
webanalyze -host https://app.example.com -crawl 1
webanalyze -hosts live_urls.txt -worker 8 -crawl 1 \
  -apps technologies.json -output json > webanalyze.json
webanalyze -host https://app.example.com -output csv
```

- `-update` first (and periodically) — stale DBs miss modern stacks.
- `-apps <file>` — path to the fingerprint DB (the flag is `-apps`, NOT
  `-technologies`).
- `-crawl <n>` — follow n same-site links; catches tech only present on
  subpages (admin panels, embedded widgets).
- `-worker <n>` — concurrency (singular `-worker`).
- `-output json` — one JSON object per host with `hostname` and `matches[]`,
  each match holding `app_name`, `version`, and the Wappalyzer `categories`.
- `-search` (on by default) tries subdomain hints from the DB.

Wappalyzer **browser extension** remains useful for manual confirmation on a
target you have open anyway; treat it as confirmation, not a pipeline stage.

## httpx -td

Embedded Wappalyzer dataset; emits `tech[]` per endpoint in the probe JSON with
zero extra cost. Entries look like `WordPress:5.8.1` or `Cloudflare` — split on
the first `:` for name/version. Good breadth, weaker version extraction than
whatweb `-a 3`; use it as the baseline layer.

## Merging and acting on the stack

Merge rule per URL: `tech = union(httpx.tech, whatweb.plugins, webanalyze.matches)`;
for versions prefer whatweb `-a 3`/`-a 4` extraction > webanalyze > httpx.

### Tech → follow-on skill routing

| Fingerprint | Action / next skill |
|---|---|
| WordPress | `cms-testing`: wpscan with `--api-token` (no token ⇒ no vuln data), `-e vp,ap,at,u` |
| Joomla | `cms-testing`: joomscan `-u ... -ec`; droopescan `scan joomla` |
| Drupal | `cms-testing`: droopescan `scan drupal -u ... -e p,t,v` |
| Any identified product+version | `nuclei -as` (tech-driven template selection) or `-tags <product>`; CVE lookup on exact versions |
| PHP / `X-Powered-By` versions | EOL check; version-specific CVEs; LFI/upload test focus in later stages |
| ASP.NET / IIS | ViewState, padding-oracle history, short-name enumeration in `content-discovery` |
| Java (JSESSIONID, Tomcat, WebLogic, JBoss) | manager/console paths in `content-discovery`; deserialization focus |
| Node/Express (`connect.sid`, `X-Powered-By: Express`) | API-first crawling (`web-crawling` with JS parsing), prototype pollution focus |
| SPA frameworks (React/Angular/Vue) | katana headless (`-hl`) in `web-crawling`; JS file mining for API routes |
| nginx/Apache version in Server header | version CVEs; misconfig templates in nuclei |
| Jenkins/GitLab/Grafana/Kibana/SonarQube | default-cred + known-CVE checks immediately (nuclei tags) |
| Cloudflare/Akamai/Fastly (`cdn:true`) | origin-IP discovery before host-level or TLS testing |
| Any HTTPS | `tls-testing`: testssl.sh `-U --json-pretty`, sslscan `--xml=` |
| Thin fingerprint (just a server header) | `content-discovery` + `web-crawling` to surface the app |

### rupu outputs for the fingerprint step

Per `references/rupu.md`:
1. Update each endpoint's work unit `hints.tech` with the merged list and re-emit
   `units.json` (hand to the `work-units` skill).
2. `assets.mark` each fingerprinted site (`web:site`, depth `mapped`) with the
   tech summary in the label.
3. Reportable observations surfaced purely by fingerprinting — e.g. an exposed
   management console, or verbose version disclosure the engagement treats as a
   finding — go through the `finding-report` skill: scope `endpoint`,
   `target_ref` = URL, HTTP exchange in evidence (use httpx `-irr` or a curl of
   the matching request), classified by CWE (e.g. CWE-200) or OWASP WSTG id
   (e.g. WSTG-INFO-02 / WSTG-INFO-08).
