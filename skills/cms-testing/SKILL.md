---
name: cms-testing
description: Identify and attack CMS platforms (WordPress, Joomla, Drupal, generic) — fingerprint version/plugins/themes, enumerate users, map known CVEs, and run credential attacks with wpscan, joomscan, droopescan, cmsmap, and CMSeeK. Use when httpx -td, whatweb, or nuclei fingerprinting indicates a target runs a CMS.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# CMS Testing

Methodology for identifying and attacking content-management systems. Entry
point: fingerprinting (httpx `-td`, whatweb, nuclei tech templates) has flagged
a site as WordPress / Joomla / Drupal / unknown-CMS. Exit point: confirmed
component CVEs and valid credentials handed to exploitation, every step
recorded into rupu (see `references/rupu.md` for exact JSON shapes).

## Pipeline

```
detect CMS -> enumerate version/plugins/themes/users -> map to known CVEs
          -> credential attack on the login surface -> hand off to exploitation
```

Every parse step below ends with one of: a work-units JSON array (normalize via
the `work-units` skill), `assets.mark` calls (per the `coverage-assets` skill),
or `findings.report` calls (write via the `finding-report` skill).

## Step 1 — Detect which CMS

If the fingerprint is ambiguous, confirm before wasting time with the wrong
scanner:

```
# broad detector, 180+ CMSes, follows redirects, detects version where possible
cmseek -u https://192.0.2.10 --follow-redirect --random-agent

# or let cmsmap auto-detect (omit -f) — it identifies WP/Joomla/Drupal and runs checks
cmsmap https://192.0.2.10

# cross-check
whatweb -a 3 https://192.0.2.10 --log-json=whatweb.json
```

Manual tells: `/wp-login.php`, `/wp-content/` (WordPress); `/administrator/`,
`/media/system/js/` (Joomla); `/CHANGELOG.txt`, `X-Generator: Drupal`,
`/core/misc/drupal.js` (Drupal).

**Handoff:** mark the site `assets.mark` kind `web:site` depth `mapped`, label
including the detected CMS. Use the generic detectors (cmseek/cmsmap) only to
*route*; always follow with the dedicated per-CMS scanner — they have far
deeper plugin/vuln databases.

## Step 2 — WordPress: wpscan

Full flag/strategy depth in `references/wordpress.md`. Core run:

```
wpscan --url https://192.0.2.10 \
  --api-token $WPSCAN_TOKEN \
  --enumerate vp,vt,u,cb,dbe \
  --plugins-detection mixed --plugins-version-detection aggressive \
  --random-user-agent --disable-tls-checks \
  -f json -o wpscan.json
```

Key points:
- **`--api-token` is mandatory for vulnerability data.** Without it you get
  component versions but zero CVE mapping (free tier: 25 req/day).
- `--enumerate vp,vt,u,cb,dbe` = vulnerable plugins, vulnerable themes, users,
  config backups, DB exports. Use `ap,at` (all plugins/themes) or `p,t` for a
  full inventory when the vuln-only view misses things; `tt` timthumbs.
- `--plugins-detection aggressive` brute-forces `/wp-content/plugins/<slug>/`
  (thousands of requests, finds everything); `passive` reads only homepage
  HTML; `mixed` (default) is the usual choice.
- `--stealthy` = passive detection + random UA; use when quiet matters.
- Proxy: `--proxy http://127.0.0.1:8080`, creds `--proxy-auth u:p`.

**Credential attack** (after `u` enumeration gives usernames):

```
wpscan --url https://192.0.2.10 \
  --usernames admin,editor --passwords rockyou.txt \
  --password-attack xmlrpc --max-threads 20 -f json -o wpscan-brute.json
```

`--password-attack` choices: `wp-login` (POST to wp-login.php, slow, logged),
`xmlrpc` (one request per guess, much faster), `xmlrpc-multicall`
(**amplification**: hundreds of guesses packed into a single
`system.multicall` request against `/xmlrpc.php` — the fastest option on
WP < 4.4 or where multicall isn't blocked). Try `xmlrpc-multicall` first;
wpscan falls back automatically if it detects it won't work.

**Parse/handoff:**

```
python3 scripts/parse_wpscan.py wpscan.json \
  --out wp-merged.json --work-units wp-units.json \
  --findings wp-findings.json --assets wp-assets.json
```

The script extracts core version + its vulns, vulnerable plugins/themes (title,
CVEs, fixed-in), interesting findings, users, and emits: a work-units array
(one unit per vulnerable component for exploitation fan-out — hand to the
`work-units` skill), `findings.report` payloads (scope `endpoint`, severity
from the vuln class, CVE references), and an `assets.mark` of the site as
`web:site` depth `tested`. Report confirmed vulns via the `finding-report`
skill; mark `/wp-login.php` and `/xmlrpc.php` as `web:route` assets.

## Step 3 — Joomla: joomscan

```
joomscan --url https://192.0.2.20 --enumerate-components   # or -ec
joomscan --url https://192.0.2.20 -ec --random-agent --proxy http://127.0.0.1:8080
```

Output is **text only** (plus an HTML report under
`reports/<target>/`); no JSON. Read for: `[+] Detecting Joomla Version`,
core CVE hits (`[++] Target vulnerable to CVE-...`), component list with
per-component exploit-db references, admin page location
(`/administrator/`), config backups (`configuration.php.bak`), debug mode,
and directory-listing paths. Cross-check version findings with droopescan
(`droopescan scan joomla -u ...`) which is more version-accurate.

**Handoff:** for each component with a referenced CVE/EDB-ID, create a work
unit; mark `/administrator/` as `web:route` depth `tested`; report confirmed
core-version CVEs via `finding-report`. Details: `references/joomla-drupal-generic.md`.

## Step 4 — Drupal (and others): droopescan

```
droopescan scan drupal -u https://192.0.2.30 -t 32 \
  -e p,t,v,i -n 2000 --output json > droope.json
```

- `-e`: `p` plugins/modules, `t` themes, `v` version, `i` interesting URLs,
  `a` all (default).
- `--output json` gives a clean machine-readable object:
  `{"plugins":{"finished":true,"findings":[{"name":...,"url":...}]},
  "themes":{...}, "version":{"findings":["10.2.x",...]}, "interesting urls":...}`.
- Also scans `joomla`, `silverstripe`, `wordpress`, `moodle` — swap the first arg.

Map the version to the Drupalgeddon family: SA-CORE-2014-005 (CVE-2014-3704,
7.x < 7.32), SA-CORE-2018-002 (CVE-2018-7600, drupalgeddon2),
SA-CORE-2018-004 (CVE-2018-7602), SA-CORE-2019-003 (CVE-2019-6340, RESTful
RCE). Confirm module versions against drupal.org security advisories.

**Handoff:** work unit per candidate core/module CVE; `assets.mark` interesting
URLs as `web:route` depth `crawled`; `findings.report` the confirmed version
vulns.

## Step 5 — Generic / deep sweep: cmsmap and CMSeeK

```
# cmsmap: force the engine with -f (W=WordPress, J=Joomla, D=Drupal), -F full plugin scan
cmsmap https://192.0.2.40 -f W -F --noedb -o cmsmap.txt
# built-in brute force once you have users:
cmsmap https://192.0.2.40 -f W -u users.txt -p rockyou.txt
```

cmsmap is the dionach/CMSmap fork lineage — forks drift, run `cmsmap --help`
and trust it over memory. `-F` enables the full (not just popular) plugin
list; `--noedb` skips local exploit-db lookups if searchsploit isn't
installed; `-d` disables dynamic checks.

CMSeeK deep mode: `cmseek -u https://192.0.2.40` then choose deep scan when a
CMS is detected — for WP/Joomla/Drupal it enumerates users, plugins, themes
and writes JSON to `Result/<host>/cms.json` (parse that file directly).

Use the generic tools when: the CMS is exotic, the per-CMS tool is blocked by a
WAF signature, or you want a second opinion on version claims.

## Step 6 — Known-CVE confirmation and exploitation handoff

For every `component@version -> CVE` pair:
1. Confirm with nuclei where a template exists:
   `nuclei -u https://192.0.2.10 -tags wordpress,joomla,drupal -jsonl -o nuclei-cms.jsonl`
   (also `-as` for tech-driven auto selection). nuclei output is JSONL — there
   is no `-json` flag.
2. `searchsploit <plugin name> <version>` / check the vendor advisory for a
   public PoC; attach it to the work unit's hints.
3. Valid credentials from Step 2 → log in (`/wp-admin/`, `/administrator/`,
   `/user/login`) and hand admin access to the exploitation crew (WP:
   plugin/theme editor or malicious plugin upload = RCE; Joomla: template
   edit; Drupal: PHP filter module).

**Final handoff:** emit the consolidated work-units array for the lead agent to
`dispatch`, one `findings.report` per verified issue (endpoint scope, HTTP
exchange in evidence, CVE/CWE classification), and `assets.mark` depth
`exploited` for anything you actually got code-exec or auth on. Exact payload
shapes: `references/rupu.md`.

## References

- `references/wordpress.md` — wpscan flags, enumeration matrix, xmlrpc brute detail, JSON schema.
- `references/joomla-drupal-generic.md` — joomscan, droopescan, cmsmap, CMSeeK in depth.
- `references/rupu.md` — work-unit, assets.mark, findings.report wiring and JSON shapes.
