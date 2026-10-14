# Joomla, Drupal, and generic CMS scanners

## joomscan (OWASP, Perl)

```
perl joomscan.pl --url https://192.0.2.20            # if run from the repo
joomscan --url https://192.0.2.20 --enumerate-components
```

Flags:
- `-u` / `--url <target>` — target base URL.
- `-ec` / `--enumerate-components` — brute component paths
  (`/components/com_*`, `/index.php?option=com_*`) and map each hit against
  its exploit-db references.
- `--cookie "a=b;"`, `--user-agent`, `--random-agent`
- `--proxy http://127.0.0.1:8080`
- `--timeout <sec>`

Output: colored text to stdout + an HTML/text report in
`reports/<target>/`. **No JSON.** Grep-worthy markers:

```
[+] Detecting Joomla Version        -> "Joomla 3.9.x"
[++] Target vulnerable to ...       -> core CVE hit, verify and report
[+] Checking apache info/status files
[+] admin finder                    -> usually /administrator/
[+] Checking robots.txt existing
[+] Finding common backup files name    -> configuration.php.bak etc. (jackpot)
[+] Finding common log files name
[++] Enumeration component (com_xxx)    -> component + exploit-db URLs
```

Joomla version tells (manual confirmation):
- `/administrator/manifests/files/joomla.xml` — exact `<version>` (often readable)
- `/language/en-GB/en-GB.xml` — version in older installs
- `/README.txt` — major.minor

High-value Joomla core CVEs to map against the version: CVE-2015-8562
(3.x <= 3.4.5 UA-header object-injection RCE), CVE-2016-8870/8869 (3.4.4-3.6.3
account creation/priv-esc), CVE-2017-8917 (3.7.0 com_fields SQLi),
CVE-2023-23752 (4.0.0-4.2.7 unauth API info leak →
`/api/index.php/v1/config/application?public=true` leaks DB creds).

## droopescan (Python)

```
pip install droopescan
droopescan scan drupal -u https://192.0.2.30 -t 32 -e a --output json
droopescan scan joomla -u https://192.0.2.20 --output json
droopescan scan wordpress|silverstripe|moodle -u ...
droopescan scan drupal -U targets.txt          # mass scan from a file
```

Flags:
- `scan <cms>` — drupal, joomla, wordpress, silverstripe, moodle.
- `-u <url>` single target, `-U <file>` list.
- `-t <n>` threads (default 4; 32 is fine against most targets).
- `-e p|t|v|i|a` — plugins/modules, themes, version, interesting urls, all.
- `-n <number>` — how many plugin/theme names to try (default "number most
  popular"; raise to 100000 for exhaustive).
- `--method not_found|forbidden|ok` — force the detection heuristic.
- `--output json` / `--output standard`; `--debug-requests` to watch traffic.

JSON shape:

```json
{"plugins": {"finished": true, "findings": [
    {"name": "views", "url": "https://192.0.2.30/sites/all/modules/views/"}]},
 "themes": {"finished": true, "findings": []},
 "version": {"finished": true, "findings": ["7.59", "7.60"]},
 "interesting urls": {"finished": true, "findings": [
    {"url": "https://192.0.2.30/CHANGELOG.txt", "description": "Default changelog file."}]},
 "host": "https://192.0.2.30/", "cms_name": "drupal"}
```

`version.findings` is a *candidate list* — droopescan hashes static files and
lists every version consistent with the hashes; the real version is one of
them. If `CHANGELOG.txt` is in interesting urls, fetch it for the exact number.

Drupal CVE map: CVE-2014-3704 (Drupalgeddon, 7.x < 7.32, pre-auth SQLi→RCE),
CVE-2018-7600 (Drupalgeddon2, <7.58 / 8.x<8.3.9/8.4.6/8.5.1, unauth RCE via
`#post_render`), CVE-2018-7602 (follow-up, needs some auth), CVE-2019-6340
(8.x REST module RCE when PATCH/POST enabled). nuclei has templates for all —
confirm with `nuclei -u <target> -tags drupal -jsonl`.

## cmsmap (dionach/CMSmap fork lineage)

Fork drift is real: **run `cmsmap --help` and trust it over this page.**

```
cmsmap https://192.0.2.40                 # auto-detect WP/Joomla/Drupal, run checks
cmsmap https://192.0.2.40 -f W -F         # force WordPress, full plugin list
cmsmap https://192.0.2.40 -f J --noedb -o cmsmap.txt
cmsmap https://192.0.2.40 -f W -u users.txt -p rockyou.txt   # built-in brute
cmsmap -i targets.txt -o out.txt          # multiple targets
```

- `-f W|J|D|M` — force CMS type (WordPress/Joomla/Drupal/Moodle).
- `-F` / `--fullscan` — full plugin DB, not just the popular subset.
- `-F` scans are loud; combine with `-a <user-agent>` and `-t <threads>`.
- `--noedb` — skip local Exploit-DB (searchsploit) correlation.
- `-d` — disable "dynamic" checks (brute of default files).
- `-u <user|file> -p <pass|file>` — credential attack against the detected
  CMS login (uses xmlrpc on WP where possible).
- `-k <file>` hashcat-crack dumped hashes; `-w <file>` wordlist for that.
- `-s` force SSL/https; `-P/-x` proxy options vary by fork — check `--help`.
- Output `-o <file>` is plain text.

Use cmsmap when you want one tool to detect + check + brute in a single pass,
or as a second opinion. Its plugin DBs are shallower than wpscan/droopescan.

## CMSeeK (cmseek)

```
cmseek -u https://192.0.2.40 --follow-redirect --random-agent
cmseek -l targets.txt --batch           # list mode, no interactive prompts
cmseek --update                         # update detection DB
```

- Detects 180+ CMSes via headers, meta generator, path probes, favicon hashes.
- For WordPress / Joomla / Drupal / Magento it offers a **deep scan**:
  version, users (WP via wp-json + author archives), plugins, themes, backup
  files. In `--batch` mode deep scan runs without prompting.
- Results persist to `Result/<hostname>/cms.json` — machine readable, e.g.:

```json
{"cms_id": "wp", "cms_name": "WordPress", "cms_url": "https://wordpress.org",
 "wp_version": "6.2.2", "wp_users": "admin,editor",
 "wp_plugins": "contact-form-7 Version 5.7,woocommerce Version 7.8",
 "url": "https://192.0.2.40", "last_scanned": "..."}
```

Parse that file instead of scraping the TUI output.

## Choosing the tool

| Situation | Tool |
|---|---|
| Unknown/exotic CMS | cmseek (broadest detection) |
| Confirmed WordPress | wpscan (deepest DB, API-backed CVEs) |
| Confirmed Joomla | joomscan + droopescan joomla (version cross-check) |
| Confirmed Drupal | droopescan drupal + nuclei drupal tags |
| One-shot detect+check+brute | cmsmap |
| WAF blocks the dedicated scanner's signature | the other tool, `--random-agent`, proxy through Burp and mutate |

## Handoff

For every component/version with a mapped CVE: one work unit (`hints` carry
cve, component, version, poc URL). Record `/administrator/`, `/user/login`,
`/wp-login.php`, `/xmlrpc.php` as `web:route` assets. Report verified issues
with `findings.report` — shapes in `rupu.md`.
