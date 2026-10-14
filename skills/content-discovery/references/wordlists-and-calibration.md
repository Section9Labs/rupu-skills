# Wordlists, extension tuning, and beating soft-404s

## SecLists paths (typical install: /usr/share/seclists)

### Directories and files

| List | Use |
|---|---|
| `Discovery/Web-Content/common.txt` | Fast first pass (~4.7k entries) |
| `Discovery/Web-Content/raft-small-directories.txt` | Quick dir pass (~20k) |
| `Discovery/Web-Content/raft-medium-directories.txt` | Standard dir pass (~30k) |
| `Discovery/Web-Content/raft-large-directories.txt` | Deep dir pass (~62k) |
| `Discovery/Web-Content/raft-medium-files.txt` | File names (pair with dirs) |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | Classic big list (~220k) |
| `Discovery/Web-Content/directory-list-2.3-small.txt` | ~87k |
| `Discovery/Web-Content/quickhits.txt` | High-value paths (.git, .env, backups) — ALWAYS run this |
| `Discovery/Web-Content/api/api-endpoints.txt`, `api/objects.txt` | API path fuzzing |
| `Discovery/Web-Content/swagger.txt` | API spec locations |
| `Discovery/Web-Content/CMS/` | wordpress.fuzz.txt, drupal.txt, joomla.txt, sharepoint.txt... |
| `Discovery/Web-Content/URLs/urls-wordpress-*.txt` | CMS deep lists |
| `Discovery/Web-Content/Common-DB-Backups.txt` | dump.sql, backup.sql variants |
| `Discovery/Web-Content/web-extensions.txt` | Extension list for `-e` loops |
| `Discovery/Web-Content/burp-parameter-names.txt` | Param fuzzing (hand to parameter-discovery) |

### VHOST / DNS

| List | Use |
|---|---|
| `Discovery/DNS/subdomains-top1million-5000.txt` | Quick vhost pass |
| `Discovery/DNS/subdomains-top1million-20000.txt` | Standard |
| `Discovery/DNS/subdomains-top1million-110000.txt` | Deep |
| `Discovery/DNS/bitquark-subdomains-top100000.txt` | Alternative deep |
| `Discovery/DNS/namelist.txt` | Internal-style hostnames (dev, staging, intranet) |

## Extension tuning

Pick extensions from the detected stack (httpx `-td`, webanalyze, headers,
cookies like `PHPSESSID`/`JSESSIONID`, 404 page style):

| Stack signal | Extensions |
|---|---|
| PHP (X-Powered-By: PHP, PHPSESSID) | `php,php3,php5,phtml,inc` |
| ASP.NET (ASPXAUTH, IIS) | `asp,aspx,ashx,asmx,config` |
| Java (JSESSIONID, Tomcat/Jetty) | `jsp,jspx,do,action` |
| Node/Go/Python APIs | usually extensionless — fuzz paths, add `json` |
| Any | always add `txt,html,bak,old,zip,log,sql,xml,json` on the quickhits/file pass |

Backup/leftover suffixes worth a dedicated pass against FOUND files:
`.bak .old .orig .save .swp .swo ~ .1 .2 .copy .tmp .zip .tar.gz .rar .7z`
and prefix variants `Copy of <name>`, `<name>.YYYY-MM-DD`. feroxbuster
`--collect-backups` automates this.

High-value standalone targets (quickhits covers most):
`.env .git/HEAD .git/config .svn/entries .DS_Store web.config .htaccess
composer.json package.json config.php.bak settings.py.orig wp-config.php.bak
backup.sql dump.sql database.sql .idea/workspace.xml phpinfo.php server-status
crossdomain.xml sitemap.xml robots.txt`

## Soft-404 / wildcard handling

A soft-404 is a 200/302 response for nonexistent paths. Detect it by
requesting 2-3 random paths (vary extension and trailing slash) and comparing
status + size + words.

Strategies, in order of preference:

1. **Auto-calibration**: ffuf `-ac` (add `-acc <known-404-marker>`),
   feroxbuster `--smart` / `--filter-similar-to https://192.0.2.10/zzqq404`.
2. **Size filter**: constant-size error page → ffuf `-fs 4242`, ferox
   `-S 4242`, dirsearch `--exclude-sizes 4242B`, gobuster `--exclude-length 4242`.
3. **Word/line filter**: size varies (reflected path) but words/lines don't →
   `-fw` / `-W` / word-count filters.
4. **Regex filter**: unique error string → ffuf `-fr 'Oops.*not found'`,
   ferox `--filter-regex`, dirsearch `--exclude-texts`.
5. **Redirect pattern**: everything 302s to `/login` → treat 302-to-login as
   the baseline and match only other statuses/locations; ALSO note that
   302-to-login paths behind auth are real routes — rerun with a session
   cookie.

For vhost fuzzing the "wildcard" is the default server block: measure its size
with a nonsense Host header first, filter with `-fs` / `--exclude-length`.
If the default response reflects the hostname (variable size), filter on
words/lines instead.

Per-extension baselines: IIS and some frameworks return different error pages
for `.aspx` vs plain paths — calibrate each extension (ffuf `-ac` handles this
by probing with extensions).

## Pacing and reliability

- Start `-t 40-60`; drop threads and add `-rate`/`--rate-limit`/`--delay` if
  you see rising 429/503 or timeouts — ferox `--auto-tune` and ffuf `-sa/-se`
  help detect degradation.
- WAF tells: sudden uniform 403s, `Server: cloudflare` challenge pages,
  TCP resets. Counter with lower rate, `--random-agent`/`-a` real UA,
  header spoofing (`-H 'X-Forwarded-For: 198.51.100.7'`), and smaller
  targeted lists instead of raft-large.
- Big lists × extensions multiply: raft-large (62k) × 5 ext = 372k requests.
  Budget accordingly; run dirs without extensions first, files-with-ext second.
