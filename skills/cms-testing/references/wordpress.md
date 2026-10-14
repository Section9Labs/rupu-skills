# WordPress deep-dive: wpscan

## Install / update

```
gem install wpscan            # or: docker run -it --rm wpscanteam/wpscan
wpscan --update               # refresh the local fingerprint DB before every engagement
```

## API token

Vulnerability data comes from the WPScan/WPVulnDB API. **Without
`--api-token` the scan reports versions but NO vulnerabilities.** Free tier =
25 API requests/day (each plugin/theme/core lookup is one request — a large
plugin inventory burns it fast). Pass via `--api-token <token>` or
`~/.wpscan/scan.yml`:

```yaml
cli_options:
  api_token: "YOUR_TOKEN"
```

## Enumeration matrix (`--enumerate` / `-e`)

| value | meaning                              | notes |
|-------|--------------------------------------|-------|
| `vp`  | vulnerable plugins                   | default-ish; needs API token to mean anything |
| `ap`  | all plugins                          | pair with `--plugins-detection aggressive` for full coverage |
| `p`   | popular plugins                      | middle ground |
| `vt`  | vulnerable themes                    | |
| `at`  | all themes                           | |
| `t`   | popular themes                       | |
| `u`   | users (default: ids 1-10)            | `u1-50` for a wider range |
| `cb`  | config backups (wp-config.php.bak…)  | high-value: creds in cleartext |
| `dbe` | DB exports left in webroot           | |
| `tt`  | timthumb files                       | legacy RCE surface |
| `m`   | media IDs                            | can leak drafts/attachments |

Combine comma-separated: `-e ap,at,u,cb,dbe,tt`. `vp` and `ap` are mutually
exclusive (same for themes).

## Detection modes

- `--detection-mode passive|mixed|aggressive` — global default for everything.
- `--plugins-detection passive|mixed|aggressive`
  - `passive`: parse homepage/known pages HTML only. Quiet, misses inactive plugins.
  - `aggressive`: request `/wp-content/plugins/<slug>/` for every known slug
    (~100k requests). Finds plugins with no homepage footprint.
  - `mixed` (default): passive first, aggressive for the rest.
- `--plugins-version-detection aggressive` — fetch readme.txt/changelogs to pin
  exact versions (version precision = CVE precision; always use it when the
  API token is loaded).
- `--interesting-findings-detection`, `--wp-version-detection`,
  `--main-theme-detection` take the same three modes.

## User enumeration internals

wpscan tries, in order: author archives (`/?author=N` redirect leaks the
slug), REST API (`/wp-json/wp/v2/users`), oEmbed, RSS author tags, login error
message oracle. Users land in the JSON `users` object keyed by username.
Manual fallback if wpscan is blocked:

```
curl -s 'https://192.0.2.10/wp-json/wp/v2/users?per_page=100' | python3 -m json.tool
curl -sI 'https://192.0.2.10/?author=1'      # Location: /author/<username>/
```

## Password attacks

```
wpscan --url https://192.0.2.10 \
  --usernames admin,editor,users.txt \
  --passwords rockyou.txt \
  --password-attack xmlrpc-multicall \
  --max-threads 25 --throttle 0 \
  -f json -o brute.json
```

- `--usernames` accepts a comma list and/or file paths; `--passwords` a file
  or comma list. If you only pass `--passwords`, wpscan uses the users it
  enumerated earlier in the same run.
- `--password-attack` values:
  - `wp-login` — POST `/wp-login.php`. 1 request per guess. Works everywhere;
    most logged/WAF-visible; the only option when xmlrpc is disabled.
  - `xmlrpc` — `wp.getUsersBlogs` call per guess over `/xmlrpc.php`. Faster,
    different log signature.
  - `xmlrpc-multicall` — packs many guesses into one `system.multicall` XML
    body: **one HTTP request tests hundreds of passwords** (amplification).
    WordPress >= 4.4 limits multicall auth attempts; many security plugins
    block it — wpscan detects failure and you fall back to `xmlrpc` or
    `wp-login`.
- Verify xmlrpc is alive first: `POST /xmlrpc.php` body
  `<methodCall><methodName>system.listMethods</methodName></methodCall>` —
  a method list in the response means it's open.
- Success shows as `[SUCCESS]` lines; in JSON under
  `password_attack` / each user's `password` field.

## Evasion / plumbing

- `--random-user-agent` (`--rua`), `--user-agent 'Mozilla/5.0 ...'`
- `--stealthy` = `--random-user-agent --detection-mode passive --plugins-version-detection passive`
- `--throttle <ms>` between requests; `--request-timeout`, `--connect-timeout`
- `--proxy http://127.0.0.1:8080` (Burp), `--proxy-auth user:pass`
- `--cookie-string 'a=b; c=d'`, `--http-auth user:pass`
- `--disable-tls-checks` for self-signed/broken TLS
- `--force` to skip the "is this WordPress" check (WAF hides the tells)
- `--wp-content-dir`, `--wp-plugins-dir` for relocated installs

## JSON output schema (what parse_wpscan.py reads)

`-f json -o wpscan.json` (or `--output`). Top-level keys of interest:

```json
{
  "target_url": "https://192.0.2.10/",
  "effective_url": "https://192.0.2.10/",
  "interesting_findings": [ {"url": "...", "to_s": "...", "type": "...",
                              "references": {"url": ["..."]}} ],
  "version": {"number": "6.3.1", "status": "insecure", "confidence": 100,
              "vulnerabilities": [ {"title": "...", "fixed_in": "6.3.2",
                 "references": {"cve": ["2023-..."], "url": ["..."]}} ]},
  "main_theme": {"slug": "twentytwentythree", "version": {"number": "1.2"},
                 "vulnerabilities": [...]},
  "plugins": {"contact-form-7": {"slug": "contact-form-7",
      "version": {"number": "5.7.1", "confidence": 80},
      "outdated": true, "latest_version": "5.8",
      "vulnerabilities": [ {"title": "Contact Form 7 < 5.8 - XSS",
        "fixed_in": "5.8", "references": {"cve": ["2023-XXXXX"],
        "wpvulndb": ["..."], "url": ["..."]}} ]}},
  "themes": { "...same shape as plugins..." },
  "users": {"admin": {"id": 1, "confidence": 100,
            "confirmed_by": {"Author Id Brute Forcing": {...}}}},
  "config_backups": {"https://192.0.2.10/wp-config.php.bak": {...}},
  "db_exports": {},
  "password_attack": {"admin": {"password": "winter2024"}}
}
```

Note: `version` can be `null` if detection failed; plugin `version` can be
`null` too — treat missing versions as "verify manually".

## Post-access RCE paths (handoff hints for exploitation)

With admin creds: Appearance → Theme File Editor (edit `404.php`, add PHP),
or Plugins → Add New → Upload (zip with a PHP webshell + plugin header), or
`wp-cli`/xmlrpc `wp.uploadFile` where available. Metasploit:
`exploit/unix/webapp/wp_admin_shell_upload`.
