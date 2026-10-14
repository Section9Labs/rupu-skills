---
name: nikto-scan
description: Fast baseline web-server misconfiguration and known-issue sweep with nikto plus wapiti as the active-DAST companion — dangerous files, outdated server software, default files, server misconfig, and active injection checks. Use early against every live web host, right after httpx/host discovery, before deeper manual testing.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Nikto Baseline Scan (+ wapiti active DAST)

Early automated sweep of each live web host: nikto for dangerous/default
files, outdated server software, and misconfig signatures; wapiti for active
injection testing (SQLi/XSS/exec/file) that nikto's signature checks don't
cover. Both are noisy, baseline tools — their output is a **triage queue**,
not a findings list. Every parse step ends in rupu output (shapes in
`references/rupu.md`).

## Pipeline

```
live hosts (httpx -json) -> nikto per host -> parse_nikto.py (work units)
                         -> wapiti per host -> parse report
                         -> manual confirmation -> findings.report / assets.mark
```

## Step 1 — Input: live web hosts

Feed from host discovery (httpx `-json` emits JSON Lines; the `url` field per
line is your target). One nikto run per scheme:host:port.

## Step 2 — nikto sweep

**Capitalization matters in nikto flags.** Full tuning map, evasion codes and
output details in `references/nikto.md`.

```
nikto -h https://192.0.2.10 -Format json -output nikto-192.0.2.10.json \
      -Tuning 123489abc -maxtime 45m -useragent 'Mozilla/5.0 (X11; Linux x86_64)'
```

- `-h`/`-host` target (URL, host, IP, or a file of targets); `-port 8443` for
  nonstandard ports (there is **no `-p`**); `-ssl` to force TLS on odd ports.
- `-Tuning` selects test classes: `1` interesting files, `2` misconfig,
  `3` info disclosure, `4` injection (XSS/script/HTML), `5` remote file
  retrieval (inside web root), `6` DoS, `7` remote file retrieval (server
  wide), `8` command execution, `9` SQLi, `0` file upload, `a` auth bypass,
  `b` software identification, `c` remote source inclusion / dir traversal.
  Prefix `x` to invert: `-Tuning x6` = everything except DoS (the usual
  default choice).
- `-Format json|xml|csv|txt|htm` + `-output <file>` (or just give the file an
  extension and nikto picks the format; it's `htm`, not `html`).
- `-id user:pass` for HTTP basic auth; `-vhost example.com` to set the Host
  header when scanning by IP; `-useproxy http://127.0.0.1:8080` to route
  through Burp.
- `-evasion 1-8,A,B` — libwhisker IDS evasion encodings (random URI encoding,
  self-ref dirs, fake params, tab separators…); stack digits: `-evasion 17`.
- `-mutate 1-6` + `-mutate-options` — guessing modes (file brute, user
  enumeration via Apache ~user, subdomain guess). Expensive; use selectively.
- `-Plugins <list>` to pin plugins (`-list-plugins` to see them);
  `-Display V` verbose, `-Display 1234EP` to control what prints;
  `-maxtime 30m`/`-until` to bound runtime; `-timeout`, `-Pause` pacing.
- `-nointeractive` for unattended fleet runs; `-ask no` to skip update prompts.

Mass form: `nikto -h hosts.txt -Format json -output nikto-all.json` (hosts.txt
one target per line, `host:port` accepted).

Reading output: each line/item is a signature hit with the path, HTTP method,
message, and an ID (`OSVDB-XXXX` historically; newer DBs use nikto test IDs
and reference URLs/CVEs). Treat `OSVDB` numbers as search keys, not proof.
Classic high-value hits: `/.git/HEAD` readable, backup files
(`/index.php.bak`), `/server-status`, outdated Apache/nginx/PHP banners,
PUT/DELETE allowed, directory indexing, default consoles (`/manager/html`,
`/phpmyadmin/`).

**Parse/handoff:**

```
python3 scripts/parse_nikto.py nikto-192.0.2.10.json \
  --out nikto-merged.json --work-units nikto-units.json --findings nikto-findings.json
```

The script accepts nikto JSON (object, array, or concatenated objects) and
CSV, normalizes each item to `{url, method, msg, id, references}`, dedupes,
and emits: merged JSON, a work-units array (one unit per finding worth manual
confirmation — hand to the `work-units` skill), and draft `findings.report`
payloads with heuristic severity + CWE/OWASP tags. Mark each scanned host
`assets.mark` kind `web:site` depth `tested`, and each flagged path as
`web:route` depth `tested` (per the `coverage-assets` skill).

## Step 3 — wapiti active DAST

wapiti crawls and actively injects — it finds what nikto's static signatures
can't. Flag depth in `references/wapiti.md`.

```
wapiti -u https://192.0.2.10/ \
  -m "sql,xss,exec,file,ssrf,xxe,crlf,redirect,upload,csrf" \
  --scope folder -d 5 --max-links-per-page 100 \
  -f json -o wapiti-192.0.2.10.json --flush-session
```

- `-m` module list (comma; prefix `-` to remove from defaults:
  `-m "common,-brute_login_form"`); `--list-modules` to enumerate.
- `--scope url|page|folder|domain|punk` — crawl boundary (default `folder`).
- Auth: `-a user%password --auth-method basic|digest|ntlm` for HTTP auth;
  form login via `--form-url`/`--form-data` (or legacy post-login
  `-c cookies.json` / `-H 'Cookie: session=...'`).
- `-f json|html|txt|xml|csv -o <path>`; JSON has `vulnerabilities` keyed by
  category, each with `path`, `method`, `parameter`, `info`,
  `http_request`, `curl_command` — the `http_request` field is your evidence
  exchange for `findings.report`.
- `-p http://127.0.0.1:8080` proxy; `--verify-ssl 0`; `--timeout`, `--tasks`
  concurrency.

Complementarity: nikto = known files/banners/misconfig (breadth, no
injection depth); wapiti = parameter-level injection on crawled routes
(depth, no known-file DB). Run both; where wapiti confirms an injection on a
route nikto flagged, that's a ready-made confirmed finding.

## Step 4 — Triage and confirm

Both tools false-positive heavily. For each work unit:
1. Replay the request (curl / Burp Repeater) and verify the behavior —
   does `/server-status` actually render? does the `.bak` download? does the
   payload execute?
2. Capture the exact HTTP request/response pair for evidence.
3. Confirmed → `findings.report` via the `finding-report` skill: scope
   `endpoint` (scope `host` only for host-wide issues like an outdated server
   version), severity per impact, OWASP/CWE classification, HTTP exchange in
   evidence. Not confirmed → close the unit with a note; keep the asset marks.
4. Interesting-but-deeper items (writable PUT, upload endpoints, injectable
   params) → new work units for the exploitation/injection skills.

## References

- `references/nikto.md` — tuning map, evasion codes, mutate modes, output formats.
- `references/wapiti.md` — modules, auth, JSON report schema.
- `references/rupu.md` — work-unit / assets.mark / findings.report shapes.
