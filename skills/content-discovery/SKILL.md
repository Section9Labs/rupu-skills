---
name: content-discovery
description: Wordlist-driven discovery of hidden directories, files, and virtual hosts on web targets using ffuf, feroxbuster, dirsearch, and gobuster — finds admin panels, backups, config files, API paths, dev endpoints, and name-based vhosts that crawling misses. Use after crawling to expand the route map before vulnerability testing.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: web-application
  phase: discovery
---

# Content Discovery

Brute-force the parts of a web application that crawling cannot see: unlinked
directories, forgotten files, backups, admin interfaces, API versions, and
name-based virtual hosts. Input is a live base URL (and ideally a tech
fingerprint from recon). Output is an expanded route map handed to the vuln
skills, recorded as rupu assets and work units — see `references/rupu.md` for
the exact wiring; every parse step below ends in a rupu-ingestible artifact.

## Tool selection

| Situation | Tool |
|---|---|
| General fuzzing, vhosts, headers, POST bodies, multi-wordlist | **ffuf** |
| Deep recursive sweep, link/word extraction, backup hunting | **feroxbuster** |
| CMS-aware brute force with `%EXT%` wordlists, smart defaults | **dirsearch** |
| Quick dir pass, vhost/dns modes, minimal deps | **gobuster** |

Run at least two tools per target (one flat fuzzer + one recursive) and merge:
different default wordlists and 404-handling catch different things.

## Step 0 — Baseline the target

Before any wordlist run, understand how the target answers garbage so you can
filter soft-404s:

```
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' https://192.0.2.10/zzqq$(date +%s)
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' https://192.0.2.10/zzqq$(date +%s).php
```

- Clean 404 → default match sets work as-is.
- 200/302 with a fixed-size "not found" page → filter on size (`-fs`), words
  (`-fw`), or a regex on the body (`-fr "Page Not Found"`), or lean on
  auto-calibration (`ffuf -ac`, `feroxbuster --smart`).
- Different behavior per extension is common — baseline each extension you fuzz.

Full soft-404 playbook: `references/wordlists-and-calibration.md`.

## Step 1 — ffuf: directories, files, vhosts

Primary flat fuzzer. Full flag reference: `references/ffuf.md`.

```
ffuf -u https://192.0.2.10/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -e .php,.html,.txt,.bak \
     -ac -mc all -fc 404 \
     -t 60 -timeout 10 \
     -o ffuf-dirs.json -of json
```

Key points:

- `-mc` has a built-in default match set (200-299,301,302,307,401,403,405,500).
  Use `-mc all` and filter explicitly (`-fc 404 -fs <soft404size>`) so you
  control what is dropped. `-ac` auto-calibrates filters from random probes;
  `-acc <string>` adds custom calibration strings.
- `-e` appends extensions to every word — pick them from the tech stack
  (httpx `-td` / webanalyze output), see the extension table in
  `references/wordlists-and-calibration.md`.
- Recursion: URL must end in `FUZZ` — `-recursion -recursion-depth 2`.
- Authenticated discovery: `-H 'Cookie: session=abc123' -H 'Authorization: Bearer eyJ...'`
  — rerun the same wordlists post-login; the diff is the post-auth surface.
- `-replay-proxy http://127.0.0.1:8080` replays only matches through Burp.
- Rate control when needed: `-rate 100 -t 40` (requests/sec, threads).

**VHOST fuzzing** (name-based virtual hosts on the same IP):

```
ffuf -u https://192.0.2.10/ \
     -H 'Host: FUZZ.example.com' \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -mc all -o ffuf-vhost.json -of json
```

First run without filters against ~50 words to learn the wildcard response
size, then add `-fs <that size>` (or `-ac`). Every surviving hit is a distinct
virtual host — a new `web:site` asset and a fresh crawl + discovery target.

**Parameter / POST-body fuzzing** (brief — deep param work belongs to the
`parameter-discovery` skill): `ffuf -u 'https://192.0.2.10/page?FUZZ=1' -fs <base>`
or `-X POST -d 'FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded'`.
Multi-wordlist with keywords: `-w dirs.txt:DIR -w files.txt:FILE -u https://192.0.2.10/DIR/FILE`
(clusterbomb default; `-mode pitchfork` for paired lists).

## Step 2 — feroxbuster: recursive sweep

Recursive by default; best single command for depth coverage. Details:
`references/recursive-and-modes.md`.

```
feroxbuster -u https://192.0.2.10 \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,html,txt -d 3 -t 50 -k \
    --smart -C 404 \
    --json -o ferox.ndjson
```

- `--smart` = `--auto-tune` (back off on errors/soft-404 floods) +
  `--collect-words` (build a target-specific wordlist from responses) +
  `--collect-backups` (request `.bak`, `~`, `.swp`, etc. variants of every
  found file). `--thorough` adds `--collect-extensions`. These collectors are
  the main reason to run ferox even after ffuf.
- Filters are deny-lists: `-C 404,503` status, `-S <bytes>` size, `-W <n>`
  words, `-N <n>` lines, `--filter-regex 'not found'`; `-s 200,301,401,403`
  is an allow-list of statuses.
- `-r` follows redirects (off by default — usually leave off so you see the
  301s that reveal directories), `-H 'Cookie: ...'` or `-b 'session=abc'` for
  auth, `--auto-bail` abandons dead directories.
- `--json` output is NDJSON — keep `-o ferox.ndjson`; interrupted scans resume
  with `--resume-from ferox-<state>.state`.

## Step 3 — dirsearch and gobuster: second opinions and vhost/dns modes

```
dirsearch -u https://192.0.2.10 \
    -e php,asp,aspx,jsp,html,js \
    -x 404 --exclude-sizes 1234B \
    -r --max-recursion-depth 2 --random-agent -t 50 \
    --format json -o dirsearch.json
```

dirsearch's bundled wordlist uses `%EXT%` markers that get substituted by `-e`
values (`-f` forces appending extensions to every word even without markers).
`--deep-recursive` recurses into every path segment of found URLs. Auth via
`-H 'Authorization: ...'` / `--cookie 'session=abc'`.

```
gobuster dir -u https://192.0.2.10 -w common.txt -x php,txt -t 50 -b 404 -k \
    -a 'Mozilla/5.0' -o gobuster-dir.txt
gobuster vhost -u https://192.0.2.10 -w subdomains-top1million-5000.txt \
    --append-domain --domain example.com -o gobuster-vhost.txt
gobuster dns -do example.com -w subdomains-top1million-20000.txt -o gobuster-dns.txt
```

gobuster has **no structured output** — `-o` is plain text; the parser script
handles it. `dir` mode: `-s`/`-b` match/blacklist statuses (mutually
exclusive), `-r` follow redirects, `-H`/`-c` headers/cookies, `--wildcard`
continues despite wildcard responses. `vhost` needs `--append-domain` to send
`word.example.com` in the Host header. `dns` uses `-do` for the domain (not
`-d`). `gobuster fuzz -u https://192.0.2.10/FUZZ?x=1 -w list.txt` for arbitrary
keyword placement. Full mode notes: `references/recursive-and-modes.md`.

## Step 4 — Parse, merge, record (rupu handoff)

Normalize and dedupe all outputs with the bundled script:

```
python3 scripts/parse_discovery.py \
    --ffuf ffuf-dirs.json --ffuf ffuf-vhost.json \
    --ferox ferox.ndjson \
    --dirsearch dirsearch.json \
    --gobuster gobuster-dir.txt --base-url https://192.0.2.10 \
    -o merged.json \
    --work-units units.json \
    --assets assets.json
```

It emits:

1. `merged.json` — deduped `{url,status,length,words,lines,redirect,source,category}`
   records.
2. `units.json` — a clean JSON **array** of work units (first char `[`), one
   per interesting endpoint with a `hints.category` guess
   (admin/upload/api/backup/config/other). Hand this to the `work-units` skill
   for normalization, then a rupu workflow `for_each:` or a lead agent
   `dispatch` fans out over it.
3. `assets.json` — one `assets.mark` payload per discovered route (`web:route`,
   depth `mapped`) and per new vhost (`web:site`). Record them via the
   `coverage-assets` skill. Exact JSON shapes: `references/rupu.md`.

## Step 5 — Chain to vuln testing

Route categories map to next skills:

- **admin** (`/admin`, `/manager`, `/console`, `/wp-admin`, `/phpmyadmin`) →
  auth-testing / default-credentials skill; 401/403 hits are still assets —
  try 403-bypass tricks (trailing `/.`, `%2e`, `X-Forwarded-For`, verb change).
- **upload** (`/upload`, `/files`, `/import`) → file-upload vuln skill.
- **api** (`/api`, `/v1`, `/graphql`, `/swagger.json`, `/openapi.json`) →
  API-testing skill; swagger/openapi specs enumerate the whole surface for free.
- **backup/config** (`.bak`, `.old`, `.zip`, `.sql`, `.env`, `web.config`,
  `.git/`) → fetch immediately, extract secrets; a readable `.git/` →
  source-recovery; report via the `finding-report` skill.
- **new vhosts** → full recon + crawl + this skill again, per vhost.
- Everything else → merge into the route map feeding injection/XSS/IDOR skills.

Anything already verified as a vulnerability during discovery (exposed `.env`,
directory listing with secrets, open admin panel) gets a `findings.report`
call per `references/rupu.md` — scope `endpoint`, the HTTP exchange in
evidence, and a WSTG/CWE classification — written up via the `finding-report`
skill. Mark exploited routes at depth `exploited`, fuzzed-but-clean ones at
`tested`.
