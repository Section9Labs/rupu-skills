# ffuf — full flag reference and recipes

ffuf fuzzes any part of an HTTP request where you place a keyword (default
`FUZZ`). Keywords go in the URL, headers, method, or body.

## Core flags

| Flag | Meaning |
|---|---|
| `-u <url>` | Target URL containing one or more keywords |
| `-w <file>[:KEYWORD]` | Wordlist; `:KEYWORD` names it for multi-wordlist runs |
| `-request <file>` | Raw HTTP request file (Burp export) as the template |
| `-request-proto https` | Protocol for `-request` mode |
| `-X <method>` | HTTP method (`-X POST`, `-X PUT`...) |
| `-d <data>` | Request body (keywords allowed) |
| `-H 'Name: value'` | Header; repeatable; keywords allowed (vhost fuzzing) |
| `-b 'k=v; k2=v2'` | Cookies |
| `-x http://127.0.0.1:8080` | Upstream proxy for ALL requests |
| `-replay-proxy http://127.0.0.1:8080` | Proxy only for MATCHED requests (Burp triage) |
| `-r` | Follow redirects |
| `-t <n>` | Threads (default 40) |
| `-rate <n>` | Requests per second cap |
| `-p 0.1` or `-p 0.1-2.0` | Delay (seconds, fixed or random range) |
| `-timeout <s>` | Per-request timeout (default 10) |
| `-maxtime <s>` / `-maxtime-job <s>` | Wall-clock caps total / per job |
| `-se` | Stop on spurious errors |
| `-sa` | Stop on all error cases |
| `-e .php,.bak` | Extensions appended to each FUZZ word (dots included) |
| `-ic` | Ignore wordlist comment lines |
| `-mode clusterbomb\|pitchfork\|sniper` | Multi-wordlist combination mode |

## Matchers and filters

Matchers select, filters drop; filters are applied to matched results.
**`-mc` default set is 200-299,301,302,307,401,403,405,500 — not "all".**

| Match | Filter | On |
|---|---|---|
| `-mc 200,301` or `-mc all` | `-fc 404,400` | status code |
| `-ms <bytes>` | `-fs 4242` or `-fs 4242,0` (comma + ranges `100-200`) | response size |
| `-mw <n>` | `-fw <n>` | word count |
| `-ml <n>` | `-fl <n>` | line count |
| `-mr 'regex'` | `-fr 'regex'` | body regex |
| `-mt '>100'` | `-ft '>100'` | response time ms |

Auto-calibration: `-ac` sends randomized probes (plain, with extension,
directory-style) and auto-creates `-fs`/`-fw`/`-fl` filters from the
responses. `-acc <string>` adds custom calibration payloads (repeatable).
`-acs <strategy>` picks the calibration strategy (`basic`, `advanced`).

Recommended discipline: `-mc all -ac`, then add explicit `-fc/-fs/-fr` as
you learn the target's error pages. Never trust the default match set to show
you 404-with-200 soft errors.

## Output

```
-o out.json -of json      # json is the default -of; also csv, ecsv, html, md, all
-of all -o base           # writes base.json/.html/.md/.csv...
-od <dir>                 # store full request/response per match
-s                        # silent (URLs only to stdout)
-v                        # verbose: full URL + redirect location inline
```

JSON structure: top-level object with `commandline`, `time`, `config`, and
`results` — each result has `url`, `status`, `length`, `words`, `lines`,
`redirectlocation`, `content-type`, `host`, and `input` (map of
keyword→payload). Parse `results[]`.

## Recipes

### Directory + file discovery with extensions

```
ffuf -u https://192.0.2.10/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -e .php,.html,.txt,.bak,.old -ac -mc all -fc 404 \
     -t 60 -o ffuf-root.json -of json
```

### Recursion (URL must END in FUZZ)

```
ffuf -u https://192.0.2.10/FUZZ -w raft-small-directories.txt \
     -recursion -recursion-depth 2 -ac -o ffuf-rec.json -of json
```

Each hit that looks like a directory spawns a new job at `hit/FUZZ`.
`-recursion-strategy greedy` recurses on all matches, `default` only on
redirects.

### Virtual hosts

```
ffuf -u https://192.0.2.10/ -H 'Host: FUZZ.example.com' \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -mc all -fs 10918 -o ffuf-vhost.json -of json
```

Learn the wildcard size first: run 50 words unfiltered, note the constant
`length`, filter it with `-fs`. If size varies (reflected hostname), use
`-fw`/`-fl` or `-fr`. Works on HTTPS even without SNI match (`-k` equivalent
is built in; ffuf skips TLS verification by default).

### Multi-wordlist (deep path product)

```
ffuf -u https://192.0.2.10/DIR/FILE \
     -w raft-medium-directories.txt:DIR \
     -w raft-medium-files.txt:FILE \
     -mode clusterbomb -ac -o ffuf-deep.json -of json
```

clusterbomb = cartesian product (default); pitchfork = line-paired lists;
sniper = one list, one position at a time across multiple marked positions.

### POST body / login fuzzing

```
ffuf -u https://192.0.2.10/login -X POST \
     -d 'username=admin&password=FUZZ' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -w passwords.txt -mc all -fr 'Invalid credentials'
```

### Backup-file sweep of known files

```
ffuf -u https://192.0.2.10/WORDEXT \
     -w found-files.txt:WORD -w backup-suffixes.txt:EXT \
     -mode clusterbomb -ac -mc all -fc 404
```

where backup-suffixes.txt holds `.bak`, `.old`, `~`, `.swp`, `.orig`, `.save`,
`.zip`, `.tar.gz`, `.1`.

### Raw-request template (authenticated API fuzzing)

Save a Burp request to `req.txt`, replace the path segment with `FUZZ`:

```
ffuf -request req.txt -request-proto https -w api-endpoints.txt -ac \
     -o ffuf-api.json -of json
```

## Reading results

- `301/302` with `Location` ending in `/` → real directory; recurse into it.
- `401/403` → protected content exists; keep it, mark it, try bypasses later.
- `200` identical size across many hits → soft-404 you failed to filter; add
  `-fs` and rerun.
- `405` on an API path → endpoint exists, wrong method; retry with
  `-X POST/PUT`.
- `-mt '>500'` time matching can expose endpoints doing real work (DB calls)
  behind generic responses.
