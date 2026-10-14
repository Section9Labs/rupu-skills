# feroxbuster, dirsearch, gobuster — recursive scanning and alternate modes

## feroxbuster

Recursive content discovery written in Rust. Recursion is ON by default:
every discovered directory is queued as a new scan up to `-d` (default 4).

### Core

```
feroxbuster -u https://192.0.2.10 \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,html,txt -d 3 -t 50 -k --json -o ferox.ndjson
```

| Flag | Meaning |
|---|---|
| `-u <url>` / `--stdin` | Target / read targets from stdin |
| `-w <file>` | Wordlist |
| `-x php,txt` | Extensions (no dots) |
| `-d <n>` | Max recursion depth (0 = infinite) |
| `-n` | Disable recursion entirely |
| `-t <n>` | Threads per scan; `--scan-limit <n>` caps concurrent directory scans (prefer the long spelling) |
| `--rate-limit <n>` | Requests/sec per directory |
| `-r` | Follow redirects |
| `-k` | Accept invalid TLS certs |
| `-H 'Name: value'` | Header (repeatable) |
| `-b 'k=v'` | Cookie |
| `-a <ua>` / `-A` | User-agent / random UA |
| `-m GET,POST` | Methods to try |
| `--dont-scan <url/regex>` | Deny-list for recursion |
| `-o <file>` | Output file |
| `--json` | NDJSON output (one JSON object per line) — pair with `-o` |
| `--resume-from <state>` | Resume interrupted scan from the auto-saved state file |
| `--burp` | Composite: proxy 127.0.0.1:8080 + insecure |

### Filters (deny) and matchers (allow)

| Flag | Effect |
|---|---|
| `-C 404,500` | Filter OUT these status codes |
| `-s 200,301,401,403` | Only SHOW these status codes |
| `-S <bytes>` | Filter out responses of this size (repeatable) |
| `-W <n>` / `-N <n>` | Filter out by word / line count |
| `--filter-regex 'pattern'` | Filter out bodies matching regex |
| `--filter-similar-to <url>` | Filter pages similar to a known 404 page |

### Smart composites and collectors

- `--auto-tune` — slow down when error/soft-404 rates spike.
- `--auto-bail` — abandon a directory scan that is clearly misbehaving.
- `--collect-words` — harvest words from responses into a dynamic wordlist
  used for the current scan (finds target-specific names).
- `--collect-backups` — for every found file, also request backup variants
  (`.bak`, `.old`, `~`, `.swp`, etc.).
- `--collect-extensions` — learn extensions seen in links and add them.
- `--smart` = auto-tune + collect-words + collect-backups.
- `--thorough` = smart + collect-extensions.

### Output parsing

NDJSON lines with `"type"` of `response`, `statistics`, or `error`. Keep only
`type == "response"`; fields: `url`, `status`, `content_length`, `word_count`,
`line_count`, `headers` (incl. `location` for redirects), `path`, `method`.

## dirsearch

Python brute forcer with a curated default wordlist using `%EXT%` markers.

```
dirsearch -u https://192.0.2.10 \
    -e php,asp,aspx,jsp,html,js \
    -x 404,500 --exclude-sizes 0B,1234B \
    -r --max-recursion-depth 2 \
    -t 50 --random-agent \
    --format json -o dirsearch.json
```

| Flag | Meaning |
|---|---|
| `-u <url>` / `-l <file>` | Target / target list |
| `-w <file>` | Custom wordlist(s), comma-separated |
| `-e php,js` | Extensions substituted into `%EXT%` markers |
| `-f` | Force: append each extension to EVERY word (even without `%EXT%`) |
| `-x 404` / `-i 200,301` | Exclude / include-only status codes |
| `--exclude-sizes 1234B` / `--exclude-texts 'Not found'` / `--exclude-regex` | Soft-404 filters |
| `-r` | Recursive; `--max-recursion-depth N` (use the long form) |
| `--deep-recursive` | Recurse into every path segment (`/a/b/` → scan `/a/` too) |
| `--force-recursive` | Recurse into every found path, not just directories |
| `-t <n>` | Threads |
| `--delay <s>` / `--max-rate <n>` | Pacing |
| `-H 'Name: value'` / `--cookie 'k=v'` / `--auth user:pass --auth-type basic` | Auth |
| `--random-agent` / `--user-agent` | UA control |
| `--proxy http://127.0.0.1:8080` | Proxy |
| `--crawl` | Extract paths from responses and test them |
| `--format json\|csv\|xml -o out.json` | Structured output |
| `--subdirs admin/,api/` | Prefix scan under given subdirectories |

JSON output: newer versions emit `{"info": {...}, "results": [{"url", "status",
"content-length", "content-type", "redirect"}]}`; older versions key results by
target URL with per-entry `path`. The bundled parser handles both.

## gobuster

Fast Go brute forcer, four relevant modes. **Plain-text output only** — parse
the text (bundled script does).

### dir mode

```
gobuster dir -u https://192.0.2.10 -w common.txt \
    -x php,txt,bak -t 50 -b 404 -k -r \
    -a 'Mozilla/5.0' -H 'X-Custom: 1' -c 'session=abc' \
    -o gobuster-dir.txt
```

- `-s 200,301,401,403` match statuses OR `-b 404,500` blacklist (not both;
  `-b` must be explicitly emptied `-b ''` if you set `-s`).
- `-x` extensions, `-r` follow redirects, `-k` skip TLS verify, `-e` print
  expanded (full) URLs, `--wildcard` keep going despite wildcard detection,
  `-f` append `/` to each word, `-U/-P` basic-auth, `-p` proxy, `--timeout 10s`.
- Output lines: `/admin  (Status: 301) [Size: 312] [--> https://192.0.2.10/admin/]`

### vhost mode

```
gobuster vhost -u https://192.0.2.10 \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain --domain example.com -t 50 -k -o gobuster-vhost.txt
```

`--append-domain` is required for `word.example.com` Host headers (without it
gobuster sends just `word`). `--exclude-length <n>` filters the wildcard
response size. Output lines: `Found: admin.example.com Status: 200 [Size: 4321]`.

### dns mode

```
gobuster dns -do example.com \
    -w subdomains-top1million-20000.txt -t 50 \
    -o gobuster-dns.txt
```

Domain flag is **`-do`** (also `--domain`), not `-d`. `-i` shows resolved IPs,
`-c` show CNAMEs, `-r 198.51.100.53` custom resolver, `--wildcard` continue on
wildcard DNS. Output: `Found: dev.example.com` (with `[...]` IPs when `-i`).

### fuzz mode

```
gobuster fuzz -u 'https://192.0.2.10/index.php?page=FUZZ' \
    -w list.txt -b 404 -o gobuster-fuzz.txt
```

Replaces the `FUZZ` keyword anywhere in URL; `--exclude-length` to filter.

## Recursion strategy across tools

1. First pass flat and wide at `/` with a medium raft list + tuned extensions.
2. Recurse selectively: feed only directories that returned 2xx/3xx/401/403
   into depth-2 scans (ferox does this automatically; with ffuf, use
   `-recursion-depth 2`; with dirsearch `-r --max-recursion-depth 2`).
3. Under confirmed app roots (`/api/`, `/admin/`, `/app/`), switch to
   context-specific wordlists (api/*.txt, CMS lists) rather than re-running
   raft-large everywhere.
4. Rerun the winning wordlist with session cookies after you obtain creds —
   post-auth content is where the vulns live.
