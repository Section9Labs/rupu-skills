# nikto deep-dive

## Invocation basics

```
nikto -h https://192.0.2.10                       # scheme in URL sets port/ssl
nikto -h 192.0.2.10 -port 8443 -ssl               # IP + explicit TLS port
nikto -h 192.0.2.10 -port 80,8080,8000            # multiple ports, same host
nikto -h hosts.txt -Format json -output all.json  # file of targets
```

**Capitalization matters**: `-Tuning`, `-Format`, `-Display`, `-Plugins`,
`-Pause`, `-Cgidirs` are capitalized; `-h`, `-port`, `-ssl`, `-vhost`,
`-id`, `-useragent`, `-useproxy`, `-evasion`, `-mutate`, `-maxtime`,
`-timeout`, `-output`, `-nointeractive` are lowercase. There is **no `-p`**
for port and `htm` not `html` for format.

## Tuning map (`-Tuning`)

| code | test class |
|------|-----------|
| 1 | Interesting files / seen in logs |
| 2 | Misconfiguration / default files |
| 3 | Information disclosure |
| 4 | Injection (XSS / script / HTML) |
| 5 | Remote file retrieval — inside web root |
| 6 | Denial of service |
| 7 | Remote file retrieval — server wide |
| 8 | Command execution / remote shell |
| 9 | SQL injection |
| 0 | File upload |
| a | Authentication bypass |
| b | Software identification |
| c | Remote source inclusion / directory traversal |
| d | WebService |
| e | Administrative console |
| x | **reverses** the selection that follows |

Combos: `-Tuning 2389c` (misconfig+info+cmdexec+sqli+traversal),
`-Tuning x6` (all except DoS — the standard sweep), `-Tuning x67` (skip DoS
and server-wide retrieval on fragile targets). No `-Tuning` = all tests.

## Evasion (`-evasion`, libwhisker encodings)

| code | technique |
|------|-----------|
| 1 | Random URI encoding (non-UTF8) |
| 2 | Directory self-reference (`/./`) |
| 3 | Premature URL ending |
| 4 | Prepend long random string |
| 5 | Fake parameter |
| 6 | TAB as request spacer |
| 7 | Change the case of the URL |
| 8 | Use Windows directory separator `\` |
| A | Use a carriage return (0x0d) as a request spacer |
| B | Use binary value 0x0b as a request spacer |

Stackable: `-evasion 17`. These mangle requests — expect some signatures to
stop matching; use only when an IDS/WAF is actually dropping you.

## Mutate (`-mutate` + `-mutate-options`)

| mode | action |
|------|--------|
| 1 | Test all files with all root directories |
| 2 | Guess password file names |
| 3 | Enumerate user names via Apache (`/~user`) |
| 4 | Enumerate user names via cgiwrap |
| 5 | Brute-force subdomain names (needs `-mutate-options` domain) |
| 6 | Guess directory names from a dictionary (`-mutate-options <file>`) |

Multiplies request volume dramatically; run after the baseline, not with it.

## Other useful flags

- `-Cgidirs all` — test every known CGI dir (default tries a short list).
- `-root /app` — prepend a path to every test.
- `-no404` — disable smart 404 detection (when the target lies with 200s,
  pair with manual filtering instead).
- `-followredirects` — probe the redirect targets too.
- `-Save <dir>` — save positive-response bodies for later review.
- `-Display`: `1` redirects, `2` cookies, `3` 200 responses, `4` auth-required
  URLs, `D` debug, `E` HTTP errors, `P` progress, `S` scrub target from
  output, `V` verbose. E.g. `-Display 124P`.
- `-until 07:00` / `-maxtime 2h` — stop conditions for fleet scheduling.
- `-Option <name>=<value>` — override nikto.conf (e.g.
  `-Option STATIC-COOKIE="session=abc"` to send a cookie).
- `-update` is removed in modern packages — update via git pull of the
  databases/ directory.

## Output formats and reading them

`-Format json -output out.json` → a JSON object (newer builds; some versions
emit an array or concatenated objects — `parse_nikto.py` handles all three):

```json
{"host": "192.0.2.10", "ip": "192.0.2.10", "port": "443",
 "banner": "Apache/2.4.29 (Ubuntu)",
 "vulnerabilities": [
   {"id": "OSVDB-3233", "method": "GET", "url": "/icons/README",
    "msg": "Apache default file found.",
    "references": "https://..."}
 ]}
```

CSV format columns: `"host","ip","port","id","method","uri","msg"` — the same
normalized fields. XML wraps items in `<item>` with `osvdbid`, `method`,
`<uri>`, `<description>`.

Interpreting items:
- `id` beginning `OSVDB-` is a (defunct) OSVDB reference — use it as a search
  key; newer DB entries carry nikto test IDs (6-digit) and CVE/URL refs in
  `references`.
- Banner/version lines ("Apache/2.4.29 appears to be outdated") are
  host-scope, severity by the actual CVEs for that version — verify the
  banner isn't spoofed.
- Path hits (default files, backups, consoles) are endpoint-scope — **replay
  before reporting**; nikto trusts status codes and matches, both lie.

High-value signatures worth immediate manual follow-up:
`/.git/HEAD`, `/.svn/entries`, `/.env`, `wp-config.php.bak`-style backups,
`/server-status`, `/server-info`, `/manager/html` (Tomcat), `/phpmyadmin/`,
`/cgi-bin/test-cgi`, shellshock CGI hits, `HTTP PUT` enabled ("may allow
clients to save files"), TRACE enabled (XST), directory indexing.
