# Corsy and CORScanner reference

## Corsy (s0md3v)

Probes each URL with 11 crafted-Origin tests (reflection, null, prefix/suffix,
unescaped dot, subdomain, http-origin, special chars, wildcard, port, third party).

```
python3 corsy.py -u https://example.com/api/user
python3 corsy.py -i routes.txt
python3 corsy.py -i routes.txt -t 20                 # threads
python3 corsy.py -i routes.txt -o corsy.json         # JSON output
python3 corsy.py -i routes.txt -d 2                  # 2s delay between requests (-d SECS; there is no --delay)
python3 corsy.py -i routes.txt -q                    # quiet
python3 corsy.py -i routes.txt --headers "Cookie: session=abc\nUser-Agent: Mozilla/5.0"
```

| Flag | Meaning |
|---|---|
| `-u URL` | single target |
| `-i file` | newline URL list |
| `-t N` | thread count |
| `-d SECS` | per-request delay |
| `-o file` | JSON results |
| `-q` | quiet (findings only) |
| `--headers "..."` | extra request headers — **use for the authenticated pass** |

Output JSON: a dict keyed by URL:

```json
{
  "https://example.com/api/user": {
    "class": "Origin reflected",
    "description": "...",
    "severity": "high",
    "exploitation": "...",
    "acao header": "https://evil.example.net",
    "acac header": "true"
  }
}
```

`class` values map to the check matrix: `Origin reflected`, `Wildcard value`,
`Null origin allowed`, `Whitelisted null origin`, `HTTP origin allowed`,
`Unescaped regex dot`, `Pre-domain bypass`, `Post-domain bypass`,
`Broad subdomain trust`, `Unrecognized origin`, `Invalid value` (server emits a
broken ACAO — hygiene note).

## CORScanner (chenjj)

```
python3 cors_scan.py -u https://example.com -o corscanner.json
python3 cors_scan.py -i routes.txt -t 50 -o corscanner.json
python3 cors_scan.py -u https://example.com -v              # verbose
python3 cors_scan.py -i routes.txt -T 10                    # timeout seconds
python3 cors_scan.py -i routes.txt -p http://127.0.0.1:8080 # proxy (route via mitmproxy/Burp to keep raw exchanges)
python3 cors_scan.py -u https://example.com -d "Cookie: session=abc"   # headers
cors -u https://example.com                                 # pip entrypoint
```

| Flag | Meaning |
|---|---|
| `-u URL` / `-i file` | target(s) |
| `-t N` | threads |
| `-T SECS` | timeout |
| `-o file` | JSON results |
| `-v` | verbose |
| `-p proxy` | HTTP(S) proxy |
| `-d "..."` | extra headers (authed pass) |

Output JSON: list of records like

```json
[{"url": "https://example.com/api/user", "type": "reflect_origin",
  "credentials": "true", "origin": "https://evil.example.net"}]
```

`type` values include `reflect_origin`, `prefix_match`, `suffix_match`,
`trust_null`, `include_match` (substring), `not_escape_dot`, `custom_third_parties`,
`special_characters_bypass`, `trust_any_subdomain`, `https_trust_http`.

## Tool strategy

1. Breadth: CORScanner over the full route list (`-t 50`), unauthenticated.
2. Depth: Corsy over the interesting/API subset **with `--headers` carrying a live
   session** — credentialed behavior is the finding.
3. Confirm each hit manually (and capture evidence):

```
curl -sk -D - -o body.txt -H "Origin: https://evil.example.net" \
     -H "Cookie: session=abc" https://example.com/api/user
grep -i '^access-control-\|^vary:' headers
curl -sk -X OPTIONS -D - -o /dev/null \
     -H "Origin: https://evil.example.net" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: x-requested-with" \
     https://example.com/api/user
```

4. Feed both JSON files to `scripts/parse_cors.py` (it autodetects each format and
   can `--verify` hits itself with stdlib urllib), then route the outputs per
   `references/rupu.md`.

False positives to discard: ACAO reflected but endpoint serves no non-public data
and no ACAC (info at best); ACAO echo on error pages only; `Vary: Origin` +
origin-allowlist where only genuinely-owned origins are echoed (test #6/#3/#4
variants to be sure the allowlist is actually strict).
