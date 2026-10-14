# Oralyzer flag reference and output handling

Oralyzer probes open-redirect and CRLF-injection sinks and classifies the redirect
mechanism: **header** (3xx + `Location`), **javascript** (payload reflected into a
JS navigation sink), **meta** (meta-refresh), and **crlf**.

## Invocation

```
oralyzer -u "https://example.com/login?next="            # single URL (param value position)
oralyzer -l targets.txt                                  # list of URLs
oralyzer -u "https://example.com/login?next=" -p payloads.txt   # custom payload file
oralyzer -u "https://example.com/login?next=" -crlf      # CRLF/response-splitting mode (SINGLE dash)
oralyzer -u "https://example.com/" --discover            # mine wayback for redirect-looking params
oralyzer -l targets.txt --workers 12                     # concurrency
oralyzer -l targets.txt -o oralyzer.json                 # JSON output
oralyzer -l targets.txt --filter header                  # restrict output: header|javascript|meta|crlf
```

| Flag | Meaning |
|---|---|
| `-u URL` | single target; put the injectable param last with an empty/placeholder value |
| `-l file` | newline list of target URLs |
| `-p file` | payload file (one per line) — pair with `references/payloads.md` |
| `-crlf` | CRLF injection mode (note: single dash, not `--crlf`) |
| `-o file` | JSON results output |
| `--discover` | pull candidate parameterized URLs from the Wayback Machine |
| `--workers N` | thread count |
| `--filter TYPE` | only report `header`, `javascript`, `meta`, or `crlf` hits |

Payload-position behavior: Oralyzer injects its payload set into the parameter
value. Feeding `-u "https://example.com/out?url=https://example.com"` lets it
swap the value; an empty trailing `?next=` works the same.

## Reading output

Console marks each payload hit with the redirect type. JSON (`-o`) is a
machine-readable record per vulnerable URL/payload with the type label. Because
versions differ in exact JSON schema, `scripts/parse_oralyzer.py` parses
defensively: it accepts a list of objects, a dict keyed by URL, or raw console
text, and extracts `{url, param, payload, type}` from whatever fields are present
(`url/target/link`, `payload`, `type/class/kind/filter`).

## Verification pass (always, before reporting)

```
# header-based
curl -skI "https://example.com/out?url=//evil.example.net/" | sed -n '1p;/^[Ll]ocation:/Ip'
# js/meta-based
curl -sk "https://example.com/out?url=//evil.example.net/" | grep -nE 'evil\.example\.net'
# crlf
curl -sk -D - -o /dev/null "https://example.com/out?url=/x%0d%0aSet-Cookie:%20crlf=injected" | grep -i '^set-cookie: crlf'
```

Capture the exact request line and the proving response fragment — that exchange
goes verbatim into `findings.report` evidence (see `references/rupu.md`).

False-positive patterns to discard: 200 pages that echo the payload inside inert
HTML (search-results pages), redirects to the payload *path on the same host*
(`Location: /evil.example.net` — relative, not off-site), and `Location` values
that the server prefixes with its own origin.

## Alternatives / complements

- Burp Intruder (Sniper) with `references/payloads.md` as the payload set, grep-match
  on `Location: //` and `evil.example.net` in responses; Collaborator payloads for
  blind confirmation.
- ZAP Automation Framework activeScan includes an External Redirect rule — useful
  for breadth, Oralyzer + manual curl for depth.
- `kxss`-style reflection pipelines don't catch header-based redirects; don't rely
  on them here.
