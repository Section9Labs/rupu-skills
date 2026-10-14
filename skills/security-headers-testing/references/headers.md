# Per-header grading criteria + CSP evaluation

Grades used by `scripts/analyze_headers.py`: `ok`, `weak` (present but defeatable),
`missing`, `info`. Each maps to a severity + CWE/WSTG.

## Content-Security-Policy (WSTG-CONF-12, CWE-693)

Parse directives by splitting on `;`, first token = directive name, rest = sources.
Effective script policy = `script-src` if present, else `default-src`, else nothing.

| Condition | Grade | Why |
|---|---|---|
| Header absent on an HTML response | missing / medium | no XSS mitigation at all |
| `'unsafe-inline'` in script policy without `'nonce-...'`/`'sha256-...'` | weak / medium | inline injection executes; CSP adds ~nothing |
| `'unsafe-eval'` in script policy | weak / low-medium | eval/Function sinks live |
| `*`, `https:`, `http:`, or `data:` as a script/object source | weak / medium | any origin (or data: URI) can host the payload |
| Missing `object-src` and no `default-src` fallback | weak / low | Flash-era but still plugin/`<object>` injection |
| Missing `base-uri` | weak / low | `<base href>` injection re-points relative script srcs |
| Allowlisted bypassable host (see list) | weak / medium | JSONP/AngularJS gadget = full bypass |
| `strict-dynamic` + nonces | ok | modern pattern |
| Only `Content-Security-Policy-Report-Only` present | missing / medium | reports, blocks nothing |
| `report-uri`/`report-to` absent | info | no visibility (hygiene note) |

Bypassable-allowlist hosts (CSP Evaluator's known-gadget logic — presence of any of
these as a script source is a bypass primitive):

```
*.googleapis.com   ajax.googleapis.com (AngularJS)   www.google.com (JSONP)
cdn.jsdelivr.net   cdnjs.cloudflare.com              unpkg.com
*.yandex.net       vk.com                            *.herokuapp.com (anyone can host)
accounts.google.com/o/oauth2/revoke (JSONP)          www.googletagmanager.com
```

Any wildcard that covers attacker-registrable space (`*.s3.amazonaws.com`,
`*.cloudfront.net`, `*.github.io`) = same grade. Validate a suspected bypass by
actually loading a gadget: e.g. with `ajax.googleapis.com` allowlisted, inject
`<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js></script>`
`<div ng-app ng-csp>{{$new.constructor('alert(document.domain)')()}}</div>`
— hand this to the XSS skill as the delivery payload.

Also check: `frame-ancestors` (see clickjacking), `form-action` (missing => injected
`<form action=//evil>` credential capture), `upgrade-insecure-requests` on mixed-content
sites. CSP in `<meta http-equiv>` cannot set frame-ancestors/report-uri — grade the
header, note the meta.

## Strict-Transport-Security (WSTG-CONF-07, CWE-319/CWE-693)

Only valid on HTTPS responses. Parse `max-age=N`, `includeSubDomains`, `preload`.

| Condition | Grade |
|---|---|
| Absent on any HTTPS origin with login/session | missing / medium |
| Absent elsewhere | missing / low |
| `max-age` < 15552000 (180d) | weak / low |
| `max-age=0` | weak / medium (actively clears HSTS) |
| no `includeSubDomains` | weak / low (subdomain strip window) |
| no `preload` | info (first-visit strip window remains) |

Also fetch `http://example.com/` and record the redirect chain — a 301 to HTTPS with
no HSTS afterward, or any HTTP 200, extends the sslstrip window.

## X-Frame-Options / frame-ancestors (WSTG-CLNT-09, CWE-1021)

- Both absent on any page with authenticated state or actions => **test the PoC**
  (see `cookies-and-clickjacking.md`), grade medium if it renders.
- `XFO: ALLOW-FROM uri` => ignored by all current browsers = absent.
- `XFO: SAMEORIGIN` with no frame-ancestors = ok (note double-framing edge cases on
  ancient browsers only).
- `frame-ancestors 'none'|'self'` = ok and overrides XFO.
- Conflicting XFO values from stacked proxies (`SAMEORIGIN, DENY`) = weak (some
  browsers treat invalid as absent).

## X-Content-Type-Options (CWE-693)

`nosniff` exact (case-insensitive). Missing = low everywhere, medium on routes serving
user-controlled content (uploads, API echoes) — MIME sniffing turns text/plain uploads
into executing HTML/JS. Also required for script/style `Cross-Origin-Read-Blocking`
protections.

## Referrer-Policy

Missing => browser default `strict-origin-when-cross-origin` (acceptable; grade info)
BUT grade **weak/low** if URLs carry secrets (session in URL, reset tokens) — then
also raise the token-in-URL finding itself (WSTG-SESS). Explicit `unsafe-url` or
`no-referrer-when-downgrade` = weak/low. `no-referrer` / `same-origin` /
`strict-origin-when-cross-origin` = ok.

## Permissions-Policy

Absent = info (hygiene). Present: parse `camera=`, `microphone=`, `geolocation=`,
`payment=` — `*` grants to all embeddees = weak/low on sites that frame third-party
content.

## CORS (defer to `cors-testing`)

In this pass only flag and hand off: `Access-Control-Allow-Origin: *` with
`Access-Control-Allow-Credentials: true` (invalid combo but server intent is clear),
ACAO reflecting the request Origin, `null` allowed. Create a work unit targeting the
`cors-testing` skill; do not run the origin battery here.

## Cache-Control (CWE-525, WSTG-ATHN-06)

On responses containing session-bound/PII data (use `--sensitive`):

| Condition | Grade |
|---|---|
| No `Cache-Control` at all | missing / medium |
| Cacheable (`public` or `max-age>0` without `private`) | weak / medium |
| `no-cache` only (still storable) | weak / low |
| `no-store` | ok |

Legacy `Pragma: no-cache` alone is not sufficient. Shared-cache exposure pairs with
web cache deception (`request-smuggling-testing` §6).

## Info-leak headers (WSTG-INFO-02)

`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`,
`Via` with software versions => info finding, one per host, listing all leaked strings.
Feed versions to CVE lookup in the vuln-scanning skill.

## Deprecated / anti-patterns

- `X-XSS-Protection`: any value — recommend `0` or removal; `1; mode=block` enabled
  XS-Leaks on legacy browsers. Grade info.
- `Expect-CT`: obsolete (CT now mandatory). Info.
- `Public-Key-Pins`: obsolete and dangerous. If present, weak/low (self-DoS risk).

## Tool crib

```
# raw capture (GET beats HEAD for fidelity)
curl -sk -D - -o /dev/null https://example.com/

# nuclei sweep
nuclei -l urls.txt -t http/misconfiguration/http-missing-security-headers.yaml -j -o nh.jsonl
# each JSONL line: matcher-name == the missing header; template-id, host, matched-at

# nikto (headers are in the 'b' tuning class among others)
nikto -h https://example.com -o nikto.json -Format json

# the authority: value-grading analyzer
python3 scripts/analyze_headers.py --url https://example.com/ -o report.json \
    --work-units gaps.json --findings findings.json
```
