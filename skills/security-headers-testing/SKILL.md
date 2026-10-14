---
name: security-headers-testing
description: Review HTTP security headers and cookie flags on every response — CSP (unsafe-inline/eval, wildcard, bypassable allowlists), HSTS, X-Frame-Options/frame-ancestors (with a working clickjacking PoC), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS exposure, cache controls, and HttpOnly/Secure/SameSite/__Host- cookie attributes. Use as a fast, high-coverage WSTG-CONF/WSTG-CLNT configuration pass on every target response; it complements active vuln skills by cataloguing the missing defenses that make their exploits land.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0"
  wstg: "WSTG-CONF, WSTG-CLNT"
  cwe: "CWE-693, CWE-1021, CWE-614, CWE-1004"
---

# Security Headers & Cookie-Flag Review

A header gap is rarely the exploit itself — it is what lets another exploit land
(no CSP => XSS executes; no HttpOnly => XSS steals the session; no frame-ancestors =>
clickjacking; no HSTS => SSL-strip). Run this pass on *every distinct response class*:
unauthenticated page, authenticated page, login/reset flow, API JSON, error page,
static asset, redirect — headers often differ per route and per CDN layer.

Per-header criteria and CSP evaluation logic: `references/headers.md`.
Cookie flags and the clickjacking PoC workflow: `references/cookies-and-clickjacking.md`.
rupu output shapes: `references/rupu.md` — every parse step below ends in a work-units
array, `assets.mark` calls, or `findings.report`.

## 1. Capture responses

```
curl -skI https://example.com/                       # HEAD, headers only
curl -sk -D - -o /dev/null https://example.com/      # GET (some stacks differ on HEAD!)
curl -sk -D - -o /dev/null -H 'Cookie: session=...' https://example.com/account
curl -sk -D - -o /dev/null https://example.com/api/v1/me -H 'Accept: application/json'
```

Prefer `-sD - -o /dev/null` over `-I`: servers frequently omit or change headers on
HEAD. Capture both HTTP and HTTPS, with and without auth, and at least one 404/500
(error pages leak and lack headers most often). For breadth, pipe a crawled URL list
(katana/gau) through the analyzer in step 2.

Broad sweeps:

```
nuclei -u https://example.com -t http/misconfiguration/http-missing-security-headers.yaml -j -o nuclei-headers.jsonl
nikto -h https://example.com -Tuning b -o nikto.json -Format json
```

Nuclei's `http-missing-security-headers` template fires one result per missing header
(matcher-name = header). Treat nuclei/nikto as discovery; the analyzer below is the
authority because it grades values, not just presence.

## 2. Analyze — `scripts/analyze_headers.py`

Self-contained (stdlib) analyzer: fetches a URL (urllib, cert-check disabled) or parses
a saved raw response, grades every security header and every `Set-Cookie`, and emits
all three rupu outputs in one run:

```
python3 scripts/analyze_headers.py --url https://example.com/ \
    --work-units gaps.json --findings findings.json -o report.json
curl -sk -D - -o /dev/null https://example.com/account -H 'Cookie: s=1' \
    | python3 scripts/analyze_headers.py --stdin --target-url https://example.com/account \
      --sensitive --findings findings.json
python3 scripts/analyze_headers.py --file saved_response.txt --target-url https://example.com/
```

Flags: `--url` fetch | `--stdin` / `--file` parse raw response; `--target-url` labels
parsed input; `--sensitive` enables cache-control checks (use for authed/PII
responses); `--method GET|HEAD`; `-o report.json` merged JSON;
`--work-units gaps.json` work-unit array; `--findings findings.json` ready
`findings.report` payloads.

Reading the report: each check has `status` (`ok|weak|missing|info`), `severity`,
`cwe`, `wstg`, and `detail`. `weak` means present-but-defeatable (e.g. CSP with
`unsafe-inline`, HSTS `max-age=86400`) — these matter more than `missing` on paper
because they signal someone tried and failed.

**Parse/handoff:** `--work-units` output goes to the `work-units` skill for fan-out
(one unit per gap needing verification, e.g. "build clickjacking PoC", "test CSP
bypass via allowlisted CDN"). Mark each analyzed URL with `assets.mark`
(kind `web:route`, depth `tested`). `--findings` payloads go through the
`finding-report` skill once you've attached the proving exchange.

## 3. Grade the big headers (summary — full criteria in `references/headers.md`)

- **Content-Security-Policy** — evaluate like Google CSP Evaluator: missing policy;
  `script-src`/`default-src` containing `'unsafe-inline'` (without nonce/hash),
  `'unsafe-eval'`, `*`, `http:`, `https:`, or `data:`; missing `object-src 'none'`;
  missing `base-uri`; allowlisted hosts with JSONP/AngularJS bypass gadgets
  (`*.googleapis.com`, `cdn.jsdelivr.net`, etc.); `Report-Only` without an enforcing
  twin. A bypassable CSP is a finding *and* an enabler note for the XSS skill.
- **Strict-Transport-Security** — missing on HTTPS; `max-age` < 15552000; missing
  `includeSubDomains`; preload-list eligibility. Only meaningful on the HTTPS
  response; also check the HTTP->HTTPS redirect hop (HSTS on HTTP is ignored —
  the redirect itself is the strip window).
- **X-Frame-Options / CSP `frame-ancestors`** — if BOTH absent on any stateful page,
  build the framing PoC (step 4). `ALLOW-FROM` is dead (ignored by modern browsers) =
  effectively missing. `frame-ancestors` wins over XFO when both present.
- **X-Content-Type-Options: nosniff** — required everywhere, critical on user-upload
  and API routes (MIME-sniff => stored XSS escalation).
- **Referrer-Policy** — missing or `unsafe-url`/`no-referrer-when-downgrade` leaks
  URLs (incl. reset tokens in path/query) cross-origin.
- **Permissions-Policy** — absence is `info`; note camera/mic/geolocation exposure.
- **CORS headers** — flag `Access-Control-Allow-Origin: *` + credentials, or
  origin reflection, then **hand off to the `cors-testing` skill** (Corsy/CORScanner)
  for the 11-origin bypass battery; don't duplicate it here.
- **Cache-Control on sensitive responses** — authed/PII responses need
  `no-store` (or `no-cache, private` minimum); missing => shared-cache / back-button
  disclosure (CWE-525). Pairs with cache-deception testing in
  `request-smuggling-testing`.
- **Leaky headers** — `Server`, `X-Powered-By`, `X-AspNet-Version`,
  `X-AspNetMvc-Version` version strings: `info`, WSTG-INFO-02.
- **X-XSS-Protection** — deprecated; `1; mode=block` on old browsers introduced
  XS-leaks; recommend removal (`0`) + CSP. Grade `info`.

## 4. Cookies and clickjacking (detail in `references/cookies-and-clickjacking.md`)

For every `Set-Cookie` (the analyzer parses them all, duplicates included):

- Session/auth cookies: require `HttpOnly` (CWE-1004), `Secure` (CWE-614),
  `SameSite=Lax|Strict` (missing/`None` => CSRF surface, CWE-1275).
- `__Host-` prefix = gold standard (Secure, no Domain, Path=/); `__Secure-` next best.
- Overly broad `Domain=.example.com` shares the session with every subdomain —
  pivot: any subdomain takeover/XSS now steals it. Broad `Path=/` on a cookie that
  only one app needs: same logic.
- To *prove* impact, chain: no HttpOnly + any XSS from the XSS skill =>
  `document.cookie` exfil PoC; SameSite=None/missing => CSRF PoC.

**Clickjacking PoC** — when XFO and frame-ancestors are both absent on a
state-changing page, generate and open the PoC:

```
python3 scripts/analyze_headers.py --url https://example.com/account/delete --poc poc.html
```

The PoC loads the target in a semi-transparent `<iframe>` over a decoy button.
If the page renders in the frame, screenshot it — that render *is* the evidence
(CWE-1021, WSTG-CLNT-09). If it's blank, check the console: `frame-ancestors` or XFO
did its job (also verify no JS frame-buster-only defense, which is bypassable with
`sandbox="allow-forms allow-scripts"` on the iframe — the PoC includes that variant).

## 5. CRLF / header-injection pointer

If any response header reflects request input (URL path/query into `Location`,
cookies echoed, etc.), that's a header-injection candidate — hand it to the
**`open-redirect-testing`** skill (Oralyzer with `-crlf`) rather than testing here.
The analyzer flags reflected-looking `Location` values as a `crlf-candidate` work unit.

## 6. Report

Every graded gap that you keep (after de-duping per-route noise — a site-wide missing
header is ONE host-scope finding, not fifty endpoint findings) goes through the
`finding-report` skill:

- scope `endpoint` + `target_ref` URL for route-specific gaps (e.g. no-store on
  `/account`); scope `host` for site-wide policy gaps (e.g. no HSTS anywhere).
- severity: typically **low/medium** — medium for missing/bypassable CSP on an app
  with injection surface, missing HttpOnly/Secure/SameSite on session cookies,
  clickjacking on state-changing pages, missing HSTS on a login origin; low for the
  rest; info for Permissions-Policy absence and banner leaks. Escalate when chained
  (proved XSS + no HttpOnly => the *XSS* finding carries it as impact).
- classification: WSTG-CONF-07 (HSTS), WSTG-CONF-12 (CSP), WSTG-CLNT-09
  (clickjacking), WSTG-SESS-02 (cookie attributes) + CWE-693/1021/614/1004 as mapped
  by the analyzer.
- evidence: the raw response header block (and for clickjacking, the PoC + screenshot;
  for cookies, the exact `Set-Cookie` line). The analyzer embeds the header block in
  every `--findings` payload automatically — exact shapes in `references/rupu.md`.
