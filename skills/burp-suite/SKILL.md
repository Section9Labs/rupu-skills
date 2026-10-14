---
name: burp-suite
description: Drive Burp Suite (Pro/Community) as the primary web-assessment workbench - intercept and tamper with Proxy/Repeater, fuzz with Intruder, crawl-and-audit with the Pro Scanner, confirm blind/OOB bugs with Collaborator, extend with BApps/Montoya, and automate headless or via the built-in REST API for CI pipelines; use whenever a target web application needs manual testing, scripted scanning, or request capture for downstream tools (sqlmap -r, ffuf, dalfox).
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Burp Suite — manual workbench + scripted scanning

Burp is the hub of a web assessment: everything the browser does flows through
the Proxy, interesting requests fan out to Repeater/Intruder/Scanner, and the
captured raw requests feed every downstream tool. This skill covers the full
loop: setup → mapping → manual tampering → fuzzing → scanning → OOB
confirmation → headless/REST automation → rupu handoff.

Depth lives in `references/`:
- `references/manual-workflow.md` — Proxy, Repeater, Intruder (all four attack
  types), Sequencer, Decoder/Comparer, Collaborator, scope discipline.
- `references/scanner-and-extensions.md` — Pro Scanner configs, auth, triage,
  must-have BApps, Montoya API extension sketch.
- `references/headless-and-rest-api.md` — headless CLI flags, the full REST
  API with curl examples, Burp XML export.
- `references/rupu.md` — REQUIRED output wiring (work units, `assets.mark`,
  `findings.report`). Every parse/handoff step below ends in one of those.

## 1. Setup

1. Start Burp, confirm the Proxy listener on `127.0.0.1:8080`
   (Proxy → Proxy settings). Add an all-interfaces listener if testing from
   another box/container.
2. Install the CA: browse `http://burpsuite` (or `http://127.0.0.1:8080`) →
   "CA Certificate", import into the test browser's trust store — or just use
   Burp's embedded Chromium (Proxy → Open browser), which is pre-wired.
3. Define scope: Target → Scope settings → Include prefix
   `https://example.com/`. Enable "show only in-scope items" in the site map
   and Proxy history, and (optionally) drop out-of-scope proxy traffic.
4. For non-browser clients, point them at the listener
   (`HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080`) or
   use an invisible/transparent listener.

**rupu**: mark the target now — `assets.mark` kind `web:site`, coordinates
`[{"t":"url","v":"https://example.com"}]`, depth `mapped`. See
`references/rupu.md`.

## 2. Map the application

- Browse every function of the app through the proxy — login, logout,
  registration, password reset, every form, every role you have creds for.
  The Target site map fills in passively; grey entries are linked-but-unvisited.
- Walk the site map tree; read Proxy → HTTP history and **WebSockets history**
  (WS traffic is where modern apps hide the interesting messages).
- Use Proxy history filters (status, MIME, extension, search term) and sort by
  parameterized requests to find injectable surface.
- Pro: right-click the target in the site map → "Scan" → crawl only, to
  augment coverage before manual work.

**rupu**: every distinct route/parameter discovered is `assets.mark` kind
`web:route` at depth `crawled` (coordinates url + `http_route` + optional
`param`). Export the interesting-request list as a work-units JSON array (one
unit per route) and hand it to the `work-units` skill so a lead agent can
fan out per-route testing. Shapes in `references/rupu.md`.

## 3. Manual tampering — Proxy intercept + Repeater

- Intercept on only when you need to tamper in-flight; otherwise work from
  history. Use Proxy → Match and replace for standing mutations (e.g. add
  `X-Forwarded-For: 127.0.0.1` to every request, swap a session cookie,
  rewrite the Host header).
- `Ctrl+R` sends any request to **Repeater**. Repeater is for hypothesis
  testing: change one thing, send, diff the response (length, status, timing,
  reflected content). Tabs are cheap — one tab per hypothesis.
- Classic Repeater passes: role/ID swap for IDOR (change `id=1001`→`1002`
  under a low-priv session), method override (GET→POST, add
  `X-HTTP-Method-Override`), content-type flips (JSON→XML to reach an XXE
  parser), auth-header removal, single-quote/`{{7*7}}`/`../` probes per
  parameter.
- Decoder for quick encode/decode chains (URL/HTML/Base64/hex/gzip);
  Comparer to diff two responses word- or byte-wise (e.g. valid vs invalid
  username on login — a diff means username enumeration).

**rupu**: each parameter you manually tested → `web:route` at depth `tested`.
A confirmed issue (e.g. IDOR proven by retrieving another user's record) goes
straight to the `finding-report` skill / `findings.report` with the full
request/response pair as evidence, classified by WSTG (IDOR = WSTG-ATHZ-04,
CWE-639).

## 4. Fuzzing — Intruder

Send to Intruder (`Ctrl+I`), set payload positions with `§` markers, pick the
attack type:

- **Sniper** — one payload set, one position at a time. Default for
  per-parameter fuzzing and username enumeration.
- **Battering ram** — one payload set, same payload in all positions at once
  (e.g. same value in `user` and `X-User` header).
- **Pitchfork** — N payload sets stepped in parallel (position 1 gets set-1
  item i, position 2 gets set-2 item i). Credential stuffing with paired
  user:pass lists.
- **Cluster bomb** — N sets, full cartesian product. Brute force
  user × password; watch the request count explode.

Payload sets: simple list (load a wordlist), numbers (IDOR ranges), brute
forcer, dates, username generator, "copy other payload", extension-generated.
Add **payload processing rules** (hash, encode, add prefix/suffix, match/
replace) and set URL-encoding of special chars appropriately.

Reading results: sort by status, **length** (the single best anomaly signal),
and add Settings → **Grep - Match** (e.g. `error`, `Welcome`, `root:`) and
**Grep - Extract** (pull a CSRF token or account name out of each response —
also the mechanism for recursive-grep attacks on multi-step flows). Columns
for response-received/response-completed time expose time-based blind
injection. Resource pool controls concurrency per attack. **Community
Intruder is heavily rate-limited** — for serious brute force on Community,
use the Turbo Intruder extension or hand off to ffuf/hydra.

**rupu**: fuzzed routes → `web:route` depth `tested`; anomalous rows worth a
dedicated child agent → work-units array; confirmed hits → `findings.report`.

## 5. Scanner (Pro)

- Launch: Dashboard → New scan (crawl and audit), or right-click any site-map
  node / proxy request → Scan. Pick a **named scan configuration**: "Audit
  checks - light active" (fast, low-noise), "Audit checks - medium active",
  "Audit coverage - maximum", or crawl-only configs. Stack multiple configs;
  later ones override.
- Auth: add Application login (username+password for simple forms, or a
  **recorded login sequence** exported from the Burp browser extension for
  multi-step/SSO logins) so the crawler reaches post-auth surface.
- **Live scanning**: Dashboard → live tasks can passively (or actively) audit
  everything you proxy while you browse — free coverage during manual work.
- Triage the Issues tab: severity × confidence matrix, read the advisory,
  **replay the attached request in Repeater to confirm** before reporting.
  Details and config depth in `references/scanner-and-extensions.md`.

**rupu**: parse scanner output via the REST API (`scripts/burp_scan.py`) or
XML export (`scripts/parse_burp_xml.py`); both emit normalized issues,
`--work-units` arrays and `findings.report` payloads. Confirmed issues →
`finding-report` skill; scanned routes → depth `tested`, exploited ones →
`exploited`.

## 6. Out-of-band — Collaborator (Pro)

- Burp → "Burp Collaborator client" → Copy to clipboard gets payload domains
  like `x7k2...oastify.com`. Inject them anywhere a blind interaction could
  surface: Host/Referer/X-Forwarded-Host headers, URL parameters (SSRF), XML
  DOCTYPE SYSTEM ids (XXE), JNDI strings, serialized-object gadget args,
  email fields (blind XSS in admin panels).
- Poll the client: a **DNS-only interaction proves the payload was resolved**
  (code executed / URL fetched server-side even if HTTP egress is blocked);
  an HTTP interaction gives you the full inbound request including any
  exfiltrated data.
- Scanner uses Collaborator automatically for blind classes; the
  **Collaborator Everywhere** BApp injects payloads into every proxied
  request's headers for passive pingback hunting.
- No Pro? Use `interactsh-client` the same way (single-dash long flags:
  `-json -o hits.json`).

**rupu**: a Collaborator hit tied to a specific injected request is a
confirmed finding — report via `findings.report` with the injected request,
the interaction record (timestamp, type, source IP) in evidence, scope
`endpoint`, e.g. SSRF = CWE-918 / WSTG-INPV-19, XXE = CWE-611 / WSTG-INPV-07.
Mark the route `exploited` if you retrieved data (e.g. cloud metadata).

## 7. Extensions

Install from Extensions → BApp Store. Core set: Logger++, Param Miner,
Turbo Intruder, Autorize, JWT Editor, Active Scan++, Collaborator Everywhere,
Upload Scanner, HTTP Request Smuggler, Hackvertor. What each is for, plus a
minimal Montoya-API (Java) HTTP-handler extension sketch, is in
`references/scanner-and-extensions.md`.

## 8. Headless / CI and the REST API (Pro)

Headless run (project file required for persistence; the unpause flag is what
actually starts queued tasks in CI):

```
java -jar -Djava.awt.headless=true burpsuite_pro.jar \
  --project-file=/opt/burp/example.burp \
  --config-file=/opt/burp/scan-config.json \
  --unpause-spider-and-scanner --disable-extensions
```

REST API: enable Settings → Suite → REST API, create an API key; base
`http://127.0.0.1:1337`, path `/{key}/v0.1/...`, self-documenting (browse the
base URL). It is deliberately minimal — start scan, poll status, read issues;
Burp Enterprise/DAST is the richer CI product.

```
POST /{key}/v0.1/scan        # {"urls":[...], "scan_configurations":[{"type":"NamedConfiguration","name":"Audit checks - light active"}], "application_logins":[...], "scope":{...}}
                             # -> 201, Location: /{key}/v0.1/scan/<task_id>
GET  /{key}/v0.1/scan/<id>   # -> scan_status, scan_metrics, issue_events[]
```

Automate it:

```
export BURP_API_KEY=S9x...; export BURP_API_URL=http://127.0.0.1:1337
python3 scripts/burp_scan.py --url https://example.com \
  --scan-config "Audit checks - light active" \
  -o burp-issues.json --work-units burp-units.json --findings burp-findings.json
```

No REST API (Community, or offline)? Export issues from the GUI
(right-click issues → "Report selected issues" → XML, include requests/
responses base64) and run:

```
python3 scripts/parse_burp_xml.py burp-export.xml \
  -o burp-issues.json --work-units burp-units.json --findings burp-findings.json
```

Both scripts normalize every issue to
`{name, severity, confidence, url, issue_type, evidence}` with decoded
request/response, map severity to rupu's info|low|medium|high|critical, and
attach a CWE/WSTG classification. Full CLI + API detail:
`references/headless-and-rest-api.md`.

**rupu**: `burp-units.json` is a ready `for_each:`/dispatch array — hand it to
the `work-units` skill. Each object in `burp-findings.json` is a ready
`findings.report` call — file confirmed ones via the `finding-report` skill.
Mark every scanned URL `web:site`/`web:route` depth `tested`.

## 9. Chaining out of Burp

- **sqlmap**: right-click request → Copy to file → `req.txt`, then
  `sqlmap -r req.txt --batch --level=3 --risk=2 --technique=BEUSTQ --force-ssl`.
  Session cookies and CSRF context come along for free — this is why Burp
  capture beats hand-built URLs.
- **ffuf**: lift the exact headers/cookies from Proxy history:
  `ffuf -u https://example.com/FUZZ -w wordlist.txt -H 'Cookie: session=...'`.
- **dalfox**: reflected-param candidates from the site map →
  `dalfox scan 'https://example.com/search?q=x' --cookies 'session=...' -o xss.json -f json`.
- Upstream chaining: run other tools *through* Burp
  (`--proxy http://127.0.0.1:8080` / mitmproxy `--mode upstream:http://127.0.0.1:8080`)
  so everything lands in one history and the live scanner sees it.

Every chain handoff that produces results ends in a rupu output — work units
for fan-out, `assets.mark` for coverage, `findings.report` for confirmed
issues (`references/rupu.md`).

## Quick decision table

| Need | Tool |
|---|---|
| See/modify one request in flight | Proxy intercept |
| Iterate payloads by hand, diff responses | Repeater (+ Comparer) |
| Automated payload placement / brute force | Intruder (Turbo Intruder on Community) |
| Broad automated vuln coverage | Scanner (Pro) crawl-and-audit |
| Blind SSRF/XXE/XSS/deser confirmation | Collaborator (or interactsh) |
| Session-token entropy | Sequencer |
| Hidden params / smuggling / authz diffing | Param Miner / HTTP Request Smuggler / Autorize |
| CI pipeline scan | Headless + REST API → `scripts/burp_scan.py` |
