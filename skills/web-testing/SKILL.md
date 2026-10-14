---
name: web-testing
description: Umbrella methodology for an end-to-end web application security assessment following OWASP WSTG v4.2 — phased flow from scope intake and recon through configuration, auth/session, authorization, input-validation, business-logic and client-side testing to exploitation and reporting, routing each phase to the specific sub-skill to load (http-probing, web-crawling, sqli-testing, xss-testing, etc.) and wiring every phase handoff into rupu work-units, assets.mark coverage, and findings.report output. Load this first on any web engagement to plan and drive the whole assessment.
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg-version: "4.2"
  role: umbrella
---

# Web Application Security Assessment — Umbrella Methodology (OWASP WSTG v4.2)

This is the spine of a web engagement. It does not teach tools itself — it tells you
**which sub-skill to load at each step**, what that step must produce, and how the
output feeds the next phase. The full WSTG-v4.2 test-case → sub-skill map is in
`references/wstg-map.md`; the one-line index of every sub-skill is in
`references/sub-skills.md`; the rupu pipeline wiring (work units, assets, findings)
is in `references/rupu.md`.

**Golden rule of this pack:** every step that parses tool output ends by producing
one of three rupu-ingestible artifacts — a work-units JSON array (fan-out), an
`assets.mark` call (coverage), or a `findings.report` call (verified issue). Exact
JSON shapes: `references/rupu.md`.

## Depth ladder

Work shallow-to-deep and record where each asset stops:

```
passive recon -> active mapping -> automated scan -> manual/targeted testing -> exploitation
   (mapped)       (crawled)         (tested)             (tested)                (exploited)
```

The parenthesized rungs are the `assets.mark` `depth` values. A route only moves
up the ladder when you actually did that work against it.

---

## Phase 1 — Scope intake & tooling setup

Inputs: target list (domains, URL bases, IP ranges like `192.0.2.0/24`), credentials
if any, out-of-band callback infrastructure (interactsh/collaborator), engagement notes.

Set up the interception proxy that ALL manual tampering and OOB testing will run
through for the rest of the engagement. Route by preference:

- Load **`mitmproxy`** — scriptable CLI/TUI proxy, best for automation-heavy runs
  and headless agents (mitmdump addons, flow filters, replay).
- Load **`burp-suite`** — Repeater/Intruder/Collaborator workflow, best for deep
  manual testing.
- Load **`owasp-zap`** — proxy + active scanner + API/daemon mode, best when you
  want a free DAST pass alongside the proxy.

Export the proxy CA, set `HTTP_PROXY`/`HTTPS_PROXY` (or per-tool `-proxy` flags) so
every downstream tool's traffic is captured. Start the OOB listener now; SSRF/XXE/
blind-injection phases depend on it.

Handoff: write the raw target list as a seed work-units array (one unit per URL
base) using the **`work-units`** skill's shape; mark each seed as `web:site` depth
`mapped` is NOT yet earned — wait for Phase 2 probing to confirm liveness.

## Phase 2 — Information gathering / recon (WSTG-INFO)

1. **Liveness + fingerprinting.** Load **`http-probing`** (httpx, whatweb,
   webanalyze; includes WAF detection with wafw00f). Probe every seed host/port,
   capture title/status/tech/TLS/CDN, detect WAFs (changes payload strategy later).
   - Output: live-sites work-units array; `assets.mark` each live base URL as
     `web:site` depth `mapped`, with tech stack in the label/notes.
2. **URL & attack-surface mapping.** Load **`web-crawling`** (katana, gau,
   hakrawler, historical URL sources). Crawl each live site (fan out with
   `for_each:` over the live-sites array), harvest URLs, forms, JS endpoints,
   API paths.
   - Output: routes work-units array; `assets.mark` each discovered route as
     `web:route` depth `crawled`.
3. **Hidden content & vhosts.** Load **`content-discovery`** (ffuf, feroxbuster,
   wordlists, recursion, vhost fuzzing). Brute-force directories, files, backup
   artifacts, admin panels, virtual hosts.
   - Output: more routes (and possibly new sites) → same work-units + `assets.mark`.
4. **Hidden parameters.** Load **`parameter-discovery`** (arjun) against the
   interesting routes (dynamic pages, APIs, anything taking input).
   - Output: route+param work units; `assets.mark` `web:route` with the `param`
     coordinate.

**Merge step (critical):** run `python3 scripts/merge_inventory.py` over all
Phase-2 arrays to produce ONE normalized engagement inventory (`sites[]`,
`routes[]` with params, `tech[]`), a master routes-to-test work-units array, and
`assets.mark` payloads. This merged array is the fan-out input for Phases 3–7.
See `references/rupu.md` for the exact command and shapes; normalize edge cases
with the **`work-units`** skill, record coverage via the **`coverage-assets`** skill.

## Phase 3 — Configuration & deployment review (WSTG-CONF) + crypto (WSTG-CRYP)

Run these in parallel across the merged inventory:

- **Known-issue sweep.** Load **`nuclei`** (template-driven: CVEs,
  misconfigurations, exposures, default logins, takeovers) and **`nikto-scan`**
  (classic server misconfig/dangerous-files scan). Feed both the full site+route
  inventory. Every nuclei match becomes a confirmation work unit — a template hit
  is a lead, not a finding, until you reproduce it through the proxy.
- **CMS-specific.** If `http-probing` fingerprinted WordPress/Joomla/Drupal/etc.,
  load **`cms-testing`** (wpscan, droopescan, plugin/theme/user enumeration).
- **TLS.** Load **`tls-testing`** (testssl.sh/sslyze: protocol versions, ciphers,
  cert issues, HSTS) — covers WSTG-CRYP-01/03 and WSTG-CONF-07.
- **Headers, cookies, clickjacking.** Load **`security-headers-testing`** (CSP,
  HSTS, X-Frame-Options/frame-ancestors, cookie flags, cache headers, CORP/COOP).

Handoff: confirmed misconfigurations → `findings.report` via the
**`finding-report`** skill (scope `endpoint` or `host`, HTTP exchange in evidence,
WSTG/CWE id). Mark swept sites/routes depth `tested`. Unconfirmed nuclei hits →
confirmation work-units array.

## Phase 4 — Identity, authentication & session (WSTG-IDNT / WSTG-ATHN / WSTG-SESS)

Load **`auth-session-testing`**. Against every login, registration, reset, SSO and
session surface in the inventory:

- Account/username enumeration, registration abuse, role provisioning.
- Credential attacks: default creds, password spraying/stuffing (hydra/ffuf
  against the login POST captured in the proxy), lockout behavior.
- Session: cookie attributes and entropy, fixation, logout/timeout, CSRF tokens.
- JWT: alg confusion, weak secrets (hashcat/jwt_tool), claim tampering.
- Password reset: token predictability, host-header poisoning of reset links.

Handoff: each verified weakness → `finding-report`. Capture at least two session
contexts (user A, user B, unauthenticated — and admin if obtainable) as proxy
sessions/cookie jars: **Phase 5 needs them.**

## Phase 5 — Authorization (WSTG-ATHZ)

Load **`access-control-testing`**. Using the multi-role sessions from Phase 4,
replay every route in the inventory across contexts:

- IDOR/BOLA: mutate object identifiers (ids, UUIDs, filenames) across users.
- BFLA / function-level: hit admin routes as low-priv/unauth; verb tampering.
- Vertical/horizontal privilege escalation; forced browsing; parameter-based
  role flags.

Handoff: each confirmed bypass → `finding-report` with the paired request/response
exchange (same request, two sessions, differing authorization outcome). Mark
exercised routes `tested`; confirmed-vulnerable routes `exploited`.

## Phase 6 — Input validation (WSTG-INPV) & server-side trust

Fan out per route+param from the merged work-units array (rupu `for_each:` or lead
agent `dispatch` — one vuln-testing child per route). Route by vulnerability class;
tech fingerprints from Phase 2 set priority (e.g. PHP → LFI/upload bias, Java →
deserialization/XXE bias, template engines → SSTI):

| Class | Sub-skill to load |
|---|---|
| SQL/NoSQL injection | **`sqli-testing`** (sqlmap, manual boolean/time/UNION/OOB) |
| XSS (reflected/stored/DOM) | **`xss-testing`** |
| OS command injection | **`command-injection-testing`** |
| XML external entities | **`xxe-testing`** |
| Server-side template injection | **`ssti-testing`** |
| Path traversal / LFI / RFI | **`path-traversal-testing`** |
| Insecure deserialization | **`deserialization-testing`** (ysoserial & friends) |
| SSRF | **`ssrf-testing`** (OOB callbacks mandatory for blind) |
| Open redirect | **`open-redirect-testing`** |
| CORS misconfiguration | **`cors-testing`** |
| Request smuggling / host header / cache poisoning | **`request-smuggling-testing`** |

Also cover WSTG-INPV-03/04 (verb tampering, parameter pollution) inline while
probing each route through the proxy.

Handoff: every tested route → `assets.mark` depth `tested` (even when clean —
that IS the coverage record). Every confirmed injection → `finding-report` with
payload, exchange, and WSTG/CWE id, and the route goes to `exploited` once proven.

## Phase 7 — Business logic (WSTG-BUSL)

Load **`business-logic-testing`**. This is manual, proxy-driven work: forge
requests, break workflow sequence (skip payment step, replay coupon, negative
quantities), race conditions on limited-use functions, integrity-check bypass.
For upload surfaces, load **`file-upload-testing`** (extension/content-type
tricks, polyglots, webshell upload, path manipulation on the stored file —
WSTG-BUSL-08/09).

Handoff: `finding-report` per confirmed logic flaw with the full exchange sequence
demonstrating the broken workflow.

## Phase 8 — Client-side (WSTG-CLNT)

Covered across skills already loaded — revisit with client-side focus:

- DOM-based XSS, JS-execution sinks, browser storage, postMessage → **`xss-testing`**.
- Client-side URL redirect → **`open-redirect-testing`**.
- Cross-origin resource sharing → **`cors-testing`**.
- Clickjacking / CSP / framing → **`security-headers-testing`**.

## Phase 9 — Exploitation & verification

Confirm, chain, and kill false positives. Everything suspected gets escalated to
proof or discarded:

- SQLi → `sqlmap --os-shell` / `--file-read` / `--dump` for impact proof
  (`sqli-testing`).
- SSRF/XXE/blind injection → OOB callback received on your interactsh listener
  is the proof (`ssrf-testing`, `xxe-testing`).
- Deserialization → gadget-chain execution with OOB or state-change evidence
  (`deserialization-testing`).
- LFI → RCE via log poisoning, PHP wrappers, or the upload surface
  (`path-traversal-testing` + `file-upload-testing`).
- Chains: open redirect → SSO token theft; CORS + session → account data read;
  smuggling → cache poisoning → stored XSS.

Rule: a scanner hit with no reproduced exchange is NOT a finding. A reproduced
exchange with demonstrated security impact IS. Mark exploited routes `exploited`.

## Phase 10 — Reporting

- Every verified issue: `findings.report` via the **`finding-report`** skill —
  scope `endpoint` with `target_ref` = affected URL (scope `host` only for
  host-wide issues like TLS), severity info..critical, `evidence.rationale`
  stating weakness + proof, the HTTP request/response exchange in evidence, and
  an OWASP (WSTG id / Top-10) or CWE classification. All three completeness
  checks of the `web` profile must pass.
- Every asset: final `assets.mark` sweep so the depth ladder reflects reality —
  use the **`coverage-assets`** skill.
- Residual leads (unconfirmed hits, untested routes): emit a final work-units
  array so a follow-up run can resume exactly where this one stopped.

## Stop-when / coverage discipline

- **Tested vs untested is explicit state, not memory.** The `assets.mark` depth
  rung per route is the coverage record. If a route never got past `crawled`, it
  was never vuln-tested — say so.
- **A clean result with budget exhausted is not proven-clean.** If time/budget
  ran out, report "no issues found in the routes reaching depth `tested`" plus
  the list of routes that did not — never "no vulnerabilities exist."
- **Stop a technique when** (a) the vuln class is confirmed and impact-proven,
  (b) the full relevant payload set ran clean through the proxy with responses
  actually read, or (c) a WAF/control blocks the class and bypass attempts from
  the relevant sub-skill's reference are exhausted — record which of the three
  applied.
- **Never silently drop a lead.** Anything suspected-but-unconfirmed becomes a
  work unit, not a deleted note.

## References & scripts

- `references/wstg-map.md` — full WSTG v4.2 test-case table → covering sub-skill.
- `references/sub-skills.md` — one-line index of every sub-skill in this pack.
- `references/rupu.md` — work-unit / assets.mark / findings.report shapes, the
  shared-skill imports, and a full rupu workflow sketch for this methodology.
- `scripts/merge_inventory.py` — merges all recon-phase work-unit arrays into one
  normalized inventory + master test fan-out array + assets.mark payloads.
