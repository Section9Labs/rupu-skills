---
name: finding-report
description: Turn raw assessment evidence into a complete, reproducible security finding — title, asset/locator, severity with a justified CVSS v3.1 vector, root cause, impact, call chain, step-by-step PoC, annotated evidence, concrete remediation (patch diff, CI/CD gate, regression test), and references — and record it with a structured target such as rupu's findings.report.
license: MIT
metadata:
  author: vulture (coral-marsh)
  domain: reporting
---

# Writing a Complete Security Finding

A finding is finished when another engineer — who was not on the assessment — can
read it, reproduce it, score it the same way you did, and fix it, without asking
you a single question. Everything below serves that test.

Work in this order. Each section of the finding does exactly one job; do not let
content leak between sections.

## 0. Before you write: inventory the evidence

List what you actually have: requests/responses, tool output, source files and
line numbers, screenshots, PoC scripts, logs. Every claim you will make in the
finding must trace back to one of these. Anything you cannot trace is either
dropped or explicitly marked as inference. If a required fact genuinely cannot
be determined (the owner, the CVSS score, a ticket id), use an honest sentinel —
`Unknown`, `Not Applicable`, `None Provided`, `None`, or
`Not Provided — <justification>` — never a plausible-sounding invention.
Fabricated owners, scores, repository names, or ticket ids destroy the report's
credibility and misroute the fix.

## 1. Title

Name the vulnerable **feature** and the **target**, not the vulnerability class.

- Bad: "SQL Injection" / "Broken Access Control"
- Good: "SQL injection in the `order_id` parameter of `/api/v2/orders` on shop.example.com"
- Good: "Unauthenticated access to the Grafana admin API on 203.0.113.20:3000"

Formula: `<defect class> in <exact feature/parameter/endpoint> on <product/host>`.
One line; a reader scanning fifty titles must be able to tell this finding from
every sibling finding on the same host.

## 2. Affected asset / locator

Pin down where the bug lives and who must fix it:

- **Product** — the named application/platform/service ("Acme Storefront v3.4"), or `Unknown`.
- **Owner** — the accountable team or service owner, only if the evidence or the
  engagement brief names one. Never guess an owner; use `Unknown`.
- **Affected component** — the exact feature, endpoint, module, or binary
  (`orders-api`, `POST /api/v2/orders`, `libparse.so`), or `Unknown`.
- **Source repository** — canonical repo, optionally with a path
  (`git.example.com/acme/orders-api @ src/db/query.py`); `Not Applicable` when
  no source-controlled code is involved (e.g. a misconfiguration of a COTS
  appliance); `Unknown` when source exists but you could not identify it.
- **Location — input**: the input surface the attacker controls: endpoint +
  method + parameter, file format field, CLI flag, header, feature.
- **Location — output**: where the effect lands: the response, the backend
  database, a downstream service, the filesystem, another user's browser.

Input and output together are the locator a fixer greps for first. Be exact:
`the "redirect" query parameter of GET /login`, not "the login page".

## 3. Severity: impact × likelihood + CVSS v3.1

Severity is a judgement you must be able to defend from the evidence. Produce
three things: a qualitative **impact** and **likelihood**, a **CVSS v3.1 base
score with its full vector string**, and the **rationale** for each metric.

### Qualitative rating

- **Impact** (Low/Medium/High/Critical): what the worst realistic outcome is —
  data classes exposed, integrity of what, availability of what, blast radius.
- **Likelihood** (Low/Medium/High): how easy and how probable exploitation is —
  reachability, authentication required, exploit complexity, whether it is
  already being scanned for in the wild.
- **Risk rating** = impact combined with likelihood. Rough matrix: Critical
  impact + Medium/High likelihood → Critical; High impact + High likelihood →
  Critical or High; High + Low → High or Medium; Medium + Medium → Medium;
  Low impact → Low unless likelihood is High and it chains (then Medium).
  State the one-sentence reason next to the rating.

### CVSS v3.1 base vector — pick each metric from evidence

Walk the eight base metrics and tie each choice to a fact in the finding:

- **AV (Attack Vector)**: `N` network — reachable over the network/Internet
  (your PoC ran a remote request); `A` adjacent — same L2/local network segment
  required; `L` local — needs local shell/login or a user opening a file;
  `P` physical.
- **AC (Attack Complexity)**: `L` low — works every time with no conditions
  outside the attacker's control (the normal case when your PoC is
  deterministic); `H` high — requires winning a race, MitM position, or
  target-specific secrets/configuration the attacker must separately obtain.
- **PR (Privileges Required)**: `N` none — unauthenticated; `L` — any basic
  user account suffices; `H` — admin-level privileges needed before exploiting.
  Base this on what your PoC actually needed, not on what the docs say.
- **UI (User Interaction)**: `N` none; `R` — a victim must click/open/visit
  something (reflected XSS, CSRF, malicious document).
- **S (Scope)**: `U` unchanged — the impact stays inside the vulnerable
  component's own security authority; `C` changed — exploitation crosses into a
  different authority: XSS executing in victims' browsers, container/VM/sandbox
  escape, an SSRF reaching internal services the web app itself is not
  authorized to reach.
- **C / I / A (Confidentiality / Integrity / Availability)**: `H` total or
  serious loss (all rows of the DB, arbitrary write, full crash); `L` limited
  loss (some data, constrained modification, partial degradation); `N` none.
  Score only what the vulnerability itself yields, not what a chained follow-on
  attack might yield — put chains in the Impact narrative instead.

Compute the score with the FIRST calculator
(https://www.first.org/cvss/calculator/3.1) or any faithful implementation —
do not do the arithmetic by hand. Record **both** the number and the vector:

```
8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)
```

Score-to-rating map: 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0
Critical. If the qualitative rating and the CVSS band disagree, say why (e.g.
business context raises it). **Never invent a score.** If you cannot defend a
metric choice from evidence, write the rating fields you can defend and set the
CVSS field to `Unknown`.

Write the rationale as one line per metric:
`AV:N — exploited remotely from 203.0.113.9 with a single HTTP request; PR:N — no session cookie or token was sent; ...`

## 4. Root cause

One or two sentences naming the **single underlying defect**: the exact
variable, check, or assumption that is wrong. Not the symptom.

- Symptom (wrong): "The endpoint returns other users' data."
- Root cause (right): "`get_order()` in `src/api/orders.py:88` builds the SQL
  query by f-string interpolation of the request's `order_id` and never
  parameterizes it; the authorization check compares against
  `request.args['user_id']` (attacker-controlled) instead of the session user."

If you can point at a file and line, do. If the exact defect is not provable
from the evidence, state the most specific defect the evidence supports and say
what remains unconfirmed.

## 5. Description, impact, and attack scenario

- **Description**: what the issue is, where it occurs, and why it is a weakness
  — the technical narrative, 1–3 paragraphs, written for an engineer who has
  never seen the system. Facts only; cite the evidence entries.
- **Impact**: what an attacker actually achieves, under which preconditions,
  and why the business cares. This is the one section where inference is
  allowed — label it as such ("an attacker who obtains X could then…"). Name
  the concrete data classes/systems at stake (customer PII, payment records,
  the internal metadata service), not abstractions ("sensitive data").
- **Attack scenario**: one realistic end-to-end story: attacker's starting
  position → steps → outcome. Keep speculative chaining honest and brief.
- **Attack vector** (summary line): how the surface is reached and what
  authentication/user interaction is required, e.g. "Remote, unauthenticated
  HTTPS request to a public endpoint; no user interaction."

## 6. Call chain / attack path

The ordered path from the externally reachable **entry point (source)**,
through intermediate **hops**, to the vulnerable **sink**. For each step give
the function/surface name, the file and line range (or `binary@VA` for
binary-only targets), any **gate** (precondition/check) crossed at that hop,
and **why the gate passes**. Example:

1. `POST /api/v2/orders` → `routes.py:41 handle_order()` — *source*
2. `handle_order()` → `orders.py:70 get_order()` — gate: `@login_required` — passes because the decorator is missing on this route
3. `get_order()` → `db/query.py:88 cursor.execute(f"...{order_id}...")` — *sink*

For non-source targets the chain can be protocol-level: network entry → service
→ parser → vulnerable routine. If you genuinely cannot establish the chain,
write `Not Provided — <justification>` (e.g. "binary not available for
analysis; behavior confirmed black-box only").

## 7. Reproduction / proof of concept

Sequential, numbered, **copy-pasteable** steps with exact payloads, exact
commands, full URLs/hosts/ports, and required preconditions (accounts, tokens,
build/version). End with what a successful result looks like, verbatim:

1. `export TARGET=https://203.0.113.20`
2. `curl -sk "$TARGET/api/v2/orders?order_id=1%20OR%201=1" -o out.json`
3. Observe `out.json` contains rows for user ids other than your own; e.g. `"user_id": 7` while authenticated as user 42.

Rules: no step may depend on undocumented state; every placeholder is declared;
include the version/commit tested so the repro stays valid; prefer one minimal
path over three variants. If a PoC script exists, reference it as an artifact
and still include the one-command invocation inline.

## 8. Evidence — one claim per entry

Evidence is the fact layer of the report. Discipline:

- **One claim per entry.** Each entry asserts exactly one checkable statement
  ("The endpoint responds 200 without an Authorization header"), paired with
  the minimal proof: a request/response excerpt, a log line, a source excerpt
  with file + line range (and language for highlighting), or a pointer to an
  attached artifact.
- **Only the lines that matter.** Trim excerpts to the 3–15 lines that prove
  the claim; elide the rest with `…`. A 400-line dump proves nothing.
- **Annotate, don't narrate.** The claim says what the excerpt shows; the
  excerpt shows it. No interpretation inside the excerpt.
- Redact credentials/session tokens in excerpts (`Authorization: Bearer <redacted>`)
  unless the token's content *is* the finding.
- **Artifacts** are the files behind the evidence: PoC scripts, raw outputs,
  screenshots, pcaps — attached by path so the record is self-contained. Each
  evidence entry that relies on a file names the artifact that proves it.

Typical minimal set: (1) the request that triggers the bug, (2) the response/
behavior proving it, (3) the source lines of the defect (when available),
(4) the PoC script/output artifact.

## 9. Remediation — fix, gate, test

Four deliverables; use `Not Provided — <justification>` only when one is
genuinely impossible, never because it is effort:

- **Remediation (prose)**: specific corrective actions in priority order — the
  direct fix first, then hardening (defense in depth), then detection. "Use
  parameterized queries in `get_order()`; additionally enforce the session user
  in the WHERE clause; add a WAF rule as interim mitigation" — not "sanitize
  inputs".
- **Recommended patch**: a **minimal unified diff** against the source
  repository that fixes the root cause and nothing else. For binary-only
  targets, a `binary@VA` pseudo-diff plus notes on the equivalent source-level
  change. Keep it reviewable: a handful of hunks, no refactoring.
- **CI/CD detection**: a pipeline check that fails the build whenever this
  *class* of issue reappears — a semgrep/CodeQL rule, a linter config, a
  dependency/version gate, or a scripted probe. Give the stage (pre-merge /
  nightly / release gate), the rule or command verbatim, and the failing signal
  to expect.
- **Regression test**: deterministic, automated, and asymmetric — it **fails on
  the vulnerable build and passes on the patched one**. Give the test body,
  the command to run it, and the expected output in each state. A test that
  passes on both builds is decoration, not a regression test.

## 10. References and cross-links

- **CWE** id(s) for the defect class (e.g. `CWE-89`), the most specific that fits. May be empty only when truly none applies.
- **CVE**(s) when the issue is a known vulnerability in a third-party component.
- **OWASP** category (Top 10 / ASVS / API Top 10) when relevant.
- Vendor advisories, standards, internal control references.
- **Tickets**: only tickets that actually appear in the evidence or brief.
  `None Provided` when none is mentioned; `Unknown` when one exists but its id
  was not given. Never invent a ticket.
- **Cross-references**: related findings in the same engagement, with the
  relation (duplicate / sibling / prerequisite / supersedes); `None` otherwise.
- **Verification status**: `confirmed` when you reproduced it yourself;
  `unverified` / `inconclusive` / `disputed` as the facts dictate.

## Writing standards (apply throughout)

1. **Specific beats general.** Exact hosts, paths, parameters, versions, line numbers.
2. **Reproducible beats persuasive.** If the repro steps work, the finding stands; adjectives add nothing.
3. **Separate fact from inference.** Evidence sections contain only what was observed; Impact may extrapolate, labeled as extrapolation.
4. **Never fabricate.** Scores, owners, repos, tickets, CVEs — use the honest sentinels when unknown.
5. **One job per section.** Root cause is not a second impact statement; description is not a second repro.
6. **Minimal evidence, fully attached.** Few entries, each decisive; raw files as artifacts.
7. **Write for the fixer.** Assume a competent engineer with zero context on your assessment.

## Recording the finding

This methodology maps 1:1 onto structured recording targets. One supported
target is **rupu's `findings.report` tool**: you call it once with the complete
finding object and rupu stores it; Markdown/HTML/PDF presentations are
generated from the recorded report, so you do not write a separate report file.
The exact field names, nesting, required fields, enums, and sentinel rules —
and the mapping from every section above onto them — are in
[references/field-reference.md](references/field-reference.md).

A complete worked example (every section filled in, CVSS rationale,
patch diff, regression test) is in
[references/worked-example.md](references/worked-example.md).
