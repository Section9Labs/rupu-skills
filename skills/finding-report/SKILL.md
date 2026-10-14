---
name: finding-report
description: Turn raw assessment evidence into one complete, reproducible security finding and record it with rupu's findings.report tool — covers writing every section (title, ownership, CVSS v3.1 severity, root cause, impact, evidence, replication steps, patch, CI/CD detection, regression test, references), deriving an honest CVSS vector, using the schema's sentinels, attaching PoC artifacts and engagement assets, and validating the report before submission. Use whenever any assessment skill has confirmed a vulnerability and the result must be written up.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0"
  domain: reporting
---

# Finding Report

This is the fleet's shared reporting skill. Every assessment skill (network, web,
api, code, binary, cloud, …) hands off here once a vulnerability is confirmed.
The output is **one structured finding** recorded with rupu's `findings.report`
tool — not a Markdown file. rupu stores the record once and generates every
rendered view and the Markdown/HTML/PDF exports from it; never write a separate
report document.

References:
- `references/cvss.md` — full CVSS v3.1 metric decisions, formula, mis-scorings.
- `references/field-reference.md` — every schema field, required/enum/sentinel rules.
- `references/rupu.md` — tool invocation on each surface, profiles, assets, tags, exports.
- `references/worked-example.md` — one complete, schema-valid full-profile finding.

Helper scripts:
- `python3 scripts/cvss31.py 'CVSS:3.1/...'` — official FIRST v3.1 base-score math; also builds a vector from metric choices with `--build`.
- `python3 scripts/check_report.py report.json` — pre-flight validation of a `report` object; prints every problem with its field path, exits non-zero on any.

## The core discipline

1. **One finding = one defect.** One root cause, one report. Two injection points
   with the same underlying flaw are one finding (list both surfaces); the same
   symptom from two different defects is two findings cross-referenced to each other.
2. **Every claim is backed by evidence.** If you assert it, there is an evidence
   entry (or artifact) that proves exactly that assertion. If you cannot prove
   it, do not claim it — downgrade the wording or go collect the proof.
3. **Never invent.** Never invent an owner, a product name, a ticket id, a CVSS
   score, or a CVE. The schema provides honest sentinels precisely so you never
   have to guess: `Unknown`, `Not Applicable`, `None Provided`, `None`, and
   `Not Provided — <justification>` (em dash, non-empty justification). Use them
   in their exact form, only on the fields that accept them
   (see `references/field-reference.md`).
4. **Reproducible or it didn't happen.** Replication steps must work for a
   stranger on a clean machine: exact commands, exact payloads, exact expected
   output, in order.
5. **Record once, completely.** rupu's `full` profile rejects a report with any
   missing section and returns *every* problem at once. Run
   `scripts/check_report.py` first so the first `findings.report` call lands.

## Writing each section

Work through these in order; later sections reuse earlier decisions.

### 1. Title

Name the **vulnerable feature AND the target** — never a bare class name.

- Bad: `SQL Injection`
- Bad: `SQL Injection in web app`
- Good: `Unauthenticated SQL injection in the product-search `q` parameter on shop.example.com (/api/v1/search)`

Pattern: `<auth context> <weakness> in <feature/parameter/function> on <target host/URL/binary>`.
The title becomes the finding's derived `summary`, so it must stand alone.

### 2. Asset / locator (ownership + location)

Pin the finding to a specific place on both axes:

- `ownership`: `product` (the named application/service), `owner` (the
  accountable team — from repo CODEOWNERS, service catalog, page footer, cert
  OU; `Unknown` if genuinely undeterminable, never a guess),
  `affected_component` (the exact endpoint/module/function),
  `source_repository` (canonical repo URL, optionally `#path`; `Not Applicable`
  for a black-box target with no source involved; `Unknown` if source exists
  but can't be located).
- `location.input`: the surface the attacker touches — endpoint + method +
  parameter, listening host:port, file + line, argv/env var.
- `location.output`: where the effect lands — the response, the backend DB,
  the downstream system, the spawned process.
- For network/web/api work, also pass the **`asset`** argument alongside the
  report (e.g. kind `web:route` with `url` + `http_route` coordinates, or
  `network:service` with `host` + `port`). The owning engagement profile
  validates the finding against its completeness checks — a `network` finding
  without host+port is rejected. See `references/rupu.md`.

### 3. Severity (rating)

Fill `rating` with all five fields: `impact`, `likelihood`, `risk_rating`,
`risk_factor` (qualitative) and `cvss_v3` (quantitative).

**Derive the CVSS v3.1 base vector — do not pattern-match from a similar CVE.**
Answer the eight questions from your own engagement facts (full decision trees
in `references/cvss.md`):

1. **AV** — where must the attacker stand? Internet-reachable → `N`; same L2/local net → `A`; local shell/account → `L`; hands on hardware → `P`.
2. **AC** — beyond attacker control, must conditions be won (race, non-default config, MitM position)? No → `L`; yes → `H`. Effort/skill is NOT complexity.
3. **PR** — privileges on the *vulnerable component* before the attack? None/anonymous → `N`; basic user → `L`; admin → `H`.
4. **UI** — must another human act (click, open, visit)? No → `N`; yes → `R`.
5. **S** — does impact escape the vulnerable component's security authority into another's (SSRF reaching internal services, XSS executing in victims' browsers, VM escape)? Same authority → `U`; crossed → `C`.
6. **C / I / A** — rate each on the impacted component: total/serious loss → `H`; partial → `L`; none → `N`.

Then compute, never eyeball:

```
python3 scripts/cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
# → 9.8 CRITICAL
```

Put **score + vector** in `rating.cvss_v3`, e.g.
`9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`, and justify each
non-obvious metric choice inside `description` or `impact` (one line each).
If severity genuinely cannot be assessed, `cvss_v3` is `Unknown` — never a
guessed number. Then set the qualitative fields:

- `impact` (Low/Medium/High/Critical): worst credible business consequence.
- `likelihood` (Low/Medium/High): how probable exploitation is — reachability,
  skill needed, whether it's being scanned for in the wild.
- `risk_rating` = impact × likelihood (this drives the finding's severity in
  rupu). Keep it consistent with the CVSS band unless you can argue the
  environment up or down — and if you do, say why.
- `risk_factor`: same scale; use the same value as `risk_rating` unless the
  engagement defines them differently.

### 4. Root cause

One or two sentences naming the **single underlying defect** — the exact
variable, check, or assumption that is wrong. Not the symptom.

- Symptom (wrong): "The search endpoint returns database errors for `'` input."
- Root cause (right): "`search_handler()` interpolates the `q` request
  parameter into the SQL string with an f-string instead of binding it as a
  query parameter, so attacker input is parsed as SQL."

Test: a developer reading only `root_cause` should know which line to fix.

### 5. Impact / attack scenario

Markdown, concrete, from the attacker's seat: who the attacker is (anonymous
internet user? authenticated tenant?), what they do, what they get (which data,
which privileges, which systems), and why it matters to this product (fraud,
tenant isolation break, PII exposure, RCE pivot). Chain it: "dump of the
`users` table including bcrypt hashes → offline cracking → admin session on
`/admin`". Avoid generic "could lead to data loss" filler.

### 6. Reproduction / PoC

`replication_steps`: an ordered array of strings. Each step is one action with
the **exact command and payload**, plus the expected observation where it
proves the point. Deterministic — fixed payloads, no "fuzz until it breaks".

```json
[
  "Confirm the service: curl -s https://shop.example.com/api/v1/search?q=widget — returns JSON product list, HTTP 200.",
  "Inject a boolean condition: curl -s \"https://shop.example.com/api/v1/search?q=widget%27%20AND%20%271%27%3D%271\" — identical result set proves the quote breaks into SQL context.",
  "Extract data: sqlmap -u 'https://shop.example.com/api/v1/search?q=widget' -p q --batch --dump -T users — dumps the users table."
]
```

Working PoC scripts, raw tool output, harnesses go in `artifacts[]` as
workspace-relative paths — supply only `path`, rupu hashes and stores them
(`{"artifacts": [{"path": "poc/sqli_dump.py"}]}`). Reference an artifact from
the evidence claim it proves.

### 7. Evidence

`evidence[]`: minimal annotated proof, **one claim per entry**, each entry an
atomic, checkable statement tied to the thing proving it:

```json
{
  "claim": "The q parameter is concatenated into the SQL statement without parameterization.",
  "file": "src/api/search.py",
  "lines": [41, 44],
  "excerpt": "query = f\"SELECT id,name,price FROM products WHERE name LIKE '%{q}%'\"\ncur.execute(query)",
  "lang": "python"
}
```

Rules: `excerpt` carries only the lines that matter; `lines` is `[start, end]`
with `1 <= start <= end`; `file` is workspace-relative; use `artifact` to point
at a stored PoC file, `binary_va` for binary-only targets. **Omit `sha256`** —
rupu hashes the file itself. For engagement profiles, add typed `blocks[]`
(e.g. an `http_exchange` block with full request/response for web/api, a
`scan_output` block for network) — several profiles *require* one
(see `references/rupu.md`). Split compound claims: "parameter reaches SQL
unescaped" and "endpoint requires no authentication" are two entries.

### 8. Call chain

`call_chain[]`: the ordered path from the externally reachable entry point to
the sink. First element `role: "source"`, last `role: "sink"`, hops between;
each has `label` (function/surface name) and optionally `file`, `lines`,
`binary_va`, and `gate`/`passes_because` for each precondition crossed and why
it passes. For a pure black-box finding where the internal path is
undeterminable: `"Not Provided — black-box assessment; server-side code path not observable"`.

### 9. Remediation (four parts)

- `remediation` (Markdown): specific corrective actions, primary fix first,
  then defense-in-depth. Name the exact API/mechanism ("bind `q` with
  `cur.execute(sql, (q,))`"), not "sanitize input".
- `recommended_patch`: a **minimal unified diff** against the source repository
  (correct paths, `---`/`+++`/`@@` hunks), `notes` for alternatives. Binary
  target → a `binary@VA` pseudo-diff. Can't produce one →
  `"Not Provided — <justification>"` (e.g. no source access). `Unknown` is NOT
  accepted here.
- `ci_cd_detection`: a pipeline check that fails the build while this class of
  issue is present — `stage` (pre-merge / nightly / release gate), `body` (the
  rule verbatim: semgrep/CodeQL rule, nuclei template, test), `expect` (the
  failing signal), optional `command`. Or the `Not Provided — …` sentinel.
- `regression_test`: a deterministic test that **fails on the vulnerable build
  and passes on the patched one** — `body`, `command`, `expect_vulnerable`,
  `expect_patched`. Or the `Not Provided — …` sentinel.

### 10. Classification and references

- `category`: the finding class, e.g. `Injection`, `Broken Access Control`.
- `cwe[]`: the most specific CWE ids from cwe.mitre.org that match the root
  cause (e.g. `["CWE-89"]`, not just `CWE-20`). May be empty, never guessed.
- `attack_vector` (string, distinct from CVSS AV): how the surface is reached
  including auth/interaction required, e.g.
  `"Remote, unauthenticated, via public HTTPS endpoint"`.
- `classifications[]` (optional, engagement profiles): other taxonomies —
  `{"system":"OWASP","id":"A03:2021"}`, `{"system":"CVE","id":"CVE-2024-1234"}`,
  `{"system":"ATT&CK","id":"T1190"}`. Include a CVE only when the target
  demonstrably runs that vulnerable component — never speculative.
- `references` (Markdown, required): CWE links, OWASP category (Top 10 2021 /
  API Security Top 10 2023 / WSTG test id), vendor advisories, control refs.
- `tickets`: tickets actually present in the evidence; `None Provided` when
  none are mentioned; `Unknown` when one exists but its id wasn't given.
  Never invent one.
- `cross_references`: `"None"`, or an array of
  `{finding_id: "fnd_…", relation: duplicate|sibling|prerequisite|supersedes, note?}`
  pointing at ids returned by previous `findings.report` calls.

## Recording the finding

1. Assemble the `report` object (every required field — see
   `references/field-reference.md`). **Omit** `verification`, evidence `sha256`,
   and artifact `sha256/size/kind/stored/host` — rupu fills those and rejects a
   call that supplies `verification`.
2. Validate locally: `python3 scripts/check_report.py report.json` — fix every
   printed field path.
3. Call the tool (`findings.report`, aliases `findings.record` /
   `report_finding`), under the `full` profile (the default):

```json
{
  "report": { "…": "the complete report object" },
  "asset": {
    "kind": "api:endpoint",
    "coordinates": [
      {"t": "url", "v": "https://shop.example.com"},
      {"t": "http_route", "v": {"method": "GET", "path": "/api/v1/search"}},
      {"t": "param", "v": "q"}
    ],
    "label": "shop.example.com GET /api/v1/search?q"
  },
  "tags": ["sqli", "api"]
}
```

   Under `full`, top-level `summary`/`severity`/`evidence` arguments are
   **rejected** — rupu derives them (`summary` ← `title`, `severity` ←
   `rating.risk_rating`, evidence rationale ← `root_cause`). In a workflow the
   same payload goes in an `action: findings.record` step; over MCP it is the
   same tool via `rupu mcp serve`. See `references/rupu.md`.
4. A rejected call returns **every** problem with its field path — fix all and
   retry once. Keep the serialized report under 256 KiB (default
   `report_max_bytes`): excerpt logs, attach the full capture as an artifact.
5. Save the returned `fnd_` id for `cross_references` in related findings and
   for `findings.tag`.
6. If relevant, also record examination depth with `assets.mark`
   (e.g. `depth: "exploited"`).

## Pre-submission checklist

- [ ] Title names feature + target; a stranger can locate the bug from it.
- [ ] Ownership real or sentinel — nothing invented.
- [ ] CVSS vector computed with `scripts/cvss31.py`; score matches vector; each metric defensible from the evidence; qualitative ratings consistent.
- [ ] Root cause names the defect (variable/check/assumption), not the symptom.
- [ ] Every evidence entry = one claim + the proof of exactly that claim.
- [ ] Replication steps run top-to-bottom on a clean machine with exact payloads.
- [ ] Patch is a valid minimal unified diff; regression test fails-vulnerable/passes-patched; CI/CD check has stage+body+expect.
- [ ] All sentinels in exact form (em dash in `Not Provided — …`).
- [ ] `scripts/check_report.py` passes clean.
