# Field Reference — rupu `findings.report`

This is the field-by-field mapping from the general finding methodology in
[SKILL.md](../SKILL.md) onto rupu's `findings.report` tool (schema
`urn:rupu:schema:finding-report:v1`, as printed by `rupu findings schema`).
You call `findings.report` **once** with the complete finding object.
Presentations and exports (Markdown, HTML, PDF) are generated from the recorded
report — no separate report file is written. A `report_finding` call returns a
`fnd_` id you can use later in `cross_references`.

The schema sets `additionalProperties: false` at the top level and inside most
objects: send exactly the fields listed, no extras.

## Honest sentinels

When information genuinely cannot be determined, use the field's sentinel
**instead of omitting the field** (most fields are required):

| Sentinel | Meaning | Used by |
|---|---|---|
| `Unknown` | Exists but could not be determined | `ownership.owner`, `ownership.product`, `ownership.affected_component`, `ownership.source_repository`, `rating.cvss_v3`, `attack_vector`, `tickets` (id not given) |
| `Not Applicable` | The concept does not apply here | `ownership.source_repository` (no source-controlled code involved) |
| `None Provided` | Nothing was mentioned in the evidence | `tickets` |
| `None` | Explicitly nothing | `cross_references` |
| `Not Provided — <justification>` | You are not supplying this, and here is why | `call_chain`, `recommended_patch`, `ci_cd_detection`, `regression_test` |

The `Not Provided — ` string must be followed by a non-empty justification
(schema pattern `^Not Provided — \S`; note the em-dash `—`). Never invent an
owner, score, repository, ticket, or CVE to avoid a sentinel.

## Required top-level fields

All of these are **required**: `title`, `ownership`, `tickets`, `rating`,
`category`, `attack_vector`, `cwe`, `description`, `impact`, `location`,
`root_cause`, `call_chain`, `evidence`, `remediation`, `recommended_patch`,
`ci_cd_detection`, `regression_test`, `replication_steps`,
`cross_references`, `references`.

Optional: `artifacts`, `blocks`, `classifications`, `verification`.

## Field-by-field

### `title` (string)
Short title specific to the vulnerable feature and target
(SKILL.md §1). `<defect class> in <feature/parameter> on <product/host>`.

### `ownership` (object; all four keys required)
SKILL.md §2, the asset half of the locator.

| Key | Content | Sentinels |
|---|---|---|
| `owner` | Accountable team/service owner. **Never invent one.** | `Unknown` |
| `product` | Named application/platform/service | `Unknown` |
| `affected_component` | Exact feature/endpoint/module | `Unknown` |
| `source_repository` | Canonical repository, optionally with a path | `Not Applicable`, `Unknown` |

### `location` (object; `input` and `output` required, Markdown)
SKILL.md §2, the surface half of the locator.

- `input` — the input surface: endpoint + method + parameter, feature, field.
- `output` — the affected area: response, downstream system, data store.

### `rating` (object; all five keys required)
SKILL.md §3.

- `impact` — enum `Low | Medium | High | Critical`
- `likelihood` — enum `Low | Medium | High`
- `risk_rating` — enum `Low | Medium | High | Critical`; **drives the finding's severity** in rupu.
- `risk_factor` — enum `Low | Medium | High | Critical`; the combined
  impact×likelihood judgement (usually equals `risk_rating`; they differ when
  business context overrides the matrix — explain the difference in `impact`).
- `cvss_v3` — string: base score **with the full vector**, e.g.
  `8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)`, or `Unknown`.
  **Never invent a score.** Put the per-metric rationale in `description` or
  `impact` so the score is auditable.

### `category` (string)
The finding class in your engagement's taxonomy, e.g.
`Injection`, `Broken Access Control`, `Sensitive Data Exposure`,
`Security Misconfiguration`. One short phrase.

### `attack_vector` (string)
One summary line: how the surface is reached, including authentication or user
interaction required (SKILL.md §5), or `Unknown`. E.g.
`Remote, unauthenticated HTTPS request to a public endpoint; no user interaction.`

### `cwe` (array of strings)
CWE ids matching `^CWE-[0-9]+$`, most specific first, e.g. `["CWE-89"]`.
May be empty (`[]`) only when truly none applies.

### `classifications` (array, optional)
Additional taxonomies, additive to `cwe`:
`{"system": "CVE", "id": "CVE-2024-1234"}`,
`{"system": "ATT&CK", "id": "T1190"}`,
`{"system": "OWASP", "id": "A03:2021"}`. Optional `vector` string per entry
(e.g. a CVSS vector attached to a CVE).

### `description` (string, Markdown)
SKILL.md §5: what the issue is, where it occurs, why it is a weakness. Facts
only; cite evidence entries. A good place for the per-metric CVSS rationale.

### `impact` (string, Markdown)
SKILL.md §5: what an attacker could achieve and why it matters — the one place
for labeled inference and the realistic attack scenario.

### `root_cause` (string, Markdown, 1–2 sentences)
SKILL.md §4: the single underlying defect, naming the exact variable, check, or
assumption that is wrong — not the symptom.

### `call_chain` (array of hops, or `Not Provided — <justification>`)
SKILL.md §6. Each hop:

| Key | Req | Content |
|---|---|---|
| `label` | yes | Function or surface name |
| `role` | yes | enum `source | hop | sink` |
| `file` | no | Workspace-relative path |
| `lines` | no | `[start, end]` — exactly two integers |
| `binary_va` | no | `binary@VA` for binary-only targets |
| `gate` | no | Precondition crossed at this hop |
| `passes_because` | no | Why the gate passes |

First hop is the externally reachable `source`; last is the `sink`. Minimum
one hop.

### `replication_steps` (array of strings, min 1)
SKILL.md §7: sequential, copy-pasteable steps with exact payloads and commands.
One step per array element, in order; final step states what success looks like.

### `evidence` (array, min 1)
SKILL.md §8: minimal annotated proof, **one claim per entry**.

| Key | Req | Content |
|---|---|---|
| `claim` | yes | The single checkable statement this entry proves |
| `excerpt` | no | Only the lines that matter |
| `file` | no | Workspace-relative path the excerpt comes from |
| `lines` | no | `[start, end]` line range in `file` |
| `lang` | no | Highlighting language, e.g. `python`, `http`, `sh` |
| `artifact` | no | `path` of an entry in `artifacts` that proves this claim |
| `binary_va` | no | Binary address for binary evidence |
| `sha256` | — | Set by rupu; **omit** |

### `artifacts` (array, optional)
PoC files, raw outputs, screenshots, harnesses — workspace-relative paths;
rupu copies and stores them with the finding. **Supply only `path`** per entry;
`kind`, `sha256`, `size`, `stored`, `host` are managed by rupu.

### `blocks` (array, optional)
Typed evidence blocks for engagement profiles, additive to `evidence`. Each
object has a `kind` tag — one of `text`, `code_slice`, `diff`, `table`,
`image`, `hexdump`, `disasm`, `decompile`, `http_exchange`, `scan_output`,
`pcap_ref` — plus that kind's fields, e.g.
`{"kind": "http_exchange", "request": "...", "response": "..."}` or
`{"kind": "scan_output", "tool": "nmap", "output": "..."}`.

### `remediation` (string, Markdown)
SKILL.md §9 prose: specific corrective actions, direct fix first.

### `recommended_patch` (object, or `Not Provided — <justification>`)
- `diff` (required) — minimal unified diff against the source repository, or a
  `binary@VA` pseudo-diff for binary-only targets.
- `notes` (optional, Markdown) — alternatives, or the equivalent source-level
  change for a binary pseudo-diff.

### `ci_cd_detection` (object, or `Not Provided — <justification>`)
- `stage` (required) — `pre-merge` / `nightly` / `release gate`.
- `body` (required, Markdown) — the rule or test, **verbatim**.
- `expect` (required) — the failing signal (what the pipeline reports when the
  issue is present).
- `command` (optional) — how to run it.

### `regression_test` (object, or `Not Provided — <justification>`)
- `body` (required) — the test, verbatim.
- `command` (required) — how to run it.
- `expect_vulnerable` (required) — output on the vulnerable build (test FAILS).
- `expect_patched` (required) — output on the patched build (test PASSES).

### `tickets`
`"None Provided"` when no existing ticket is mentioned in the evidence;
`"Unknown"` when one exists but its id was not given; otherwise an array of
`{"type": "Jira|Bug|Remediation Tracker|Vulnerability Management|Other",
"identifier": "...", "url": "...", "notes": "..."}` (`type` and `identifier`
required). **Never invent a ticket.**

### `cross_references`
`"None"`, or an array of
`{"finding_id": "fnd_...", "relation": "duplicate|sibling|prerequisite|supersedes", "note": "..."}`
(`finding_id` and `relation` required). The `fnd_` id is what a previous
`report_finding` call returned.

### `references` (string, Markdown)
SKILL.md §10: CWE links, OWASP category, CVE/vendor advisories, control
references, related tickets — as a Markdown list.

### `verification` (object, optional)
- `status` (required) — enum `unverified | confirmed | disputed | inconclusive`.
  Use `confirmed` only when the replication steps were executed successfully.
- `by_agent`, `by_run`, `notes` — optional provenance.

## Call shape (minimal skeleton)

```json
{
  "title": "…",
  "ownership": {"owner": "…", "product": "…", "affected_component": "…", "source_repository": "…"},
  "tickets": "None Provided",
  "rating": {"impact": "High", "likelihood": "High", "risk_rating": "High", "risk_factor": "High",
             "cvss_v3": "8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)"},
  "category": "…",
  "attack_vector": "…",
  "cwe": ["CWE-…"],
  "description": "…",
  "impact": "…",
  "location": {"input": "…", "output": "…"},
  "root_cause": "…",
  "call_chain": [{"label": "…", "role": "source"}, {"label": "…", "role": "sink"}],
  "evidence": [{"claim": "…", "excerpt": "…"}],
  "artifacts": [{"path": "poc/exploit.py"}],
  "remediation": "…",
  "recommended_patch": {"diff": "--- a/… \n+++ b/… \n…"},
  "ci_cd_detection": {"stage": "pre-merge", "body": "…", "expect": "…"},
  "regression_test": {"body": "…", "command": "…", "expect_vulnerable": "…", "expect_patched": "…"},
  "replication_steps": ["…", "…"],
  "cross_references": "None",
  "references": "- …",
  "verification": {"status": "confirmed"}
}
```

See [worked-example.md](worked-example.md) for a fully filled-in finding.
