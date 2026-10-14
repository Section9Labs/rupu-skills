# Field reference — rupu finding report schema

Source of truth: `urn:rupu:schema:finding-report:v1` (draft-07). Print it live
with `rupu findings schema`. `additionalProperties: false` at the top level —
unknown keys reject the report.

**Required** (all of): `title`, `ownership`, `tickets`, `rating`, `category`,
`attack_vector`, `cwe`, `description`, `impact`, `location`, `root_cause`,
`call_chain`, `evidence`, `remediation`, `recommended_patch`,
`ci_cd_detection`, `regression_test`, `replication_steps`,
`cross_references`, `references`.
Optional: `artifacts`, `blocks`, `classifications`.
Required strings must be non-empty after trimming. `cwe` may be an empty list.

**Fields rupu fills — the agent must omit:**

- `verification` — set by verification runs; supplying it rejects the call at `report.verification`.
- `evidence[].sha256` — rupu hashes the claim's `file` at write time; anything sent is discarded.
- `artifacts[].sha256/size/kind/stored/host` — filled when rupu stores the file; supply **only `path`**.

## Section → field map

| Finding section | Schema field(s) | Type / rule | Sentinels accepted |
|---|---|---|---|
| Title | `title` | string, specific to feature + target | — |
| Asset: owner | `ownership.owner` | string; accountable team; never invented | `Unknown` |
| Asset: product | `ownership.product` | string; named app/platform/service | `Unknown` |
| Asset: component | `ownership.affected_component` | string; exact feature/endpoint/module | `Unknown` |
| Asset: repo | `ownership.source_repository` | string; canonical repo, optionally with path | `Not Applicable` (no source-controlled code involved), `Unknown` |
| Tickets | `tickets` | array of `{type*, identifier*, url?, notes?}` (min 1), only tickets present in the evidence | `None Provided` (none mentioned), `Unknown` (exists, id not given) |
| Severity: qualitative | `rating.impact`, `rating.risk_rating`, `rating.risk_factor` | enum `Low\|Medium\|High\|Critical` | — |
| Severity: likelihood | `rating.likelihood` | enum `Low\|Medium\|High` | — |
| Severity: CVSS | `rating.cvss_v3` | string: base score, optionally with vector, e.g. `9.8 (CVSS:3.1/AV:N/...)`; never invented | `Unknown` |
| Classification | `category` | string, e.g. `Injection` | — |
| Classification | `cwe` | array of `^CWE-[0-9]+$`; may be empty | — |
| Classification (extra) | `classifications[]` | `{system*, id*, vector?}` e.g. `{"system":"CVE","id":"CVE-2024-1234"}`, `{"system":"OWASP","id":"A03:2021"}`, `{"system":"ATT&CK","id":"T1190"}`; optional, additive to `cwe` | — |
| Reach | `attack_vector` | string: how the surface is reached, incl. auth / user interaction | `Unknown` |
| Narrative | `description` | Markdown: what, where, why it is a weakness | — |
| Impact / scenario | `impact` | Markdown: what an attacker achieves and why it matters | — |
| Locator: input | `location.input` | Markdown: input surface / endpoint / parameter / feature | — |
| Locator: output | `location.output` | Markdown: affected area / response / downstream system | — |
| Root cause | `root_cause` | Markdown, 1–2 sentences, the exact wrong variable/check/assumption | — |
| Entry→sink path | `call_chain` | array (min 1) of `{label*, role*: source\|hop\|sink, file?, lines? [start,end], gate?, passes_because?, binary_va?}` | `Not Provided — <justification>` |
| Evidence | `evidence` | array (min 1) of `{claim*, file?, lines? [start,end, 1≤start≤end], excerpt?, lang?, artifact?, binary_va?}`; one claim per entry; `file` workspace-relative; omit `sha256` | — |
| Typed evidence | `blocks[]` | optional; each `{kind*, …}` with kind ∈ `text, code_slice, diff, table, image, hexdump, disasm, decompile, http_exchange, scan_output, pcap_ref`; `image`/`hexdump`/`pcap_ref` name one file in `artifact.path` (stored like an artifact) | — |
| Fix: actions | `remediation` | Markdown: specific corrective actions | — |
| Fix: patch | `recommended_patch` | `{diff*, notes?}` — minimal unified diff (or binary@VA pseudo-diff) | `Not Provided — <justification>` (NOT `Unknown`) |
| Fix: pipeline check | `ci_cd_detection` | `{stage*, body*, expect*, command?}`; stage = pre-merge / nightly / release gate; expect = the failing signal | `Not Provided — <justification>` (NOT `Unknown`) |
| Fix: regression test | `regression_test` | `{body*, command*, expect_vulnerable*, expect_patched*}` — fails vulnerable, passes patched | `Not Provided — <justification>` (NOT `Unknown`) |
| Reproduction | `replication_steps` | array of strings (min 1), sequential, exact payloads and commands | — |
| Related findings | `cross_references` | `"None"` or array (min 1) of `{finding_id*, relation*: duplicate\|sibling\|prerequisite\|supersedes, note?}`; `finding_id` must be an existing `fnd_` id | `None` |
| References | `references` | Markdown: CWE, OWASP category, control references, related tickets | — |
| PoC files | `artifacts[]` | optional; `{path*}` workspace-relative; directories expand; rupu hashes/stores | — |

(`*` = required within that object.)

## Sentinel rules — exact forms only

A sentinel replaces a value only when the information **genuinely cannot be
determined**, only on the fields listed, and only in its exact form:

| Sentinel | Valid on |
|---|---|
| `Unknown` | `ownership.owner`, `ownership.product`, `ownership.affected_component`, `ownership.source_repository`, `attack_vector`, `rating.cvss_v3`, `tickets` |
| `Not Applicable` | `ownership.source_repository` only — no source-controlled code involved |
| `None Provided` | `tickets` — none are mentioned anywhere in the evidence |
| `None` | `cross_references` — no related finding |
| `Not Provided — <justification>` | `call_chain`, `recommended_patch`, `ci_cd_detection`, `regression_test`. **Em dash (—, U+2014)**, one space each side, non-empty justification. `Unknown` is NOT accepted on these four. |

## Write-time enforcement (full profile)

- Every required field present; strings non-empty after trim.
- Enums exactly as listed (case-sensitive).
- `evidence` ≥ 1 claim; `replication_steps` ≥ 1 step.
- `file` values workspace-relative; `lines` = `[start, end]`, `1 ≤ start ≤ end`.
- `cross_references[].finding_id` must be an existing finding id.
- Serialized report ≤ `[findings].report_max_bytes` (default 256 KiB) — checked
  again after artifact directories expand. Big logs → artifact + excerpt.
- Artifact paths must exist inside the workspace, be regular files (or
  directories, expanded, symlinks skipped), ≤ 500 files, ≤ 2 GiB copied total
  per report (defaults); over-size single files are recorded `stored: external`
  by reference.
- A rejected call returns **every** problem at once, each with its field path
  (e.g. `report.rating.cvss_v3`, `report.blocks[2].artifact.path`); a
  structurally malformed JSON argument surfaces as a single parse error.

Pre-flight locally: `python3 scripts/check_report.py report.json`.
