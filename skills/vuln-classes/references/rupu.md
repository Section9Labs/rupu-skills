# rupu wiring for vuln-classes

This skill parses crash reports / debugger output (via
`scripts/classify_crash.py`) and must end by producing rupu-ingestible
data. Use the shared `work-units` and `finding-report` skills for the
generic mechanics; this file maps classification results onto them.

## Assets: assets.mark

Classification is the step that earns the `vuln-identified` depth on the
binary-profile ladder `discovered -> triaged -> analyzed -> vuln-identified
-> exploited` (monotonic — never lower a depth):

- `binary:file` — coordinate `t=file`, `v=<sha256 of the binary>` (or path
  if unhashable). Mark `vuln-identified` once at least one class is
  confirmed with a reproducer; it was `triaged`/`analyzed` by the upstream
  `fuzzing` / RE skills.
- `binary:symbol` — the file coordinate plus `t=symbol`,
  `v=<vulnerable function>` (stripped binaries: `t=vaddr`, `v=0x401100`).
  Mark the faulting/vulnerable function `vuln-identified`; also mark
  interesting sinks spotted statically (a `printf(user)` call site, an
  unguarded `malloc(n*m)`) at `analyzed` even before dynamic confirmation.

`exploited` is set later by `rop-chains` / `heap-exploitation` /
`format-string-exploitation` / `pwntools`, never by this skill.

## Findings: findings.report

A **confirmed** class (signature + dynamic confirmation per the class's
step (c)) is a finding. Report with rupu's `findings.report` using the
field contract from the shared `finding-report` skill. The script's
`--json finding.json` stub supplies the core fields:

```json
{
  "title": "heap buffer overflow in parse_chunk",
  "vuln_class": "heap-overflow",
  "primitive": "adjacent-chunk data/metadata corruption",
  "binary": "/work/targets/example_parser",
  "faulting_function": "parse_chunk",
  "frames": ["parse_chunk", "parse_file", "main"],
  "evidence_excerpt": "ERROR: AddressSanitizer: heap-buffer-overflow ...",
  "next_skills": ["heap-exploitation", "pwntools"],
  "status": "identified"
}
```

Add before reporting: the reproducing input (path), the exact replay
command, the protection matrix (`checksec` output — it drives severity),
and the exploitability assessment (primitive + what blocks it). Severity
by primitive: PC control / arbitrary write > constrained write > leak >
DoS-only.

A `status: identified-unconfirmed` stub (class "unknown") is NOT a finding
— it goes back into the queue as a work unit for `gdb-debugging`.

## Work units (when fan-out continues)

If classification yields multiple distinct vulnerable functions/sites,
emit a JSON array (file starts with `[`, consumable by rupu `for_each:`;
see the `work-units` skill), one unit per site, exactly
`{id, title, targets, hints}`:

- `id`: slug `"<class>-<function>"`, e.g. `format-string-log-msg`.
- `targets`: `[{file, faulting_function, vuln_class, primitive,
  crash_input_path?}]` — non-empty.
- `hints`: sorted; the exploitation skill from the class table
  (`rop-chains`, `heap-exploitation`, `format-string-exploitation`),
  plus `gdb-debugging` and `pwntools`.

Upstream, the `fuzzing` skill's `triage_crashes.py` already emits units
hinting at `vuln-classes`; this skill consumes those units, upgrades the
hints to the concrete exploitation skill, and reports findings.

## Evidence retention

Keep under the run workspace: every ASan report and gdb session log used
for classification, the `finding.json` stubs, `checksec` output, annotated
disassembly excerpts (the call-site signature), and the reproducing
inputs. Never delete raw output.
