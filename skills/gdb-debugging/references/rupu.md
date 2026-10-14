# rupu wiring for gdb-debugging

How results from this skill flow into rupu. Do not reinvent mechanics — import the
shared skills named below.

## Assets (`assets.mark`)

Asset model for the binary-analysis pack:

- kind `binary:file` — coordinate `t=file`, `v=<sha256 or path>` of the target binary.
  Depth ladder (monotonic, never lower): `discovered -> triaged -> analyzed ->
  vuln-identified -> exploited`.
- kind `binary:symbol` — coordinates: the file coordinate PLUS `t=symbol`,
  `v=<name>` (or `t=vaddr`, `v=0x...` for stripped binaries) for interesting
  functions/sinks.

Marks this skill makes:

| Event in gdb | Mark |
|---|---|
| Reproduced a crash (SIGSEGV/SIGABRT) with controlled input | `binary:file` → `vuln-identified` |
| Confirmed offset to saved RIP / controlled pointer / corrupted chunk | `binary:file` → `vuln-identified`, plus `binary:symbol` for the vulnerable function (`backtrace` frame or `xinfo $rip`) at `vuln-identified` |
| Got a shell / arbitrary code exec via the primitive | `binary:file` → `exploited` |
| Only inspected, no crash | `binary:file` → `analyzed` |

## Findings (`findings.report`)

Report every confirmed crash/primitive with rupu's `findings.report` tool. Field
contract lives in the shared **`finding-report`** skill — follow it; do not write a
separate report file. Minimum content for a crash finding:

- title: e.g. "Stack buffer overflow in ./httpd parse_header — saved RIP control at offset 72"
- the target coordinate (same as the asset mark),
- the primitive: offset, which register/slot is controlled, signal, mitigations
  (`checksec` output), pattern length used,
- repro: exact input (`run < pattern.bin`, pattern length, mode stdin/argv), gdb
  commands to re-observe,
- evidence paths (below).

`scripts/gdb_offset.py` prints a one-line JSON finding stub (`FINDING-STUB: {...}`)
with these fields pre-filled — paste/adapt it into `findings.report`.

## Work units

This skill is usually the CONSUMER of work units emitted by `dynamic-tracing` /
`vuln-classes`. If a gdb session itself fans out follow-ups (e.g. one unit per
suspicious function found via backtraces), emit a JSON array file of
`{id, title, targets, hints}` objects per the shared **`work-units`** skill —
hints sorted, e.g. `["heap-exploitation", "pwntools"]`.

## Evidence

Keep ALL raw artifacts under the run workspace; never delete:

- gdb transcripts: `gdb ... | tee evidence/gdb-session-$(date +%s).log` or
  `set logging file evidence/gdb.log` + `set logging enabled on`,
- the crashing input file (the exact pattern bytes),
- core dumps (`ulimit -c unlimited`; cores land per `/proc/sys/kernel/core_pattern`),
- `scripts/gdb_offset.py` output (it writes its gdb transcript next to its temp
  input and prints both paths).
