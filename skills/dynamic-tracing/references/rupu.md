# rupu wiring for dynamic-tracing

How trace observations flow into rupu. Import the shared skills named below for
mechanics; this file only states what THIS skill emits.

## Work units (consumed by rupu `for_each:`)

`scripts/trace_scan.py` writes `<outdir>/work-units.json` — a file whose content
starts with `[`, so rupu `for_each:` can JSON-parse it directly. Each element is
EXACTLY:

```json
{
  "id": "dangerous-call-strcpy-target-1",
  "title": "strcpy with 968-byte attacker-reachable source in ./target",
  "targets": [{"file": "/path/to/target", "call": "strcpy", "detail": "arg len 968 -> 0x7ffd..."}],
  "hints": ["gdb-debugging", "vuln-classes"]
}
```

- `id`: stable lowercase `[a-z0-9-]` slug (tool + call + target + counter).
- `targets`: non-empty; objects carry `file`, `call`, `detail` (and `endpoint` for
  network units).
- `hints`: SORTED short strings naming the next skill/tool
  (`gdb-debugging`, `heap-exploitation`, `pwntools`, `vuln-classes`).

Generic fan-out mechanics: see the shared **`work-units`** skill.

## Assets (`assets.mark`)

- `binary:file` (coordinate `t=file`, `v=<sha256 or path>`), depth ladder
  `discovered -> triaged -> analyzed -> vuln-identified -> exploited` (monotonic):
  - any successful trace run → at least `triaged`;
  - trace parsed and summary produced → `analyzed`;
  - marker provably reaching `system()`/`execve` argv, or a path you control reaching
    `openat` outside the intended root → `vuln-identified`.
- `binary:symbol` (file coordinate + `t=symbol`, `v=<name>`; or `t=vaddr` from
  ltrace `-i`) for each dangerous sink observed (`strcpy`, `system`, `printf`-with-
  variable-fmt, oversized `memcpy`): mark `discovered` when seen, `triaged` once the
  argument provenance (attacker-reachable or not) is established.

## Findings (`findings.report`)

Only VERIFIED issues (marker in the dangerous argument, not merely "strcpy exists"):

- command injection: `system("...MARKER...")` line + the input that produced it;
- path traversal / file write: the `openat`/`rename` line showing the escaped path;
- format string: `printf(<your bytes>)` plus the `%p` leak output;
- unbounded copy with confirmed attacker-length source (then usually confirmed as a
  crash via `gdb-debugging` first — attach that offset).

Use rupu's `findings.report` tool with the field contract from the shared
**`finding-report`** skill (title, target coordinate, severity, repro command,
evidence paths). Do not write a separate report file.

## Evidence

Keep ALL raw traces under the run workspace; never delete:

- `evidence/strace.out` or per-pid `evidence/trace.<pid>` files,
- `evidence/ltrace.out`,
- the exact driver input (marker string, request bytes),
- `trace_scan.py`'s `summary.txt` and `work-units.json`.

Finding evidence fields should reference these paths plus the specific line numbers
(`grep -n` output) that prove the claim.
