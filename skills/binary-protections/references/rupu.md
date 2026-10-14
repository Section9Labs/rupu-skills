# rupu wiring — binary-protections

This skill parses tool output (checksec/rabin2/readelf), so it ends by
producing rupu-ingestible data. Raw tool output is evidence — keep it under
the run workspace, never delete it (`scripts/checksec_json.py -o` writes the
normalized record; redirect raw checksec/readelf output with `tee` next to
it).

## Assets — `assets.mark`

The protections read is an **update to the existing `binary:file` asset**
created by `binary-triage` — same coordinate (`t=file, v=<sha256>`), one rung
up the monotonic ladder `discovered → triaged → analyzed → vuln-identified →
exploited`. Completing the protections read (together with the triage facts)
is what justifies `analyzed`:

```
assets.mark kind=binary:file coords=[{t: file, v: 3f1a9b2c4d5e…}]
            depth=analyzed
            note="relro=partial canary=no nx=yes pie=no fortify=no
                  rpath=none runpath=none;
                  plan: ret2plt libc leak -> ret2libc; GOT writable"
```

The note carries the full normalized record plus the plan sentence — the next
unit (usually `pwntools`) reads its strategy straight from the asset instead
of re-deriving it. `scripts/checksec_json.py` prints this exact line
(prefixed `[rupu]`) per file.

When a specific writable target drives the plan (e.g. a GOT slot under
partial RELRO), mark it as a `binary:symbol`:

```
assets.mark kind=binary:symbol
            coords=[{t: file, v: 3f1a9b2c…}, {t: symbol, v: exit@got}]
            depth=discovered
            note="partial RELRO: writable GOT slot, overwrite target"
```

## Findings — `findings.report`

Protections alone are configuration facts, not findings. They BECOME a
finding when combined with a confirmed sink into an exploitability
conclusion. Examples that cross the line:

- triage found `gets` reachable from stdin + this skill reads canary=no,
  pie=no, relro=partial → "stack buffer overflow, direct ret2libc path" —
  report it, bump the asset to `vuln-identified`.
- executable stack (`GNU_STACK RWE`) on a network daemon → report the missing
  mitigation itself as a hardening finding with the exploitation consequence
  spelled out.
- RPATH/RUNPATH pointing at a writable or relative directory on a setuid
  binary → library-planting privesc, report directly.

Use rupu's `findings.report` tool; the field contract (title, severity,
evidence, reproduction) is defined by the shared **`finding-report`** skill —
import it by name, do not invent fields and do not write a separate report
file. Evidence = the saved checksec/readelf output path + the triage evidence
for the sink.

## Work units

This skill normally consumes units emitted by `binary-triage` (its `hints`
include `binary-protections`). If the protections read itself spawns
follow-on work — e.g. "needs a libc leak primitive" or "hunt FSOP gadgets" —
append units to the same work-units JSON array file (content starts with `[`,
objects EXACTLY `{id, title, targets, hints}`, hints sorted, e.g.
`["pwntools"]` or `["ghidra-headless", "radare2"]`). Fan-out mechanics: the
shared **`work-units`** skill.
