# rupu wiring for the rop-chains skill

This skill parses tool output (ROPgadget/ropper/one_gadget via
`scripts/find_gadgets.py`), so every run must end in rupu-ingestible data. Import
the shared `work-units` and `finding-report` skills by name for the generic
mechanics.

## Work units

`scripts/find_gadgets.py --work-units units.json` emits a JSON array file
(content starts with `[`, so rupu `for_each:` can JSON-parse it directly) of
objects EXACTLY `{id, title, targets, hints}`:

```json
[
  {
    "id": "build-rop-chain-target",
    "title": "Build ROP chain for ./target from discovered gadgets",
    "targets": [
      {"kind": "binary:file", "t": "file", "v": "9f2a...sha256"}
    ],
    "hints": ["pwntools", "rop-chains", "srop"]
  }
]
```

- `id`: stable lowercase `[a-z0-9-]` slug (derived from the binary path).
- `targets`: non-empty; use the binary's sha256 as `v` when computable.
- `hints`: sorted short strings naming next skills/tools — e.g.
  `libc-identification` when a leak stage is planned, `srop` when
  syscall gadgets exist, `gdb-debugging` for chain verification.

Fan-out mechanics: shared `work-units` skill.

## Assets (`assets.mark`)

Binary profile model, depth ladder monotonic
`discovered -> triaged -> analyzed -> vuln-identified -> exploited`:

| moment | mark |
|---|---|
| gadget inventory completed (`gadgets.json` written) | `binary:file` (t=file, v=sha256) → `analyzed` |
| viable chain strategy confirmed (e.g. pop rdi + puts@plt on no-PIE) | `binary:file` → `vuln-identified` |
| chain lands (shell / arbitrary execve, locally on target build or remote) | `binary:file` → `exploited` |
| key gadgets and pivot targets worth remembering | `binary:symbol` with the file's coordinates plus `t=vaddr`, `v=0x401234` (e.g. the `pop rdi ; ret`, the `syscall ; ret`, the .bss pivot buffer) |

## Findings (`findings.report`)

On a landed chain, file the finding via `findings.report` per the shared
`finding-report` skill's field contract: technique (ret2libc / SROP /
ret2dlresolve / one_gadget / pivot), the gadget addresses used, offsets, libc
build, the exploit script path (from the `pwntools` skill) as PoC, and the target
coordinates (sha256; `203.0.113.10:1337`-style endpoint if remote). The exploit
script + `gadgets.json` + the tube transcript ARE the report — do not write a
separate report file.

## Evidence

Keep under the run workspace, never delete:

- raw ROPgadget/ropper/one_gadget stdout (`tee` it:
  `ROPgadget --binary ./target | tee raw/ropgadget.txt`),
- `gadgets.json` and `units.json`,
- `rop.dump()` listings for every chain version attempted,
- corefiles from failed chains (they explain the fix).
