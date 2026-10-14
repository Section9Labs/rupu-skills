# rupu wiring — angr

This skill parses solver/exploration output. Every session MUST end with
rupu-ingestible data. Use the shared `work-units` skill for fan-out mechanics and the
shared `finding-report` skill for the findings field contract — do not reinvent either.

## 1. Work units

One clean JSON array file (content starts with `[`; rupu `for_each:` JSON-parses it).
Objects have EXACTLY `{id, title, targets, hints}`:

- `id`: stable lowercase `[a-z0-9-]` slug, e.g. `angr-crackme-solved-0x401a2c`
- `title`: human-readable
- `targets`: non-empty array of target objects
  (`{"file": "./crackme", "sha256": "<hex>", "vaddr": "0x401a2c"}`)
- `hints`: **sorted** array of short next-skill/tool names

`scripts/angr_solve.py --work-units units.json` emits this. Example:

```json
[
  {
    "id": "angr-licd-unconstrained-stdin",
    "title": "licd: unconstrained state — 400-byte stdin controls PC (offset 136)",
    "targets": [
      {"file": "./licd", "sha256": "9ac2...41", "vaddr": "0x4011f0"}
    ],
    "hints": ["pwntools", "rop-chains"]
  },
  {
    "id": "angr-crackme-solved-serial",
    "title": "crackme: serial check solved, accepting input recovered",
    "targets": [{"file": "./crackme", "sha256": "77be...03"}],
    "hints": ["finding-report", "qiling-unicorn"]
  }
]
```

## 2. Assets — `assets.mark`

Binary profile model (same as the rest of the `binary-analysis` pack):

- kind `binary:file` — coordinate `t=file`, `v=<sha256>` (preferred) or path.
- kind `binary:symbol` — the file coordinate plus `t=symbol`, `v=<name>` or
  `t=vaddr`, `v=0x401a2c` for check functions, sinks, hijack sites.

Depth ladder, monotonic: `discovered -> triaged -> analyzed -> vuln-identified -> exploited`.

| angr result | mark |
|---|---|
| Project loads, CFG built, check function located | `binary:file` -> `triaged`; the check fn `binary:symbol` -> `discovered` |
| Exploration completes; reachability of success/failure states characterized | `binary:file` -> `analyzed`; check fn -> `analyzed` |
| Solved input recovers a secret (serial/password), or symbolic data proven to reach a dangerous sink, or unconstrained state found | relevant `binary:symbol` -> `vuln-identified` |
| Solved/crash input verified against the real binary (it accepts the serial / crashes with controlled PC) | -> `exploited` |

Never mark `exploited` on symbolic evidence alone — verify concretely first
(run the real binary with the solved bytes; a hijack PoC counts once PC control is
demonstrated natively or under the `qiling-unicorn` skill).

## 3. Findings — `findings.report`

Report via rupu's `findings.report` tool; field contract in the shared
`finding-report` skill. No standalone report files. Typical angr findings:

- **Recovered secret / bypassable check**: hardcoded serial, password derivable from
  constraints, license check that angr satisfies in seconds. Evidence: the exact
  solved input bytes (hex + base64 in `solve.json`), the solver script, and a
  transcript of the real binary accepting the input.
- **Control-flow hijack (unconstrained state)**: include the symbolic PC expression,
  the constrained crash input (`pc == 0x41414141` stdin dump), the computed offset,
  and the stdin length used. Downstream exploitation goes to `pwntools`/`rop-chains`;
  file the finding when PC control is verified.
- **Taint-to-sink proof**: symbolic input bytes reach `system()`/`execve` argument or
  a size parameter — include the sink address, the SimProcedure tap output, and a
  satisfying concrete sample.

## 4. Evidence

Keep under the run workspace, never delete:

- `solve.json` from `scripts/angr_solve.py` (solved input in hex AND base64 — raw
  bytes rarely survive copy/paste)
- the solver script actually used (it is the reproduction procedure)
- native-verification transcript (`./target < solution.bin` output)
- for hijacks: the crash input file and the constraint dump
