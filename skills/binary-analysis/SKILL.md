---
name: binary-analysis
description: Umbrella skill for the binary analysis / reverse engineering / exploitation pack — the end-to-end flow for taking unknown binaries (ELF, PE, Mach-O, raw firmware) from first contact through triage, static and dynamic analysis, vulnerability identification, and working exploitation primitives; routes by name to every sub-skill in the pack. Load this first when handed one or more unknown binaries on an authorized engagement.
license: Proprietary
metadata:
  author: Section9Labs
---

# Binary Analysis — Umbrella Flow

You have been handed one or more unknown binaries and asked to understand them,
find memory-safety and logic vulnerabilities, and build working exploitation
primitives. This skill is the map. It does not teach any tool itself — it tells
you which sub-skill to load at each step and how the phases chain together.

Work in a run workspace (e.g. `work/<run>/`). Every phase writes its raw tool
output under that workspace as evidence and, where it parses output, emits
rupu-ingestible data (assets, work units, findings). The rupu wiring for the
whole pack is defined once in `references/rupu.md` — read it before fanning out
over multiple binaries or recording results.

## The five phases

```
1. Triage          -> what is this file? what protections? firmware?
2. Static RE       -> what does the code do? where does input reach a sink?
3. Dynamic         -> run/emulate/trace/fuzz/solve it; confirm reachability
4. Vuln ID         -> name the bug class; name the primitive it yields
5. Exploitation    -> turn the primitive into control: ROP, heap, fmt, pwntools
```

Phases are not strictly linear. You will loop 2↔3 (read code, test a theory,
read more code) and 4→3 (suspected bug → dynamic confirmation). But never skip
Phase 1: the protections table from triage steers everything after it.

---

## Phase 1 — Triage / first contact

Goal: identify every file, enumerate strings/symbols/structure, read the
mitigations, and carve firmware if that is what you have.

- **Load the `binary-triage` skill** for the first pass on each file:
  `file`, `strings`, `nm`, `readelf`, `objdump`, `rabin2` — identification,
  arch/endianness, linking (static vs dynamic), stripped or not, imports and
  exports, interesting strings (paths, format strings, URLs, credentials,
  version banners), section layout. It includes the triage normalizer that
  turns raw tool output into the pack's work-units JSON and `assets.mark`
  calls (ladder step: discovered → triaged).
- **Load the `binary-protections` skill** to read the mitigation posture:
  checksec output, RELRO (none/partial/full), stack canary, NX, PIE,
  FORTIFY_SOURCE, CET/shadow-stack, and the PE/Mach-O equivalents
  (DEP/ASLR/CFG, PAC). Produce a protections table per binary — this table is
  the plan's steering input (see "How protections steer the plan" below).
- **Load the `binwalk-firmware` skill** when the input is a firmware image or
  an unknown blob: entropy analysis, signature scanning, extraction
  (`binwalk -eM`), filesystem carving (squashfs/jffs2/ubifs/cpio), and
  recursing — every executable carved out of the image goes back through
  `binary-triage` as a new `binary:file` asset.

Deliverables: per-file identification record, protections table, string/symbol
inventory, and (for firmware) the carved tree. If there is more than one
binary, emit a work-units file now (one unit per binary) so a rupu workflow
`for_each:` or a lead agent's `dispatch` can fan out — see `references/rupu.md`.

## Phase 2 — Static reverse engineering

Goal: understand the code well enough to trace attacker-controlled input
(argv, stdin, files, env, sockets, IPC, parsed formats) to dangerous sinks
(`strcpy`/`memcpy`/`sprintf` family, `malloc`/`free` lifecycle, format-string
calls, index arithmetic, `system`/`exec`).

- **Load the `ghidra-headless` skill** for scriptable bulk work:
  `analyzeHeadless` project creation, decompilation export of all functions to
  C, cross-reference dumps, scripted sink searches over the decompiled corpus.
  This is the right tool when the binary is large, when you have many binaries,
  or when you want greppable decompiled C for an LLM or script to scan.
- **Load the `radare2` skill** for interactive and automated r2/rizin work:
  `aaa` analysis, function listing, cross-references (`axt`), disassembly and
  graph views, searching for sink calls, and `r2pipe` Python automation when
  you want structured JSON (`aflj`, `axtj`, `izj`) out of the analysis.

Decision: use Ghidra headless for breadth (export everything, grep the C), use
radare2 for depth and speed on a specific function or for scripted queries.
They are complementary — most engagements use both.

Deliverables: function/sink inventory — every reachable sink, the input path
that feeds it, and the controlling constraints. Mark the interesting functions
as `binary:symbol` assets and promote the file to ladder step `analyzed`.
Candidate sinks become per-sink work units for Phase 3/4 fan-out.

## Phase 3 — Dynamic analysis

Goal: observe and control the running (or emulated) program; confirm what
static analysis suspected; discover what static analysis missed.

- **Load the `gdb-debugging` skill** for gdb with GEF/pwndbg: cyclic-pattern
  offset finding, breakpoints and watchpoints, `vmmap`, heap inspection
  (`heap bins`, `heap chunks`), GOT/PLT inspection, register and stack state at
  crash time, `checksec` from inside the debugger, and scripting with `gdb -x`
  / batch mode for repeatable crash analysis.
- **Load the `dynamic-tracing` skill** for `ltrace`/`strace`: library-call and
  syscall traces to see what the program actually reads, opens, and executes;
  `-f` to follow forks, `-e trace=` filters, `-s` to widen string capture.
  Fast way to find config files, hidden inputs, and the exact `read`/`recv`
  that carries attacker data.
- **Load the `qiling-unicorn` skill** when you cannot run the target natively:
  foreign architectures (MIPS/ARM router firmware on an x86 host), missing
  rootfs, kernel-less blobs. Qiling for full-OS-emulation with hooks and a
  carved rootfs; Unicorn for emulating a single function or shellcode-sized
  region with hand-set state.
- **Load the `angr` skill** for symbolic execution: solve for the input that
  reaches a target address (or avoids a bad one), recover magic bytes and
  checksum constraints, and model paths that fuzzing struggles to hit
  (multi-byte comparisons, nested parsers).
- **Load the `fuzzing` skill** (AFL++, honggfuzz, libFuzzer) to discover
  crashing inputs at scale: harness construction, persistent mode, QEMU mode
  for closed-source targets, corpus and dictionary strategy, crash triage and
  minimization. Fuzzing output (unique crashes) feeds straight back into
  `gdb-debugging` for root-cause and into Phase 4 for classification.

Decision — static vs dynamic vs symbolic vs fuzzing:

| Situation | Approach |
|---|---|
| Small binary, readable logic | Static first (`radare2`/`ghidra-headless`); confirm in gdb |
| Large/obfuscated binary, unclear input path | Dynamic first: `dynamic-tracing` to find the input, then static on the handler |
| Specific hard-to-reach state (magic values, checksums) | `angr` symbolic execution |
| Complex parser, want bugs at scale | `fuzzing`, then triage crashes in `gdb-debugging` |
| Can't execute natively (arch/firmware) | `qiling-unicorn` emulation; angr also runs on foreign arch |
| Need exact overflow offset / crash state | `gdb-debugging` with cyclic patterns |

These compose: fuzz while you read; use angr to get past the checksum that
blocks the fuzzer; emulate the firmware service so you can fuzz and debug it.

Deliverables: confirmed input→sink reachability, crash artifacts (inputs,
backtraces, register state) stored under the workspace, exact offsets.

## Phase 4 — Vulnerability identification

Goal: name the bug and name the primitive.

- **Load the `vuln-classes` skill** to classify what you found: stack buffer
  overflow, heap overflow, use-after-free / double-free, format string,
  integer overflow / signedness, off-by-one. For each class it gives the
  source-code pattern, the disassembly signature, the dynamic confirmation
  test (what the crash looks like in gdb, what the trace shows), and —
  critically — the exploitation primitive each one yields (saved-RIP control,
  adjacent-chunk corruption, arbitrary read/write, allocator metadata
  control, bounds bypass).

Deliverable: candidate-vulnerability list, each entry naming the bug class,
the evidence (file, function, crash input), and the primitive. Promote the
affected `binary:file` asset to `vuln-identified` and record each confirmed
bug with `findings.report` (see `references/rupu.md`).

## Phase 5 — Exploitation primitive construction

Goal: a working exploit (or a clearly demonstrated primitive) per confirmed bug.

- **Load the `pwntools` skill** first — it is the framework everything else
  plugs into: `process`/`remote` I/O, `ELF`/`ROP` objects, `cyclic`, packing,
  shellcraft, leak-handling patterns, and the standard exploit script skeleton.
- **Load the `rop-chains` skill** when NX forces code reuse: gadget discovery
  with ROPgadget/ropper, `one_gadget` for instant-shell candidates,
  ret2libc, ret2plt, SROP, ret2dlresolve, and stack pivots for short
  overflows.
- **Load the `libc-identification` skill** when the target is remote or the
  libc is unknown: turn a leaked libc address into a libc build ID
  (libc-database / online lookups), then resolve `system`, `/bin/sh`, and
  gadget offsets against the identified build.
- **Load the `heap-exploitation` skill** for glibc heap bugs: tcache
  poisoning, fastbin dup, UAF and double-free leverage, overlapping chunks,
  house-of-* techniques, and the version-specific constraints
  (safe-linking, key checks) per glibc release.
- **Load the `format-string-exploitation` skill** for `%n`-family bugs:
  parameter-index discovery, arbitrary read for leaks (defeat PIE/ASLR/canary),
  arbitrary write for GOT/hook/return-address overwrite, and `%hn` split-write
  construction with pwntools `fmtstr_payload`.

Deliverable: exploit script(s) under the workspace, each reproducible
end-to-end. Promote the asset to `exploited` and finalize the finding.

---

## How protections steer the plan

Read the Phase 1 protections table and let it decide the route:

- **NX enabled** → no shellcode on stack/heap; plan for code reuse:
  `rop-chains` (ret2libc/ret2plt/SROP/ret2dlresolve). NX disabled → classic
  shellcode via `pwntools` shellcraft is back on the table.
- **Stack canary** → a plain stack smash won't survive the epilogue. You need
  a canary leak (format string, out-of-bounds read, partially-controlled
  output) before overwriting the return address, a brute-force (forking
  servers re-use the canary per child — byte-by-byte brute), or a path that
  bypasses the canary entirely (heap bug, non-stack write target, overwriting
  before the canary check matters).
- **PIE / ASLR** → every address is randomized; you need a leak first
  (format string, uninitialized output, partial overwrite of a low byte) to
  rebase the binary/libc, then feed the leak to `libc-identification` and
  `rop-chains`. No PIE → the binary's own addresses are fixed: ret2plt and
  GOT reads work without any leak.
- **Full RELRO** → GOT is read-only; no GOT overwrite — pick another write
  target (saved return address, `__malloc_hook`-era hooks on old glibc, exit
  handlers, FSOP/`_IO_FILE`, function pointers in the program's own data).
  Partial/no RELRO → GOT overwrite is a prime target for format-string or
  heap arbitrary-write primitives.
- **FORTIFY_SOURCE** → `%n` in writable-segment format strings is blocked and
  `_chk` variants bound some copies; look for non-fortified paths and
  runtime-constructed format strings.
- **CET / shadow stack / PAC** → ret-based chains are constrained; prefer
  JOP/COP-style gadgets, data-only attacks, or hijacking indirect calls.
- **Statically linked** → no libc identification needed; the binary itself is
  a giant gadget farm and syscall gadgets are usually present (SROP shines).
- **Stripped** → lean on `ghidra-headless` auto-analysis, FLIRT-style
  signatures in `radare2`, and `dynamic-tracing` to label functions by
  behavior.

Combine them: *NX + canary + PIE + Full RELRO* means your plan is
leak-first (fmt string or OOB read) → identify libc → ROP to `system` or
one_gadget, landing the write on the return address or an exit handler, never
the GOT.

## Artifacts and hand-off

By the end of a run the workspace contains:

1. **Protections table** — one row per binary (RELRO/canary/NX/PIE/FORTIFY/
   CET, arch, linking, stripped), from Phase 1.
2. **Function/sink inventory** — reachable sinks with input paths and
   constraints, from Phase 2, with `binary:symbol` assets marked.
3. **Candidate vulnerabilities** — class, evidence, primitive, from Phases
   3–4, with crash inputs and gdb state preserved as evidence.
4. **Working exploits** — reproducible scripts, from Phase 5, where reached.

Every parse/hand-off step produces rupu-ingestible output: work-units JSON for
fan-out, `assets.mark` for the discovered→triaged→analyzed→vuln-identified→
exploited ladder, and `findings.report` for verified bugs. The single source
for all of that wiring is `references/rupu.md`. Keep all raw tool output under
the run workspace — never delete evidence.

## Quick router

`python3 scripts/route.py <file...>` prints, per file, its type and the Phase 1
sub-skill to load first (works from magic bytes alone; degrades gracefully if
the file is unreadable).

| You have / you need | Load |
|---|---|
| Unknown file, first look | `binary-triage` |
| Mitigation posture | `binary-protections` |
| Firmware image / blob | `binwalk-firmware` |
| Bulk decompilation, sink grep | `ghidra-headless` |
| Interactive/scripted disasm, xrefs | `radare2` |
| Debugger, offsets, heap/GOT view | `gdb-debugging` |
| Syscall/library-call trace | `dynamic-tracing` |
| Can't run natively (arch/firmware) | `qiling-unicorn` |
| Input to reach a state | `angr` |
| Crashes at scale | `fuzzing` |
| Name the bug + primitive | `vuln-classes` |
| Exploit framework | `pwntools` |
| Gadgets, ret2*, SROP, pivots | `rop-chains` |
| Which remote libc is this | `libc-identification` |
| glibc heap techniques | `heap-exploitation` |
| %n read/write | `format-string-exploitation` |
