---
name: binary-protections
description: Read a binary's exploit mitigations (NX, stack canary, PIE, RELRO, FORTIFY_SOURCE, ASLR, CET/CFI, PE DEP/ASLR/CFG/SafeSEH, Mach-O) with checksec/rabin2/readelf and translate each one into a concrete exploitation-plan decision. Use right after binary-triage, before writing any exploit, to decide between shellcode, ROP, ret2libc, GOT overwrite, leak-first strategies, or canary bruteforce.
license: Proprietary
compatibility: Linux host; checksec.sh or pwntools recommended; readelf/rabin2 fallback paths included; PE/Mach-O notes apply cross-platform
metadata:
  author: Section9Labs
---

# Binary Protections → Exploitation Plan

Mitigations are not a stop sign; they are a routing table. Each flag removes
some techniques and makes others mandatory. Read them all **before** writing
the first line of exploit code, and let them decide the plan.

Input: a binary already identified by the `binary-triage` skill (you have its
sha256, format, arch). Output: a normalized protections record, an updated
`binary:file` asset, and — when the combination implies a working technique —
a finding.

## 1. Read the protections

Primary (checksec.sh):

```
checksec --file=./target
checksec --output=json --file=./target     # machine-readable, preferred
checksec --dir=./bins/ --output=json       # whole directory at once
checksec --proc-all                        # every running process
checksec --kernel                          # kernel config hardening read
```

pwntools equivalent (same facts, plus it is what your exploit script will
assert against):

```
pwn checksec ./target
python3 -c "from pwn import ELF; ELF('./target')"   # prints the checksec block
```

Cross-format (works on PE/Mach-O):

```
rabin2 -I ./target     # canary, nx, pic, relro, stripped, static, fortify-ish
rabin2 -Ij ./target    # JSON
```

No checksec anywhere? Read it straight off the ELF (this is also how you
settle disagreements between tools):

```
readelf -lW ./target | grep -E 'GNU_STACK|GNU_RELRO'   # NX, RELRO segment
readelf -d  ./target | grep -E 'BIND_NOW|FLAGS|RPATH|RUNPATH'
readelf -h  ./target | grep Type                        # EXEC=no PIE, DYN=PIE/.so
readelf --dyn-syms ./target | grep -E '__stack_chk_fail|__\w+_chk'
readelf -n  ./target | grep -iE 'IBT|SHSTK'             # CET markers
```

Decision rules: `GNU_STACK … RWE` = NX off. `GNU_RELRO` present = at least
partial RELRO; plus `BIND_NOW`/`FLAGS_1: NOW` = full. `Type: DYN` with an
`INTERP` header = PIE. `__stack_chk_fail` imported = canary. Any `*_chk`
import (`__printf_chk`, `__memcpy_chk`) = built with `-D_FORTIFY_SOURCE`.

Or just run the normalizer:

```
python3 scripts/checksec_json.py ./target -o protections.json
```

It prefers `checksec --output=json`, falls back to `rabin2 -Ij`, then to raw
`readelf` parsing, prints `{file, relro, canary, nx, pie, fortify, rpath,
runpath}` plus one plan-implication line per protection, and emits the
`[rupu] assets.mark` line.

## 2. What each flag does to the plan

### NX / DEP (`GNU_STACK RW`)
- **Off (RWE)**: writable memory is executable. Plan: inject shellcode into
  the overflowed buffer / env / heap and jump to it. On a non-PIE binary a
  `jmp rsp` or `call rax` gadget removes the need to know the buffer address.
- **On**: no injected code runs. Plan: reuse existing code — ret2libc
  (`system("/bin/sh")`), ROP, SROP (`sigreturn` gadget builds a full register
  frame), or `mprotect`/`mmap` ROP stage that re-enables RWX and then runs
  shellcode anyway.

### Stack canary (`__stack_chk_fail`)
- A linear stack overflow that reaches the saved RIP corrupts the canary
  first; the process aborts with `*** stack smashing detected ***` — seeing
  that message in testing is itself proof you control the overflow length.
- Plan options, in preference order:
  1. **Leak it**: format string, OOB read, or an overflow of only the
     buffer's non-terminated end printed back to you.
  2. **Byte-at-a-time brute on a forking server**: children inherit the
     parent's canary unchanged, so overflow 1 extra byte, 256 tries max per
     byte, crash = wrong, no crash = right; 4096-ish connections total for
     64-bit (first canary byte is always `\x00`).
  3. **Skip it**: a non-linear write (indexed OOB write, format-string `%n`)
     that lands past the canary; or target data *below* the canary (local
     function pointers, loop indexes).

### PIE (`Type: DYN` + INTERP)
- **No PIE**: `.text`, PLT, GOT at fixed addresses forever. Plan: ret2plt
  (`puts@plt(puts@got)` leaks libc with zero prior leaks), GOT overwrite at a
  known address, direct ROP over the binary's own gadgets.
- **PIE**: every binary address needs `base + offset`. Plan: get ONE leak of
  any `.text`/data pointer (format string `%p` spray, uninitialized stack
  read, OOB read), subtract the known offset, then everything is absolute
  again. Partial-overwrite trick: the low 12 bits of any pointer are not
  randomized (page-aligned base), so overwriting only the last 1–2 bytes of a
  return address reaches nearby code with 0–4 bits of brute force.

### RELRO
- **None/Partial** (`GNU_RELRO` only, lazy binding): the GOT is writable and
  is the premier write-what-where target — overwrite `free@got` with
  `system`, then `free(buf_containing_binsh)`. Partial also keeps lazy
  binding, enabling ret2dlresolve (fake link_map/relocation → resolve
  arbitrary libc symbol with no leak at all).
- **Full** (`GNU_RELRO` + `BIND_NOW`): GOT read-only. Plan shifts to other
  writable function pointers: `__malloc_hook`/`__free_hook` (glibc < 2.34),
  FSOP (`_IO_FILE` vtable / `_IO_list_all`), `exit` handlers, `.fini_array`
  only if not covered by RELRO, or pure ROP with a stack pivot.

### FORTIFY_SOURCE (`*_chk` imports)
- `sprintf/strcpy/memcpy` become `__*_chk` with compile-time-known sizes —
  constant-size overflows abort; runtime-sized ones often survive. `%n` in a
  format string located in **writable** memory is rejected by `__printf_chk`,
  and positional/`%N$` tricks get consistency-checked. Plan: prefer
  read-only-resident format strings (rare if attacker-supplied), lean on
  `%s`/`%p` leaks (still allowed), or move to a non-fortified sink. Note
  which call sites still use the raw function — fortification is per-call.

### ASLR (system-wide, not a binary property)
- `cat /proc/sys/kernel/randomize_va_space` — `0` off, `1` stack/mmap/vdso,
  `2` (default) + brk/heap. Libraries, stack, heap randomize per-exec;
  a **non-PIE binary's own segments never move** regardless of this setting.
- One leaked libc pointer defeats library ASLR for that process entirely:
  `libc_base = leak - offset_of_leaked_symbol`; all of libc follows. On
  forking servers, layout is constant across children → brute/leak once.
- 32-bit targets: only ~8–16 bits of mmap entropy — plain bruteforce of a
  libc address is practical.

### Modern extras (name them in the report even when you won't face them)
- **CET / IBT + shadow stack**: `readelf -n` → `x86 feature: IBT, SHSTK`.
  IBT demands `endbr64` at indirect-branch targets (filters gadget set);
  shadow stack kills plain return-address overwrites where enforced
  (needs CPU+kernel+glibc support; often compiled-in but inactive).
- **Clang CFI / kCFI**: indirect calls type-checked; data-only attacks and
  in-type function pointers remain.
- **PE**: DEP (`NX_COMPAT`), ASLR (`DYNAMIC_BASE` + relocations, check
  `HIGH_ENTROPY_VA` for 64-bit), CFG (`GUARD_CF`), SafeSEH (32-bit only),
  `/GS` canary. Read with `rabin2 -I`, `objdump -x` (DllCharacteristics),
  or `python3 -c "import pefile"` where available. Details and the
  DllCharacteristics bit table: `references/formats-arch.md`.
- **Mach-O**: PIE flag in header (`MH_PIE`), stack canary
  (`___stack_chk_fail` import), NX default-on, plus code signing / hardened
  runtime / library validation which gate injection rather than memory
  corruption. `rabin2 -I` and `otool -hv` read them.

## 3. Combination → plan cheat sheet

| canary | nx | pie | relro | first plan |
|---|---|---|---|---|
| no | no | no | any | overflow → shellcode on stack (or ret2reg gadget) |
| no | yes | no | ≤partial | ret2plt leak → ret2libc; or GOT overwrite / ret2dlresolve |
| no | yes | yes | full | leak binary+libc ptr (fmt/OOB) → ROP → FSOP/hooks if write-only |
| yes | yes | no | ≤partial | leak canary (fmt) or fork-brute → ret2plt → ret2libc |
| yes | yes | yes | full | hardest: stack leak for canary + lib leak → full ROP, or logic/heap bug instead |

Full per-mitigation bypass depth, and exactly what each kind of leak buys
you: `references/protections.md`. Calling conventions and where protections
live per format/arch (needed the moment you build a ROP chain):
`references/formats-arch.md`.

## 4. Record and hand off

Update the `binary:file` asset (same sha256 coordinate `binary-triage` used)
— protections are facts about the asset, carried in the note, and the read
completes the analysis step:

```
assets.mark kind=binary:file coords=[{t: file, v: <sha256>}] depth=analyzed
            note="relro=partial canary=no nx=yes pie=no fortify=no;
                  plan: ret2plt leak -> ret2libc, GOT writable"
```

When protections + a confirmed sink add up to an exploitability conclusion
(e.g. `gets` + no canary + no PIE + partial RELRO = textbook ret2libc), file
it with rupu `findings.report` (field contract: shared `finding-report`
skill) and bump the asset to `vuln-identified`. Wiring details:
`references/rupu.md`.

Hand off:
- **`pwntools`** — build the exploit the plan dictates; mirror the read with
  `ELF('./target').checksec()` inside the script.
- **`rop-chains`** — when NX forces code reuse: gadget hunting and chain
  construction for the arch read here.
- **`libc-identification`** — when the plan needs libc offsets (ret2libc,
  hooks, FSOP) and the remote libc is unknown.
- **`format-string-exploitation`** / **`heap-exploitation`** — when the leak
  or write primitive the plan demands comes from those bug classes.
- **`radare2`** / **`ghidra-headless`** — leak-primitive hunting and sink
  confirmation.
- Back to **`binary-triage`** output for which input channel delivers the
  overflow.

## References

- `references/protections.md` — every mitigation in depth, bypass catalog, leak economics.
- `references/formats-arch.md` — ELF/PE/Mach-O header locations; x86-64/i386/ARM/AArch64 calling conventions for ROP.
- `references/rupu.md` — assets.mark updates and findings.report wiring.
