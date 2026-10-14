---
name: vuln-classes
description: Identify common memory-safety and logic vulnerability classes in a binary — stack/heap overflow, use-after-free/double-free, format string, integer overflow/signedness, off-by-one/null-byte — giving for each the source pattern, the disassembly signature (objdump/Ghidra/r2), the dynamic confirmation (gdb/ASan/trace), and the primitive plus the exploitation skill to hand off to. Use after triage/RE/fuzzing surfaces a suspicious function or crash and you need to name the bug and pick the exploitation path.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Vulnerability classes

Given a suspicious function (from the `ghidra-headless`/`radare2` RE skills),
a crash (from the `fuzzing` skill), or a trace, name the vulnerability class.
Each class below gives: (a) source pattern, (b) binary/disassembly signature,
(c) dynamic confirmation, (d) resulting primitive → exploitation skill.
One deep reference per class under `references/`.

## 1. Stack buffer overflow — `references/stack-overflow.md`

- **(a) Source**: fixed stack buffer + unbounded copy — `gets(buf)`,
  `strcpy(buf, src)`, `sprintf(buf, "%s", src)`, `scanf("%s", buf)`,
  `memcpy(buf, src, attacker_len)`, `read(fd, buf, big_n)`.
- **(b) Disasm**: large `sub rsp, 0xN` in the prologue, then a call to
  `gets/strcpy/sprintf/scanf/read/memcpy@plt` with `lea r?, [rbp-0xN]` as
  the destination and **no bound derived from the buffer size**. In Ghidra:
  `char buf[64]; ... strcpy(buf, param_1);`. No `__stack_chk_fail` call =
  no canary.
- **(c) Confirm**: send a de Bruijn pattern (`pwndbg> cyclic 200` /
  pwntools `cyclic(200)`), crash in gdb, `cyclic -l $rip-bytes` → offset to
  saved RIP (load the `gdb-debugging` skill). ASan: `stack-buffer-overflow
  WRITE of size N`.
- **(d) Primitive**: saved-RIP control (plus saved RBP / locals) →
  `rop-chains` for the chain, `pwntools` for delivery. Canary present →
  need a leak or byte-wise brute (forking servers) first.

## 2. Heap overflow — `references/heap-overflow.md`

- **(a)**: write past a `malloc(n)` chunk — copy length > n, size computed
  differently at alloc vs copy, `strcat` into a tight chunk.
- **(b)**: `call malloc` with size X (or size in a register traced from
  input), result in `rax` → pointer, then a copy loop / `memcpy@plt` whose
  length is a *different* expression. Ghidra: `p = malloc(len); memcpy(p,
  src, len2);` with `len2 > len` reachable.
- **(c)**: ASan `heap-buffer-overflow WRITE ... 0 bytes to the right of
  N-byte region`; or in pwndbg watch the next chunk header corrupt:
  `heap`, `vis_heap_chunks` before/after the copy.
- **(d)**: adjacent-chunk data/metadata corruption → `heap-exploitation`
  (overlapping chunks, tcache poisoning via corrupted fd, house techniques).

## 3. Use-after-free / double-free — `references/uaf-double-free.md`

- **(a)**: `free(p)` then later deref/write of `p` (dangling pointer kept
  in a struct/global), or a second `free(p)` on an error path.
- **(b)**: `call free` on a value that is **not nulled** afterwards
  (missing `mov qword [..], 0`), with a later load/call through the same
  slot; or two `call free` reachable with the same pointer (double-free).
  In Ghidra, track the variable: xrefs after the `free` call site.
- **(c)**: ASan `heap-use-after-free` / `attempting double-free` with
  alloc/free/use stacks. pwndbg: `bins`/`tcachebins` — see the freed chunk
  in tcache, then the UAF write change its `fd`/key.
- **(d)**: control of a freed chunk → tcache/fastbin poisoning, arbitrary
  alloc → `heap-exploitation`.

## 4. Format string — `references/format-string.md`

- **(a)**: printf-family with attacker bytes as the *format*:
  `printf(user)`, `fprintf(f, user)`, `syslog(pri, user)`, `snprintf(dst,
  n, user)` — vs the safe `printf("%s", user)`.
- **(b)**: `call printf@plt` where `rdi` (1st arg) is a buffer/heap/argv
  pointer, not a `lea rdi, [rip+rodata_literal]`; often `xor eax, eax`
  right before (variadic SSE count). Compiler warning `-Wformat-security`
  fires on the same pattern in source.
- **(c)**: send `%p.%p.%p.%p` → leaked hex = confirmed. Find your buffer:
  `AAAA%7$p` style positional probing until `0x41414141` appears.
- **(d)**: arbitrary read (`%s`/`%p` + positional), arbitrary write (`%n`,
  `%hn`, `%hhn`) → `format-string-exploitation`; the leak alone defeats
  ASLR/canary for other classes.

## 5. Integer overflow / underflow / signedness — `references/integer-bugs.md`

- **(a)**: size arithmetic that wraps (`malloc(count * size)`,
  `len + hdr`), or a **signed** length checked (`if (len < MAX)`) then used
  **unsigned** (`memcpy(dst, src, len)` with len = -1 → SIZE_MAX), or
  truncation (u64 → u32/u16).
- **(b)**: `imul`/`add`/`shl` feeding `call malloc` with no overflow check
  (no `jo`/no `__builtin_mul_overflow` sequence/`calloc`); signedness
  mismatch = `movsx` vs `movzx`, signed `jl/jg/jle` guarding a value later
  used by unsigned `jb/ja` or passed to memcpy. A `cmp` with `jl` followed
  by use as `size_t` is the classic.
- **(c)**: drive boundary values: `0`, `-1`, `0x7fffffff`, `0x80000000`,
  `0xffffffff`, `count=0x40000001,size=4`. Watch the allocation size in gdb
  (`break malloc`, inspect `rdi`) vs the copy length. ASan:
  `allocation-size-too-big`, `negative-size-param`, or a downstream
  heap-buffer-overflow.
- **(d)**: undersized allocation / huge copy → heap overflow or OOB
  read/write → `heap-exploitation` (or stack OOB → `rop-chains`).

## 6. Off-by-one / null-byte overflow — `references/off-by-one.md`

- **(a)**: `for (i = 0; i <= len; i++)` into `buf[len]`; or
  `buf[size] = 0` / `strlen`-based terminator landing one past;
  `strncat`/`snprintf` size confusion (`sizeof(buf)` vs `sizeof(buf)-1`).
- **(b)**: loop compare `jle/jbe` against the exact size; or an isolated
  `mov byte [reg+size], 0` after a copy where `size` equals the allocation.
  Ghidra: index expression `buf[n]` where `buf` is `char buf[n]`.
- **(c)**: ASan `heap-buffer-overflow WRITE of size 1` exactly at
  region-end; pwndbg `vis_heap_chunks` shows the next chunk's `size` LSB
  cleared (poison null byte: `0x101` → `0x100`, flags cleared).
- **(d)**: chunk-size/prev_inuse corruption → overlapping chunks via
  shrunk/backward-consolidated chunks → `heap-exploitation`. Stack
  off-by-one over saved RBP → stack pivot → `rop-chains`.

## Triage checklist (tie inputs to signatures)

1. **From fuzzing** (`fuzzing` skill units): the ASan first line maps 1:1
   onto classes 1–3 and 6 (`stack-buffer-overflow`, `heap-buffer-overflow`,
   `heap-use-after-free`, `double-free`; WRITE size 1 at region end =
   off-by-one; `allocation-size-too-big`/`negative-size-param` = class 5).
   Run `scripts/classify_crash.py` on the report.
2. **From static RE**: list imports (`rabin2 -i` / Ghidra symbol tree) —
   `gets/strcpy/sprintf/scanf/system` → class 1/4 candidates; walk xrefs
   to `malloc/free/memcpy/printf` and check each call site against the
   signatures above.
3. **From a raw gdb crash**: RIP = `0x6161616x` cyclic bytes → class 1;
   crash inside `malloc/free/_int_malloc` → classes 2/3/6 (metadata already
   corrupted); crash inside `vfprintf/printf` → class 4; fault address
   huge/wrapped (e.g. `0xfffffffffffffff8`) → class 5.
4. **From a trace** (`ltrace ./target <in`): see the actual
   `malloc(size)` vs `memcpy(..., n)` arguments and `printf("%s"...)` vs
   `printf(user_data)` directly.
5. Confirm dynamically (per-class step (c)) before reporting — a signature
   without a reproducing input is a lead, not a finding.

## Protections change exploitability, not the bug

Check with pwntools `checksec ./target` (or the `gdb-debugging` skill):

- **Canary** (`__stack_chk_fail` present): class 1 needs a leak (class 4 is
  the classic leak source) or a fork-server byte-brute; class 6 on the
  stack may slip under the canary.
- **NX**: shellcode on stack dead → ROP (`rop-chains`); classes unchanged.
- **PIE/ASLR**: every absolute-address primitive needs a leak first; pair
  any write primitive with a format-string or OOB-read leak.
- **RELRO**: partial → GOT overwrite is the easy `%n`/arbitrary-write
  target; full → go for `__malloc_hook`-era alternatives per glibc version
  (see `heap-exploitation`), `exit` handlers, or return addresses.
- **FORTIFY_SOURCE**: `__strcpy_chk`/`__printf_chk` call sites mean the
  compiler knew sizes — `%n` from writable format blocked, some overflows
  abort; look for the *non*-`_chk` calls nearby (size unknown = still hot).
- Static vs dynamic linking changes target selection, not classification.

## scripts/classify_crash.py

Feed it an ASan report or a gdb crash dump (file or stdin); it matches the
markers above (bug keyword, faulting instruction, registers, cyclic-pattern
RIP), prints the class + the exploitation skill to load, and emits a finding
stub JSON:

```sh
python3 scripts/classify_crash.py report.txt --json finding.json
./target_asan crash.min 2>&1 | python3 scripts/classify_crash.py -
```

## Record results (rupu)

See `references/rupu.md`. In short: `assets.mark` the binary
(`binary:file`) at `vuln-identified` and the vulnerable function
(`binary:symbol`) likewise; a confirmed class with a reproducer →
`findings.report` per the shared `finding-report` skill (the script's
finding stub carries the fields); hand the primitive to the named
exploitation skill; keep every report/trace as evidence.
