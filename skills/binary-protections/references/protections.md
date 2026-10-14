# Protections in depth — mitigation, bypass, and what a leak buys you

## NX / W^X / DEP

Mechanism: PT_GNU_STACK without `E` makes the kernel map the stack
non-executable; hardware NX bit (PAE/64-bit) enforces per-page. On PE this is
DEP via `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.

Check: `readelf -lW ./target | grep GNU_STACK` → `RW ` on, `RWE` off. Note:
a linked object with a missing `.note.GNU-stack` can silently yield RWE on
old toolchains — always check the final binary, not assumptions.

Bypass catalog:
- **ret2libc**: return into `system` with `/bin/sh` (the string exists inside
  libc itself: `strings -a -t x libc.so.6 | grep /bin/sh`). x86-64 needs a
  `pop rdi; ret` gadget first; i386 just stacks args.
- **ROP**: chain gadgets; find them with `ROPgadget --binary ./target`,
  `ropper -f ./target`, or r2 `/R pop rdi`. Static binaries carry a full
  gadget set.
- **SROP**: one `syscall; ret` plus `rax=15` (`rt_sigreturn`) lets a fake
  sigframe set every register at once — great when gadgets are scarce.
- **mprotect/mmap stage**: ROP into `mprotect(buf_page, 0x1000, 7)` then jump
  to shellcode — turns NX back off for your page.
- **ret2dlresolve** (partial RELRO): fake relocation entries make the dynamic
  linker resolve `system` for you — no leak, no libc knowledge needed.

NX **off** plan: put shellcode in the overflowed buffer or in an environment
variable (`SHELLCODE=...` lands at a findable stack address on non-ASLR/non-PIE
setups) and return into it; `jmp esp/rsp` gadget avoids address guessing.

## Stack canary (SSP)

Mechanism: `-fstack-protector[-strong|-all]` places a random per-process
value (from AT_RANDOM, TLS `fs:0x28` on x86-64) between locals and saved
RBP/RIP; epilogue compares and calls `__stack_chk_fail` → abort + message
`*** stack smashing detected ***: terminated`.

Check: `nm -D ./target | grep __stack_chk_fail`. Note `-strong` only guards
functions with arrays/address-taken locals — some functions remain unguarded;
check the specific vulnerable function's epilogue in disasm
(`objdump -d -M intel --disassemble=<fn>` → look for `xor rcx, fs:0x28`).

Properties that matter:
- First byte is `\x00` on glibc (terminator canary) — reduces brute space and
  blocks str-function leaks of it.
- Constant across `fork()` children. Constant for the process lifetime.
- Stored also in TLS — an arbitrary write can overwrite BOTH the stack copy
  and `fs:0x28` to any matching pair.

Bypass catalog:
1. **Leak**: format string (`%p` spray — canary sits at a stable offset; it
   looks like 7 random bytes + trailing 00... actually leading 00 in memory,
   printed as e.g. `0x1a2b3c4d5e6f7700`), OOB read, or overflowing exactly up
   to the canary so a later `puts(buf)` prints the adjacent bytes (overwrite
   the terminator `\x00` with one non-null byte, read back, restore).
2. **Fork brute**: forking server, child canary == parent canary. Overflow
   with known-good prefix + 1 guessed byte; connection closes cleanly = byte
   correct. ≤ 256×7 attempts for 64-bit (byte 0 is `\x00`).
3. **Bypass without touching it**: indexed OOB write past it; `%n` write to
   the return address directly; overwrite function pointers / C++ vtables /
   longjmp buffers below the canary; corrupt the TLS canary too via a second
   write.
4. **Abort-path abuse** (old glibc): `__stack_chk_fail` → `__fortify_fail`
   used `argv[0]` for the message — overwriting argv[0] leaked memory.
   Patched, but check the target glibc.

## PIE / ASLR of the main binary

Mechanism: `-pie -fPIE` produces ET_DYN with INTERP; kernel loads at a random
mmap-region base. Without PIE, ET_EXEC loads at the fixed link address
(0x400000 x86-64 default, 0x08048000 i386).

Check: `readelf -h` Type + `readelf -lW | grep INTERP`. (DYN without INTERP =
shared library, not PIE-the-executable.)

No-PIE plan: everything in the binary is absolute. ret2plt leak:

```
pop rdi; ret → puts@got → puts@plt → ret → main
```

prints the live libc address of `puts`; `libc_base = leak - libc.sym.puts`;
second stage is classic ret2libc. GOT addresses are also fixed → GOT
overwrite target list is known offline.

PIE plan: need one pointer into the binary (or just into libc if you only
need libc). Sources: format string stack spray (`%1$p %2$p …` — return
addresses into `__libc_start_main`/binary main are on the stack),
uninitialized locals printed back, OOB reads, `/proc/<pid>/maps` if any file
read primitive exists. Partial overwrite: low 12 bits fixed (page alignment),
so a 2-byte overwrite of a return address reaches anything within the same
64 KB window at 1-in-16 odds.

## RELRO

Mechanism: `-Wl,-z,relro` maps `.dynamic`, `.got` (non-PLT part),
`.init_array`/`.fini_array` into PT_GNU_RELRO, remapped read-only after
relocation. `-z now` adds eager binding so `.got.plt` can be protected too →
**full RELRO**.

Check: `readelf -lW | grep GNU_RELRO` + `readelf -d | grep -E 'BIND_NOW|NOW'`.

- **No RELRO**: even `.init_array`/`.fini_array`/`.dynamic` writable —
  overwrite a `.fini_array` entry to hijack exit; overwrite `DT_DEBUG`-area
  structures.
- **Partial** (the common default): `.got.plt` writable + lazy binding.
  Prime targets: overwrite `exit@got`→`main` (infinite retries), any
  frequently-called got entry → `system`, with argument control via the
  function's natural first argument (e.g. `strlen@got = system`, then feed
  `"/bin/sh"` to whatever gets strlen'd). Lazy binding also enables
  **ret2dlresolve**.
- **Full**: GOT off the table. Alternatives: glibc `__malloc_hook` /
  `__free_hook` / `__realloc_hook` (removed in glibc 2.34 — check version
  from triage strings), **FSOP** (`_IO_list_all` → fake `_IO_FILE` with evil
  vtable / `_IO_wfile_jumps` gadget chains on modern glibc), `atexit`/
  `__exit_funcs` (pointer-mangled since 2.28: need the mangling cookie from a
  TLS leak), `ld.so` link_map `l_addr` + `DT_FINI` tricks, or pure ROP with a
  stack pivot (`leave; ret`, `xchg rsp, …`).

## FORTIFY_SOURCE

Mechanism: `-D_FORTIFY_SOURCE=2 -O1+` rewrites str/mem/printf calls with
compile-time-known destination sizes to `__*_chk` variants that abort on
overflow (`*** buffer overflow detected ***`). `_FORTIFY_SOURCE=3` (glibc
2.34+) extends to runtime-computed sizes via `__builtin_dynamic_object_size`.

Check: `nm -D ./target | grep _chk`; checksec counts "fortified" vs
"fortifiable" functions.

What survives:
- Calls where the compiler could not see the destination size (`char *p =
  malloc(n)`) stay raw — fortification is per-call-site, so audit the disasm:
  raw `strcpy@plt` next to `__strcpy_chk@plt` in the same binary is normal.
- `%n` is blocked only when the format string lives in **writable** memory;
  leaks via `%s`/`%p`/`%x` always work, so FORTIFY does not stop
  canary/PIE/libc leaking — only the `%n` write primitive.
- `__printf_chk` also validates `%N$` positional usage consistency — spray
  sequential `%p` instead of jumping positions.

## ASLR (system)

`/proc/sys/kernel/randomize_va_space`: 0 off, 1 stack+mmap+vdso, 2 (+heap).
Per-exec randomization; never per-fork. Entropy (x86-64 defaults): mmap/libs
~28 bits, stack ~30, heap (brk) ~13 offset from exe when non-PIE. i386: mmap
~8 bits → brute-forceable in minutes against a respawning service.

Leak economics — what one leaked pointer buys:
- **libc pointer** → all of libc (`system`, `/bin/sh`, gadgets, hooks,
  environ → stack address!). `environ` in libc data holds a stack pointer:
  libc leak → read `environ` → stack leak → return-address overwrite via
  arbitrary write.
- **binary .text pointer** (PIE) → whole binary: PLT, GOT (readable for a
  second-stage libc leak), gadgets.
- **stack pointer** → precise distance to the vulnerable frame's return
  address and canary.
- **heap pointer** → heap grooming becomes deterministic; glibc ≥2.32
  safe-linking means tcache fd pointers are `ptr ^ (addr>>12)` — a heap leak
  gives you the key.

## CET, CFI and friends

- **IBT**: indirect calls/jmps must land on `endbr64`. Compiled-in marker:
  `readelf -n` → GNU_PROPERTY `x86 feature: IBT`. Enforcement needs CPU
  (Tiger Lake+/Zen3+) + kernel + glibc. Effect: JOP/COP targets restricted to
  endbr64 sites; classic ret-based ROP unaffected by IBT alone.
- **SHSTK** (shadow stack): hardware-checked return addresses — ret-based ROP
  dies where enforced. Userspace enforcement is still rare; verify at
  runtime (`/proc/<pid>/status` → `x86_Thread_features: shstk`), don't assume
  from the marker.
- **Clang CFI / Windows CFG**: indirect-call target set checks. Bypass
  classes: data-only attacks, calling a *valid but wrong* in-set function,
  unprotected modules in the same process, JIT regions.
- **Windows**: DEP + ASLR (rebase every boot, per-process for EXEs with
  DYNAMIC_BASE; HIGH_ENTROPY_VA for real 64-bit entropy), SafeSEH/SEHOP
  (32-bit SEH overwrite mitigation), CFG (GUARD_CF), XFG, ACG. Non-ASLR DLL
  in the process = your fixed gadget module.

## Reading the combination

Always write the plan down as: input channel (from `binary-triage`) →
primitive (overflow/fmt/UAF) → leak needs (canary? pie base? libc base?) →
control-flow technique (shellcode/ROP/GOT/FSOP) → payload. Every mitigation
line above answers exactly one slot of that sentence.
