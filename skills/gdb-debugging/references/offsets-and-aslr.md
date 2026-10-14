# Offsets and ASLR — the full method

## 1. De Bruijn / cyclic patterns

A De Bruijn sequence over alphabet `a-z` with subsequence length n guarantees every
n-byte window is unique, so any n bytes you recover from a register or stack slot map
back to exactly one offset in the input. Defaults differ:

- pwntools `cyclic` / `cyclic_find`: **n=4** (works for 32- and 64-bit — on amd64 the
  low dword of the leaked qword is looked up).
- GEF `pattern create` / pwndbg `cyclic`: **n=8 on amd64**, n=4 on i386.

Mixing tools with mismatched n silently fails the lookup ("pattern not found"). Pass
`-n 4` (pwndbg) / `pattern create 200 4` (GEF) / `cyclic(200, n=8)` (pwntools) to align.
`scripts/gdb_offset.py` tries both n=8 and n=4 automatically.

## 2. Where the pattern lands, per crash shape (amd64)

| Crash shape | Where to look | Why |
|---|---|---|
| `ret` faults, RIP = address of the ret | `x/gx $rsp` → pattern qword | non-canonical addresses (>47 bits set wrongly) can't be loaded into RIP; the ret faults with the pattern still on the stack |
| RIP itself = `0x6161616261616161`-style | `$rip` | 32-bit, or an address that happened to be canonical, or an indirect call through a controlled pointer |
| SIGSEGV on a mov, fault addr = pattern | gdb's "si_addr" / `p $_siginfo._sifields._sigfault.si_addr` | you control a POINTER, not the return address — arbitrary read/write primitive instead |
| `$rbp` = pattern | `$rbp` | saved-RBP offset; saved-RIP is usually +8 past it |
| `__stack_chk_fail` backtrace, no segv | canary tripped | overflow confirmed but canary blocks; you need a leak or a non-linear write — note it and pivot |

Check all of: `$rip`, `*(long*)$rsp`, `*(long*)($rsp+8)`, `$rbp`, si_addr.

## 3. Offsets ≠ addresses: computing bases at runtime

ASLR randomizes mapping BASES per-exec; everything inside a mapping keeps fixed
relative offsets. So:

```
libc_base   = leaked_libc_addr − static_offset_of_that_symbol_in_libc
system      = libc_base + offset(system)
binsh       = libc_base + offset("/bin/sh")
pie_base    = leaked_binary_addr − static_offset_in_binary
```

Get static offsets from the exact libc the target uses:

```
ldd ./target                          # which libc file
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep ' system@'
strings -tx libc.so.6 | grep /bin/sh  # offset of the string
```

In gdb, with the process live:

```
vmmap libc            # base = start of the first r--p libc mapping (NOT the r-xp one on modern glibc — the FIRST segment)
p &system             # absolute; subtract vmmap base to get/verify the static offset
piebase               # pwndbg: PIE base
info proc mappings    # plain gdb fallback
```

Leak sources, in rough order of availability: format string (`%p`/`%s` of a GOT
entry), puts/printf of an uninitialized or over-read buffer containing a stale libc
pointer (unsorted-bin fd pointers are libc addresses: `main_arena+96`), partial GOT
read, stack leak of `__libc_start_main` return address.

## 4. ASLR inside vs outside gdb

- gdb **disables** ASLR for processes it launches (`set disable-randomization on` is
  the default). Addresses look stable (`0x7ffff7...`) — great for development, a trap
  for the final exploit.
- `set disable-randomization off` (or pwndbg/GEF `aslr on`) re-enables it in-debugger:
  always do a final run this way to confirm the exploit computes bases from leaks
  rather than using baked-in debugger addresses.
- Attaching (`gdb -p`) does NOT change the target's existing randomization — attach
  runs reflect reality.
- The environment also shifts the stack: argv/envp sizes change `$rsp` even with ASLR
  off. `env -i ./target` and matching env in gdb (`show env`, `unset env LINES`,
  `unset env COLUMNS` — gdb injects those two) reduce drift when stack addresses
  matter.
- Core dumps preserve the randomized layout of the crashed run: `gdb ./target core`
  then `info proc mappings` / `vmmap` gives you the bases of THAT run — useful to
  verify a leak you captured remotely.

## 5. Offset-finding without a debugger (sanity checks)

```
ulimit -c unlimited
./target < pattern.bin ; gdb -q ./target core -ex 'x/gx $rsp' -ex q
dmesg | tail        # kernel logs "ip ... sp ..." on segfaults — quick fault value
```

`scripts/gdb_offset.py` automates the gdb-batch version of this.
