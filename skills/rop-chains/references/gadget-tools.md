# Gadget tooling: ROPgadget, ropper, one_gadget, r2

## ROPgadget

```bash
pip install ROPgadget
ROPgadget --binary ./target                      # dump all gadgets
```

Key flags:

| flag | effect |
|---|---|
| `--binary FILE` | target (ELF/PE/Mach-O; x86/x64/ARM/ARM64/MIPS/PPC/SPARC/RISC-V) |
| `--depth N` | max gadget length in instructions (default 10; raise for exotic chains) |
| `--only "pop\|ret"` | keep gadgets made ONLY of these mnemonics |
| `--re 'pop rdi'` | regex filter on the instruction text |
| `--badbytes "00\|0a"` | drop gadgets whose address contains these bytes |
| `--ropchain` | auto-generate an execve("/bin/sh") chain (works best on static x86/x64) |
| `--string "/bin/sh"` | find a string's vaddr |
| `--memstr "/bin/sh"` | build the string from scattered single bytes |
| `--opcode c3` | search raw opcode bytes |
| `--offset 0x400000` | add a base to printed addresses (pre-rebase for PIE) |
| `--range 0x1000-0x3000` | restrict search to a vaddr range |
| `--thumb` | ARM thumb mode |
| `--rawArch x86 --rawMode 64` | treat input as a raw blob |
| `--multibr` | include multiple-branch gadgets |
| `--all` | show duplicate gadgets at every address |
| `--dump` | show gadget opcode bytes |

Output format: `0x0000000000401234 : pop rdi ; ret` — address, colon, sequence.
Final line `Unique gadgets found: N`. `--ropchain` appends a "ROP chain
generation" section with ready `p += pack('<Q', ...)` python lines; sanity-check
the writes (it builds "/bin/sh" in .data via mov-write gadgets, then
`int 0x80`/`syscall` execve).

Pitfalls: default depth misses long csu gadgets; ROPgadget finds *misaligned*
gadgets (x86 variable-length encoding) that objdump never shows — these are
legitimate and often the only `pop rdi` in tiny binaries.

## ropper

```bash
pip install ropper
ropper --file ./target                           # all gadgets, colored
ropper --file ./target --nocolor                 # parse-friendly
```

Key flags:

| flag | effect |
|---|---|
| `--search "pop rdi"` | semantic search; prints matches with quality score |
| `--search "% ; ret"` | `%` wildcards a whole instruction, `?` a char |
| `--search "mov [%], %"` | find write-what-where gadgets |
| `--chain execve` | auto chain; also `--chain "execve cmd=/bin/sh"` |
| `--chain "mprotect address=0x401000 size=0x1000"` | mprotect chain |
| `--badbytes 000a` | hex string of forbidden address bytes |
| `--type rop` | `rop` (ret), `jop` (jmp/call), `sys` (syscall), `all` |
| `--inst-count N` | max gadget length |
| `--stack-pivot` | list only pivot gadgets |
| `--jmp rsp` | find jmp/call-reg gadgets (`--jmp "rsp,rax"`) |
| `--ppr` | pop-pop-ret (SEH, 32-bit Windows) |
| `--opcode ffe4` / `--instructions "jmp esp"` | raw/assembled opcode search |
| `--string "/bin/sh"` | string vaddr |
| `-I 0x555555554000` | print addresses rebased to this image base |
| `--arch x86_64 --raw` | raw blob mode |
| `--console` | interactive mode (`search`, `chain`, `badbytes` as commands) |

Output format: `0x0000000000401234: pop rdi; ret;` — note semicolon-terminated,
no spaces around the colon; normalize before comparing with ROPgadget output.
`--search` prints `[INFO] Searching for gadgets: ...` headers on stderr-ish lines;
skip non-`0x`-prefixed lines when parsing.

ropper vs ROPgadget: run both — their disassemblers (capstone configs) disagree on
edge cases, and each finds gadgets the other misses. `scripts/find_gadgets.py`
merges them.

## one_gadget

```bash
gem install one_gadget
one_gadget ./libc.so.6
one_gadget ./libc.so.6 --level 1       # more candidates, weaker constraints
one_gadget ./libc.so.6 --raw           # addresses only (scripting)
one_gadget ./libc.so.6 --near exit     # order by distance to a function
one_gadget --build-id 0123abcd...      # by libc build-id (from a GOT leak dump)
```

Output per candidate:

```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```

The address is a LIBC OFFSET — final address = `libc.address + 0xe3afe`.
Verifying constraints: in gdb, break at your control point (the overwritten
return / the hooked call) and inspect each named register and `[rsp+N]` slot.
Typical wins: `rsi == NULL` after `pop rsi; ret` with 0; `rdx == NULL` right
after many read/puts paths. If every candidate fails, fall back to a full
`execve` chain from libc gadgets (libc has every `pop` you need).

## radare2 / rizin

```bash
r2 -q -c '/R pop rdi' ./target        # gadget search ending in ret
r2 -q -c '/R/ pop r[ds]i' ./target    # regex form
r2 -q -c '/Rj pop rdi' ./target       # JSON output
# in-session: e search.in=io.maps.x ; /R leave
```

Useful when ROPgadget/ropper are unavailable or when you want gadget search over
a live-attached process (`r2 -d`), including libraries at their real bases.

## Choosing between results

1. Prefer gadgets in the main binary (no leak needed on no-PIE).
2. Prefer short gadgets without memory dereferences (a `pop rdi ; ret` beats
   `pop rdi ; mov [rax], rbx ; ret` — the latter crashes unless rax is mapped).
3. Respect bad bytes: anything your input channel mangles (`\x00` for strcpy,
   `\x0a` for fgets/gets, `\x20\x09` for scanf("%s")).
4. After rebasing (PIE/libc), re-check bad bytes — they apply to the FINAL address.
