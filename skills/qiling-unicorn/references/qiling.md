# Qiling — current API reference and firmware workflow

Everything here uses the **current** API (Qiling >= 1.4). Old spellings
(`ql.reg`, `ql.mem_read`, `ql.sp`, `ql.nprint`) were removed; port any old blog code.

## Construction

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT

ql = Qiling(
    argv=["rootfs/bin/target", "arg1", "arg2"],  # argv[0] = path inside/under rootfs
    rootfs="rootfs",
    env={"PATH": "/bin", "QUERY_STRING": "a=1"}, # dict[str,str] or dict[str,bytes]
    verbose=QL_VERBOSE.DEBUG,    # OFF | DEFAULT | DEBUG | DISASM | DUMP
    multithread=True,            # emulate threads; needed for pthread daemons
    console=True,                # False -> silence target stdout to log only
    log_file="run.log",
)
```

Also accepted: `code=b"..."` + `archtype=`/`ostype=` for shellcode-mode (no file),
`profile="profile.ql"` for ini-style OS tuning (heap size, mmap base, uid).

Run control:

```python
ql.run()                                     # from entry point to exit
ql.run(begin=0x401000, end=0x40123c)         # partial execution window
ql.run(timeout=10_000_000)                   # microseconds
ql.run(count=1_000_000)                      # max instructions
ql.stop()                                    # from inside a hook
ql.emu_error()                               # dump regs+maps after a crash
```

## Memory — `ql.mem`

```python
data = ql.mem.read(addr, size)               # -> bytearray
ql.mem.write(addr, b"\x90\x90")
ql.mem.map(addr, size, info="[fake_mmio]")   # addr/size page-aligned
ql.mem.unmap(addr, size)
ql.mem.map_anywhere(size)                    # -> addr
hits = ql.mem.search(b"admin")               # list of addresses, whole mem
hits = ql.mem.search(b"\x7fELF", begin=lo, end=hi)
ql.mem.string(addr)                          # read NUL-terminated str
print(ql.mem.get_formatted_mapinfo())        # /proc/self/maps-style listing
```

`ql.patch(offset, b"...")` patches **image-relative** (applied after load, survives
nothing — it is a live write at `base+offset`); `ql.patch(addr, b"...", target='lib.so')`
patches inside a named loaded image.

## Registers / stack — `ql.arch`

```python
ql.arch.regs.rdi = 0x1000            # attribute access, any arch reg name
v = ql.arch.regs.read("r0")          # by-name read
ql.arch.regs.write("pc", addr)
pc = ql.arch.regs.arch_pc            # arch-independent PC
sp = ql.arch.regs.arch_sp            # arch-independent SP
ql.arch.stack_push(0xdeadbeef)
ql.arch.stack_pop()
ql.arch.stack_read(8)                # [sp+8]
ql.arch.stack_write(8, value)
```

ABI argument registers (for arg-dumping hooks):

| Arch | args | return |
|---|---|---|
| x8664 (SysV) | rdi, rsi, rdx, rcx, r8, r9 | rax |
| x86 (cdecl) | stack: `ql.arch.stack_read(4*(i+1))` | eax |
| ARM (AAPCS) | r0–r3 | r0 |
| ARM64 | x0–x7 | x0 |
| MIPS o32 | a0–a3, then stack sp+16.. | v0 |
| RISC-V | a0–a7 | a0 |

Or let Qiling do it: `params = ql.os.resolve_fcall_params({'buf': POINTER, 'len': INT})`
inside an API hook (types from `qiling.os.const`).

Helpers: `ql.os.utils.read_cstring(ptr)`, `ql.os.heap.alloc(n)` /
`ql.os.heap.free(ptr)` for building replies in stubs.

## Hooks

All hook installers return a handle; `handle.remove()` or `ql.hook_del(handle)`.

```python
ql.hook_address(cb, addr)                 # cb(ql) — fires at exact PC
ql.hook_code(cb)                          # cb(ql, addr, size) — every insn
ql.hook_code(cb, begin=lo, end=hi)        # restrict range (big speedup)
ql.hook_block(cb)                         # cb(ql, addr, size) — every basic block
ql.hook_intno(cb, intno)                  # software interrupts
ql.hook_insn(cb, UC_X86_INS_SYSCALL)      # specific instruction
ql.hook_mem_read(cb, begin=, end=)        # cb(ql, access, addr, size, value)
ql.hook_mem_write(cb, begin=, end=)
ql.hook_mem_unmapped(cb)                  # on fault: map+return True to retry
ql.hook_mem_invalid(cb)
```

Hooks run **before** the event (mem-read hooks fire before the value is fetched, so
`ql.mem.write(addr, fake)` inside the hook controls what the guest reads — this is how
MMIO faking works).

### Call/return tracing pattern

```python
calls = []
def on_block(ql, addr, size):
    calls.append(addr)
ql.hook_block(on_block)
```

Then symbolize offline: subtract `ql.loader.images[i].base`, feed to your
disassembler's function list. (This is exactly what `scripts/qiling_run.py` emits.)

## Syscall and API interception — `ql.os`

```python
from qiling.const import QL_INTERCEPT

# Replace the syscall entirely (CALL), or wrap it (ENTER adjusts args before the
# built-in impl runs, EXIT sees/overrides the return value after).
def my_read(ql, fd: int, buf: int, count: int) -> int:
    ql.mem.write(buf, b"GET /admin HTTP/1.0\r\n\r\n"[:count])
    return min(count, 23)
ql.os.set_syscall("read", my_read, QL_INTERCEPT.CALL)
ql.os.set_syscall(0x3f, my_read, QL_INTERCEPT.CALL)      # by number works too

def on_write_exit(ql, fd, buf, count, retval):
    ql.log.info(f"write({fd}) -> {bytes(ql.mem.read(buf, count))!r}")
    return retval
ql.os.set_syscall("write", on_write_exit, QL_INTERCEPT.EXIT)

# Library-level (PLT/dynamic symbol) interception — hooks the *function*, not the
# syscall. ENTER/EXIT also available.
def fake_system(ql):
    cmd = ql.os.utils.read_cstring(ql.arch.regs.rdi)
    ql.log.warning(f"system({cmd!r}) BLOCKED — command injection sink reached")
    ql.arch.regs.rax = 0
ql.os.set_api("system", fake_system, QL_INTERCEPT.CALL)
```

An intercepted `system()`/`popen()`/`execve()` that receives your input verbatim is a
confirmed command injection: capture the string, report it (see `references/rupu.md`).

## Filesystem redirection — `ql.add_fs_mapper`

```python
ql.add_fs_mapper("/proc/cpuinfo", "./fake_cpuinfo")     # guest path -> host file
ql.add_fs_mapper("/dev/urandom", "/dev/urandom")        # pass-through
```

Custom device object:

```python
from qiling.os.mapper import QlFsMappedObject

class FakeNvram(QlFsMappedObject):
    def read(self, size):   return b"wan_ip=203.0.113.7\n"[:size]
    def write(self, data):  return len(data)
    def ioctl(self, cmd, arg): return 0
    def fstat(self):        return -1
    def close(self):        return 0

ql.add_fs_mapper("/dev/nvram", FakeNvram())
```

## Snapshot / restore and fuzzing

```python
snap = ql.save(mem=True, reg=True, cpu_context=True, os=True, loader=True, fd=True)
# ... mutate, run ...
ql.restore(snap)
```

Save to disk for cross-process reuse: `ql.save(..., snapshot="state.bin")`,
later `ql.restore(snapshot="state.bin")`.

Brute loop skeleton (password check inside a CGI):

```python
ql.run(end=CHECK_FN)                          # stop right at the check
snap = ql.save()
for pw in wordlist:
    ql.restore(snap)
    buf = ql.arch.regs.a0                     # arg already points at input buffer
    ql.mem.write(buf, pw.ljust(16, b"\x00"))
    ql.run(begin=CHECK_FN, end=CHECK_RET)
    if ql.arch.regs.v0 == 1:
        print("password:", pw); break
```

### AFL++ via unicornafl

```python
from qiling.extensions.afl import ql_afl_fuzz

def place_input(ql, data, _round):
    if len(data) > 0x100: return False
    ql.mem.write(INPUT_BUF, data)
    return True

ql.run(end=MAIN_ADDR)      # execute init once, fork server starts here
ql_afl_fuzz(ql, input_file=sys.argv[1], place_input_callback=place_input,
            exits=[EXIT_ADDR])
```

Run: `afl-fuzz -i in -o out -U -- python3 harness.py @@`. Crashing inputs are real
PoCs — triage the crash PC/registers by replaying the input in a plain Qiling run with
`verbose=QL_VERBOSE.DEBUG`, then hand to `pwntools`/`rop-chains` for exploitation.

## Other extensions

- `from qiling.extensions import pipe` — `ql.os.stdin = pipe.SimpleInStream(0)` then
  `ql.os.stdin.write(b"input\n")` to script stdin without a real tty.
- `from qiling.extensions.coverage import utils as cov` —
  `with cov.collect_coverage(ql, 'drcov', 'out.cov'):` produces DynamoRIO-format
  coverage loadable in Lighthouse/lightkeeper over your IDA/Ghidra DB.
- GDB stub: `ql.debugger = True` (listens :9999) or `"gdb:0.0.0.0:9999"` — attach
  cross-arch `gdb-multiarch`, set breakpoints in the emulated process.
- `ql.debugger = "qdb"` for the built-in CLI debugger.

## Windows / PE notes

Same API. Rootfs = `rootfs/x8664_windows` from the qiling rootfs repo; you must copy
real system DLLs into `rootfs/.../Windows/System32` (the repo README script fetches
them). `ql.os.set_api("CreateFileW", ...)` style interception works on Win32 APIs.
Registry is emulated from `rootfs/.../Windows/registry` JSON files. This makes Qiling
a decent malware-sample detonation cage: samples run with no real OS beneath them.
