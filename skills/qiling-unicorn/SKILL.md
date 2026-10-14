---
name: qiling-unicorn
description: Emulate binaries you cannot or should not run natively (foreign-arch firmware userland, extracted daemons, isolated samples) with the Qiling framework, and do raw CPU emulation of single lifted routines with Unicorn — instrument with hooks, intercept syscalls, fake MMIO, snapshot/restore to fuzz, and recover algorithms/keys. Use when a target binary is MIPS/ARM/etc. on an x86 analyst box, needs a firmware rootfs, or when you only need one decode/crypto/checksum function to run.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Qiling + Unicorn emulation

Qiling emulates a whole userland program (loader, syscalls, libc, filesystem) on top of
the Unicorn CPU engine. Unicorn alone emulates raw instructions in a flat address space.

Decision rule:
- **Whole binary** (firmware httpd, CGI, daemon, sample): **Qiling**.
- **One routine** (a decoder, checksum, key schedule you lifted from a disassembler): **Unicorn**.
- Need *constraints solved*, not execution? Load the sibling `angr` skill instead.

Install: `pip install qiling` (pulls in `unicorn`, `capstone`, `keystone-engine`).
Deep API reference: `references/qiling.md`. Raw Unicorn: `references/unicorn.md`.
Output wiring into rupu: `references/rupu.md`.

## 1. Get a rootfs

Qiling resolves the target's interpreter, shared libraries, `/etc`, `/dev` **inside the
rootfs you give it** — never your host `/`.

- **Firmware**: hand off from the `binwalk-firmware` skill. `binwalk -eM firmware.bin`
  yields `_firmware.bin.extracted/squashfs-root/`. That directory *is* the rootfs:
  it already contains the vendor's uClibc/musl, config files, web root.
- **Single cross-arch binary** with no firmware image: clone the prebuilt rootfs set
  (`git clone https://github.com/qilingframework/rootfs`) and use e.g.
  `rootfs/mips32el_linux`, `rootfs/arm_linux`, `rootfs/x8664_linux`. Drop your binary
  anywhere under it.
- Missing pieces (`/etc/passwd`, nvram files, `/dev/urandom`) — create them in the
  rootfs, or redirect at runtime with `ql.add_fs_mapper` (below).

## 2. Run a binary — current API only

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(
    ["squashfs-root/usr/sbin/httpd", "-p", "8080"],   # argv[0..n]
    "squashfs-root",                                   # rootfs
    verbose=QL_VERBOSE.DEFAULT,                        # OFF/DEFAULT/DEBUG/DISASM/DUMP
    multithread=True,                                  # REQUIRED for pthread daemons
)
ql.run()                      # or ql.run(begin=0x401000, end=0x401234, timeout=10_000_000)
```

Arch/OS/endianness are auto-detected from the ELF/PE/Mach-O header. `timeout` is in
microseconds; `count=` limits instruction count.

**Use these spellings — the old ones are gone:**

| Current | Deprecated (do not use) |
|---|---|
| `ql.arch.regs.rdi`, `ql.arch.regs.read("r0")`, `ql.arch.regs.write("pc", x)` | `ql.reg.rdi` |
| `ql.mem.read(addr, size)`, `ql.mem.write(addr, b"..")`, `ql.mem.map(addr, size)`, `ql.mem.search(b"needle")` | `ql.mem_read` / `ql.mem_write` |
| `ql.arch.stack_push(v)`, `ql.arch.stack_pop()`, `ql.arch.stack_read(off)` | `ql.sp`, `ql.stack_read` |
| `ql.arch.regs.arch_pc`, `ql.arch.regs.arch_sp` | `ql.pc`, `ql.sp` |

Useful at any time: `ql.loader.images` (load bases — add the base to IDA/Ghidra static
offsets for PIE binaries), `ql.mem.get_formatted_mapinfo()`, `ql.os.exit_code`.

## 3. Firmware httpd / CGI workflow

1. **Environment**: CGI binaries read everything from env vars.
   ```python
   env = {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": "64",
          "QUERY_STRING": "page=login", "REMOTE_ADDR": "192.0.2.10"}
   ql = Qiling(["squashfs-root/www/cgi-bin/login.cgi"], "squashfs-root", env=env)
   ```
2. **Fake missing files/devices** without touching the rootfs:
   ```python
   ql.add_fs_mapper("/dev/urandom", "/dev/urandom")   # pass through to host
   ql.add_fs_mapper("/etc/config", "./fake_config")   # redirect to local file
   ql.add_fs_mapper("/dev/nvram", MyFakeNvram())      # QlFsMappedObject subclass
   ```
3. **Stub vendor API calls** that would block or crash — nvram getters, watchdogs:
   ```python
   def fake_nvram_get(ql: Qiling):
       # Grab the C-string arg per the arch ABI (ql.os.resolve_fcall_params also works)
       key = ql.os.utils.read_cstring(ql.arch.regs.a0)   # MIPS: a0
       ql.log.info(f"nvram_get({key!r})")
       # write a reply and return its pointer
       buf = ql.os.heap.alloc(32); ql.mem.write(buf, b"admin\x00")
       ql.arch.regs.v0 = buf                              # MIPS return reg
       return
   ql.os.set_api("nvram_get", fake_nvram_get, QL_INTERCEPT.CALL)
   ```
4. **Feed input by intercepting the syscall** instead of real sockets:
   ```python
   def my_read(ql, fd, buf, count):
       payload = CURRENT_INPUT[:count]
       ql.mem.write(buf, payload)
       return len(payload)                 # returned value = syscall return value
   ql.os.set_syscall("read", my_read, QL_INTERCEPT.CALL)   # or ENTER/EXIT to wrap
   ```
5. **Snapshot right after init, restore per attempt** — this is the fuzz/brute loop:
   ```python
   ql.run(end=ADDR_AFTER_PARSE_SETUP)      # run up to the interesting point
   snap = ql.save(mem=True, reg=True, cpu_context=True, os=True, loader=True)
   for candidate in wordlist:
       ql.restore(snap)
       CURRENT_INPUT = candidate
       ql.run(begin=ADDR_AFTER_PARSE_SETUP, end=CHECK_RETURN_ADDR)
       if ql.arch.regs.v0 == 0: print("hit:", candidate); break
   ```
   For coverage-guided fuzzing, Qiling ships an AFL++ bridge:
   `from qiling.extensions.afl import ql_afl_fuzz; ql_afl_fuzz(ql, input_file=..., place_input_callback=..., exits=[...])`
   run under `afl-fuzz -U -- python3 harness.py @@`. Details in `references/qiling.md`.

## 4. Hooks — instrumenting execution

```python
hret = ql.hook_address(cb, 0x401560)         # cb(ql) at exactly this PC
ql.hook_code(lambda ql, addr, size: ...)     # every instruction (slow; use for traces)
ql.hook_block(lambda ql, addr, size: ...)    # every basic block (cheaper trace)
ql.hook_mem_read(cb, begin=0x1E00_0000, end=0x1E00_1000)   # cb(ql, access, addr, size, value)
ql.hook_mem_write(cb, begin=..., end=...)
ql.hook_mem_invalid(cb)                      # catch segfaults, map on demand
hret.remove()                                # or ql.hook_del(hret)
```

**Fake MMIO** the firmware polls (status registers, UART ready bits):
```python
ql.mem.map(0x1E00_0000, 0x1000)              # map the device window first
def mmio_read(ql, access, addr, size, value):
    if addr == 0x1E00_0004:                  # "status" register
        ql.mem.write(addr, (0x1).to_bytes(size, "little"))   # always READY
ql.hook_mem_read(mmio_read, begin=0x1E00_0000, end=0x1E00_1000)
```

**Patch out an anti-analysis / self-check branch** (offsets are image-relative via the
loaded base):
```python
base = ql.loader.images[0].base
ql.patch(base + 0x1a2c, b"\x00\x00\x00\x00")     # MIPS nop
# or dodge at runtime: ql.hook_address(lambda ql: ql.arch.regs.write("pc", base+0x1a40), base+0x1a2c)
```

**Dump arguments at any function** — `scripts/qiling_run.py` does this generically:

```bash
python3 scripts/qiling_run.py squashfs-root/bin/upnpd squashfs-root \
    --func 0x40a310 --nargs 3 --arg "-f" --env REQUEST_METHOD=POST \
    --out trace.json --work-units units.json
```

It logs every executed block, dumps register args + dereferenced strings at `--func`
on each hit, writes a JSON trace, and emits a rupu work-unit file (`references/rupu.md`).

## 5. Unicorn directly — one routine, no OS

Lift the function bytes from the binary, map code + stack + I/O buffers, set the ABI
registers, run from entry to the return point. Perfect for recovering a config
decryptor or brute-forcing a checksum/key byte-by-byte at millions of calls/second.

```python
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RSP, UC_X86_REG_RAX

CODE_ADDR, STACK, DATA = 0x400000, 0x7f0000, 0x600000
with open("decode_fn.bin", "rb") as f: code = f.read()   # dd/objcopy'd from the ELF

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(CODE_ADDR, 0x10000); uc.mem_write(CODE_ADDR, code)
uc.mem_map(STACK, 0x10000);     uc.mem_map(DATA, 0x1000)
uc.mem_write(DATA, bytes.fromhex("9f3a..."))              # the ciphertext blob
uc.reg_write(UC_X86_REG_RSP, STACK + 0x8000)
uc.reg_write(UC_X86_REG_RDI, DATA)                        # arg1: buf
uc.reg_write(UC_X86_REG_RSI, 0x20)                        # arg2: len
uc.emu_start(CODE_ADDR, CODE_ADDR + len(code))            # begin, end(=until PC)
print(uc.mem_read(DATA, 0x20))                            # recovered plaintext
```

`uc.hook_add(UC_HOOK_CODE, lambda uc, a, sz, _: print(hex(a)))` traces instructions;
`uc.emu_stop()` inside a hook halts; `uc.context_save()/context_restore()` is the fast
register-only snapshot for brute loops. Full worked micro-example (ARM checksum brute,
calling conventions table, ret-trap trick) in `references/unicorn.md`.

## 6. Reading results and handing off

- **Crash during emulation** (`ql.mem` unmapped write at attacker-reachable data,
  symbolized PC overwritten): confirm overflow, compute offset, then load the
  `pwntools` and `rop-chains` skills to build the real exploit; load `angr` to solve
  for precise constraint-satisfying input.
- **Recovered algorithm / key / credential** (decrypted config, nvram default creds,
  checksum reversed): report via rupu `findings.report` per the `finding-report` skill.
- **Reached a dangerous sink in emulation** (`system()`, `strcpy` into fixed buffer
  with your bytes): mark the function with `assets.mark` (`binary:symbol`, depth
  `vuln-identified`) — exact field contract in `references/rupu.md`.
- Keep `trace.json`, snapshots, and raw emulation logs in the run workspace as evidence.

## Troubleshooting quick hits

| Symptom | Fix |
|---|---|
| `FileNotFoundError` on ld.so / libc | Wrong rootfs; use the firmware's own squashfs-root or the matching qiling prebuilt rootfs |
| Hangs in `pthread_create` / `accept` | Construct with `multithread=True`; intercept `accept`/`read` with `set_syscall` instead of real networking |
| Dies in `ioctl`/`nvram` vendor call | `ql.os.set_api`/`set_syscall` stub returning success |
| Invalid mem read at a weird high address | MMIO poll — `ql.mem.map` + `hook_mem_read` fake it |
| PIE offsets don't match disassembler | Add `ql.loader.images[0].base` to static offsets |
| Old blog code with `ql.reg`/`ql.mem_read` | Port to `ql.arch.regs` / `ql.mem.*` — the old names were removed |
