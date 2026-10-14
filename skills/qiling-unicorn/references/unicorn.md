# Unicorn — raw CPU emulation of a single routine

Use Unicorn when you need **one function** out of a binary to execute: a config
decryptor, a password-hash routine, a custom checksum, a string de-obfuscator. No
loader, no syscalls — you map memory, place bytes, set registers, run.

## Core API

```python
from unicorn import *            # Uc, UC_ARCH_*, UC_MODE_*, UC_HOOK_*, UcError
from unicorn.x86_const import *  # UC_X86_REG_*
from unicorn.arm_const import *  # UC_ARM_REG_*
from unicorn.arm64_const import *
from unicorn.mips_const import *

uc = Uc(UC_ARCH_X86, UC_MODE_64)
# other combos: (UC_ARCH_X86, UC_MODE_32), (UC_ARCH_ARM, UC_MODE_ARM|UC_MODE_THUMB),
# (UC_ARCH_ARM64, UC_MODE_ARM), (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

uc.mem_map(addr, size)                       # 4K-aligned addr and size
uc.mem_map(addr, size, UC_PROT_READ|UC_PROT_EXEC)
uc.mem_write(addr, b"...")
data = uc.mem_read(addr, size)               # -> bytearray
uc.reg_write(UC_X86_REG_RDI, 0x600000)
val = uc.reg_read(UC_X86_REG_RAX)
uc.emu_start(begin, until, timeout=0, count=0)   # stops when PC == until
uc.emu_stop()                                # callable from inside a hook
```

Hooks:

```python
uc.hook_add(UC_HOOK_CODE, cb)                        # cb(uc, addr, size, user_data)
uc.hook_add(UC_HOOK_CODE, cb, begin=lo, end=hi)
uc.hook_add(UC_HOOK_BLOCK, cb)
uc.hook_add(UC_HOOK_MEM_READ, cb)                    # cb(uc, access, addr, size, value, ud)
uc.hook_add(UC_HOOK_MEM_WRITE, cb)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, fault_cb)
#   fault_cb returns True after uc.mem_map(...) to retry the access, False to abort
uc.hook_add(UC_HOOK_INTR, cb)                        # int/svc/syscall traps
h = uc.hook_add(...); uc.hook_del(h)
```

Fast snapshot for brute loops (registers + internal CPU state, NOT memory):

```python
ctx = uc.context_save()
...
uc.context_restore(ctx)        # rewrite mutated memory yourself
```

## Extracting the routine's bytes

From the function's file offset and size (your disassembler shows both):

```bash
# ELF: vaddr -> file offset usually differs only by segment delta; easiest:
objcopy -O binary --only-section=.text target text.bin        # whole .text
dd if=target of=fn.bin bs=1 skip=$((0x1a2c)) count=$((0x1f0)) # exact slice
```

Map `.text` at its real vaddr so intra-section calls and rip-relative data still
resolve; also map `.rodata`/`.data` at their vaddrs if the routine touches them.

## Worked micro-example — brute an ARM checksum byte

Firmware validates a 4-byte serial suffix with a custom checksum at `0x104f0`
(Thumb). Recover inputs that pass:

```python
from unicorn import *
from unicorn.arm_const import *
import itertools, struct

CODE_VA, STACK, DATA = 0x10000, 0x7f000000, 0x20000
code = open("text.bin", "rb").read()          # whole .text extracted at CODE_VA

uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
uc.mem_map(CODE_VA & ~0xfff, (len(code) + 0x1fff) & ~0xfff)
uc.mem_write(CODE_VA, code)
uc.mem_map(STACK, 0x10000)
uc.mem_map(DATA, 0x1000)

FN, FN_END = 0x104f0, 0x1055a                 # entry, address of the final 'bx lr'
TARGET = 0x5aa5

# Trap returns: point LR at a mapped-but-nonexistent 'return pad' and stop there.
RET_PAD = DATA + 0xf00

ctx0 = None
def run_once(candidate: bytes) -> int:
    global ctx0
    uc.mem_write(DATA, candidate)
    uc.reg_write(UC_ARM_REG_R0, DATA)         # arg0: buf
    uc.reg_write(UC_ARM_REG_R1, 4)            # arg1: len
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x8000)
    uc.reg_write(UC_ARM_REG_LR, RET_PAD)      # return target
    uc.emu_start(FN | 1, RET_PAD)             # |1 = Thumb bit; stop at the pad
    return uc.reg_read(UC_ARM_REG_R0)

for cand in itertools.product(range(256), repeat=4):
    b = bytes(cand)
    if run_once(b) == TARGET:
        print("valid suffix:", b.hex()); break
```

Notes embedded in that example:
- **Thumb**: start address must have bit0 set in `emu_start`.
- **Return trap**: set LR (or push a fake return address on x86:
  `uc.mem_write(rsp, struct.pack('<Q', RET_PAD))`) to a sentinel and pass it as
  `until` — cleaner than guessing the function's last instruction.
- Calls to *other* functions inside the slice work only if their code is mapped;
  if the routine calls `memcpy`, either map libc's bytes too or hook the call site
  with `UC_HOOK_CODE` and implement it in Python (`uc.mem_write(dst, uc.mem_read(src, n))`
  then set PC past the call).

## x86-64 call: argument/stack setup cheat

```python
uc.reg_write(UC_X86_REG_RSP, STACK + 0x8000)
uc.mem_write(STACK + 0x8000, struct.pack("<Q", RET_PAD))   # fake return address
uc.reg_write(UC_X86_REG_RDI, a0); uc.reg_write(UC_X86_REG_RSI, a1)
uc.reg_write(UC_X86_REG_RDX, a2); uc.reg_write(UC_X86_REG_RCX, a3)
uc.emu_start(FN, RET_PAD)
result = uc.reg_read(UC_X86_REG_RAX)
```

MIPS o32: args in `UC_MIPS_REG_A0..A3`, return in `V0`, return address in `RA`
(set RA to the pad). Big-endian MIPS firmware: `UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN`.

## When Unicorn fights you

| Problem | Fix |
|---|---|
| `UC_ERR_FETCH_UNMAPPED` immediately | begin address not mapped, or Thumb bit missing |
| `UC_ERR_READ_UNMAPPED` mid-run | routine touches .rodata/.data/globals — map those sections at their vaddrs |
| Runs forever | wrong `until`, or routine loops on unemulated state — add a `count=` cap and a UC_HOOK_CODE trace to see where |
| `syscall`/`svc` executed | you grabbed too much; hook UC_HOOK_INTR and emulate, or move up to Qiling |
| FPU/SIMD instruction unsupported | rare on recent Unicorn 2; otherwise patch the insn out or compute that part in Python |

If you find yourself stubbing more than two or three calls, stop — load the whole
binary under Qiling instead; it exists precisely to do that plumbing for you. If you
need the *inverse* (what input makes this routine output X), the sibling `angr` skill
solves it symbolically instead of brute-forcing.
