# Formats and architectures — where protections live, and ROP calling conventions

## ELF

| Protection | Where it is encoded | Read with |
|---|---|---|
| NX | PT_GNU_STACK p_flags (RW vs RWE) | `readelf -lW` |
| RELRO | PT_GNU_RELRO segment; DT_BIND_NOW / DT_FLAGS BIND_NOW / DT_FLAGS_1 NOW | `readelf -lW`, `readelf -d` |
| PIE | e_type == ET_DYN **and** PT_INTERP present | `readelf -h`, `readelf -lW` |
| Canary | `__stack_chk_fail` in .dynsym | `nm -D`, `readelf --dyn-syms` |
| FORTIFY | `__*_chk` symbols in .dynsym | `nm -D \| grep _chk` |
| RPATH/RUNPATH | DT_RPATH / DT_RUNPATH | `readelf -d` |
| CET markers | .note.gnu.property: `x86 feature: IBT, SHSTK` | `readelf -n` |

Static binaries: no .dynsym — check canary via `nm ./target | grep
__stack_chk_fail` (if unstripped) or scan disasm for `fs:0x28` reads.

## PE

Protections live in the Optional Header `DllCharacteristics` bitfield and the
Load Config directory:

| Bit | Name | Meaning |
|---|---|---|
| 0x0020 | HIGH_ENTROPY_VA | 64-bit ASLR with full entropy |
| 0x0040 | DYNAMIC_BASE | ASLR opt-in (needs .reloc section to be effective — stripped relocs = no rebase) |
| 0x0100 | NX_COMPAT | DEP |
| 0x0400 | NO_SEH | no SEH at all (32-bit) |
| 0x4000 | GUARD_CF | Control Flow Guard |

- **SafeSEH** (32-bit only): Load Config `SEHandlerTable`/`SEHandlerCount`;
  absent table on a /SAFESEH-less module = SEH overwrite viable.
- **/GS canary**: Load Config `SecurityCookie` pointer; look for
  `__security_check_cookie` in imports/disasm.
- **CFG**: Load Config `GuardCFFunctionTable`; `GUARD_CF` bit set.

Read with: `rabin2 -I file.exe` (nx, pic, canary mapped cross-format),
`objdump -x file.exe | grep -A2 DllCharacteristics`, or where pefile exists:

```
python3 - <<'EOF'
import pefile
pe = pefile.PE("file.exe")
print(hex(pe.OPTIONAL_HEADER.DllCharacteristics))
EOF
```

Plan notes: one non-ASLR module in the process defeats ASLR for gadget
purposes; DEP without ASLR = classic fixed-address ROP; CFG constrains
indirect calls but not returns (pre-XFG).

## Mach-O

- **PIE**: `MH_PIE` flag in the mach header — `otool -hv file | grep PIE` or
  `rabin2 -I` `pic` field. Forced on for modern arm64.
- **NX**: default; `allow_stack_execute` entitlement is the rare exception.
- **Canary**: `___stack_chk_fail` import — `nm -m file | grep stack_chk`.
- **RESTRICT segment / hardened runtime / library validation**: gate
  DYLD_INSERT_LIBRARIES-style injection, not memory corruption.
- Fat binaries: `rabin2 -A` to list slices, `rabin2 -a arm64 -I` or
  `lipo -thin` to pick one before analysis.

## Calling conventions for ROP

The protections read tells you *that* you need ROP; the arch tells you *how
arguments travel*, i.e. which gadgets you must find.

### x86-64 (System V, Linux/macOS)
- Args: RDI, RSI, RDX, RCX, R8, R9; syscall number RAX; syscall args RDI,
  RSI, RDX, **R10**, R8, R9. Return RAX.
- Gadget shopping list: `pop rdi; ret` (arg1), `pop rsi; ret`,
  `pop rdx; ret` (rarer — try `pop rdx; pop rbx; ret` or libc csu gadgets),
  `syscall; ret`, `leave; ret` (pivot).
- **Stack alignment**: `system`/glibc with movaps needs RSP ≡ 0 mod 16 at the
  call — insert one extra `ret` gadget when you segfault inside libc.
- `__libc_csu_init` universal gadget (pre-glibc-2.34 binaries): sets
  rdi/rsi/rdx + indirect call from a static non-PIE binary.

### i386 (cdecl)
- Args on the stack: `[ret][arg1][arg2]…` — ret2libc is just
  `&system; &exit; &"/bin/sh"`. Chaining calls needs `pop; pop; ret`-style
  stack-cleanup gadgets. Syscall: int 0x80, EAX num, EBX ECX EDX ESI EDI.

### ARM (32-bit, EABI)
- Args R0–R3, return address in **LR** — overflows overwrite a saved LR on
  the stack, reached on `pop {…, pc}`. Gadgets end in `pop {…, pc}` or
  `bx lr`. Thumb/ARM interworking: target address bit 0 selects Thumb —
  gadget addresses may need `|1`. Syscall: `svc #0`, num in R7.

### AArch64
- Args X0–X7, syscall num X8, `svc #0`; return via LR (X30). Epilogues are
  `ldp x29, x30, [sp], #N; ret` — chains are built around ldp gadgets, and
  the frame layout (FP saved *below* LR) changes offset math vs x86. PAC
  (`paciasp`/`autiasp` in prologues, armv8.3+) signs LR — a PAC'd binary on
  PAC hardware needs a signing-gadget or data-only approach.

### Universal checks before chain-building
- `rabin2 -I` endian field — big-endian MIPS/PPC firmware flips every
  packed address (`p64(..., endian='big')` in pwntools).
- Static vs dynamic (triage): static = gadgets and syscalls from the binary
  itself, no libc leak needed at all.
