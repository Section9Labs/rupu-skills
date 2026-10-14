# Integer overflow / underflow / signedness / truncation

## (a) Source patterns

**Multiplication/addition wrap** feeding an allocation:

```c
items = read_u32(in);                     // attacker: 0x40000001
buf = malloc(items * sizeof(uint32_t));   // 32-bit: wraps to 4
for (i = 0; i < items; i++) buf[i] = ..;  // writes 4GB -> heap overflow
// also: malloc(len + 2) with len = 0xffffffff -> malloc(1)
```

**Signed check, unsigned use**:

```c
int len = read_i32(in);                   // attacker: -1
if (len > MAX) return -1;                 // -1 passes the signed check
memcpy(dst, src, len);                    // size_t: 0xffffffffffffffff
```

**Underflow**: `n - hdr_size` with `n < hdr_size` → huge unsigned.
**Truncation**: `size_t` → `uint16_t`/`int` loses high bits: check uses the
wide value, allocation uses the narrow one (or vice versa).

## (b) Binary / disassembly signature

- Arithmetic directly feeding malloc with no guard:

```
mov    eax, dword [rbx]       ; attacker count (32-bit!)
shl    eax, 2                 ; *4 — can wrap in 32 bits
mov    edi, eax
call   malloc@plt             ; no jo/cmov guard, not calloc
```

  Guarded code looks different: `mul` + `jo`, or a `cmp` against
  `SIZE_MAX/size` before, or `calloc(n, size)` (which checks internally),
  or the `__builtin_mul_overflow` pattern (mul + seto).
- **Signedness mismatch**: sign-extension `movsx rdx, eax` into a size
  register; a **signed** branch (`jl/jg/jle/jge`) guarding a value later
  consumed by an **unsigned** context (`jb/ja` elsewhere, or `rdx` of
  `memcpy`, or `rdi` of `malloc`). `cmp eax, 0x400; jle ok` followed by
  `movsxd rdx, eax; call memcpy` is the canonical sighting.
- **Truncation**: value computed in `rax` but only `ax`/`eax` stored or
  compared (`mov word [..], ax`), with the full value used elsewhere.
  Note: 32-bit ops zero the upper half (an implicit truncation), `movzx`
  vs `movsx` tells you unsigned vs signed interpretation.
- Ghidra decompiler renders these as casts: `malloc((uint)(len * 4))`,
  `if ((int)len < 0x400) memcpy(dst, src, (ulong)len)` — grep decompiled
  output for `(int)`, `(uint)`, `(short)` near malloc/memcpy.

## (c) Dynamic confirmation

Drive the boundary values through the input field in question:

| Value | Tests |
|---|---|
| `0` | zero-alloc then write; `n-1` underflow |
| `-1` / `0xffffffff` | signed check bypass; `+1` wrap to 0 |
| `0x7fffffff` | signed max; `+1` flips sign |
| `0x80000000` | signed min; abs()/negation bugs |
| `0x40000001` (×4), `0x2aaaaaab` (×6)... | 32-bit multiplication wrap |
| `0xffff`, `0x10000` | 16-bit truncation edges |

In gdb: `break malloc`, run with the boundary input, `p/x $rdi` — compare
the actual allocation size with the later copy length (`break memcpy`,
`p/x $rdx`). Tiny alloc + huge copy = confirmed.

Sanitizers: build with `-fsanitize=undefined` → `runtime error: signed
integer overflow: 1073741825 * 4 cannot be represented...` (note: unsigned
wrap is *defined* in C — use `-fsanitize=unsigned-integer-overflow` to flag
it anyway). ASan downstream reports: `allocation-size-too-big`,
`negative-size-param`, or simply the resulting heap-buffer-overflow.

The `fuzzing` skill finds these fastest with CmpLog plus a dictionary of
the boundary constants above.

## (d) Primitive and hand-off

The integer bug is a *root cause*; the primitive is whatever the wrong
size produces:

- Undersized `malloc` + full-length write → **heap overflow** →
  `heap-exploitation` (see `references/heap-overflow.md`).
- Huge `memcpy` length → usually a wild crash, but a short controlled OOB
  write before the fault can be enough — check what lies after the
  destination.
- Negative index / wrapped offset → OOB read (leak) or targeted OOB write.
- Stack destination → **stack overflow** → `rop-chains`.

Report the root cause as the integer bug (fixers need that), exploit it as
the resulting class.

## Worked micro-example

```c
// gcc -m32 -o intov intov.c   (32-bit makes the wrap obvious)
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    unsigned int n; char tmp[4096];
    fread(&n, 4, 1, stdin);
    unsigned int total = n * 4;          // wraps
    char *buf = malloc(total);
    size_t got = fread(tmp, 1, sizeof tmp, stdin);
    for (unsigned i = 0; i < n && i*4 < got; i++)   // bounded by n, not total
        memcpy(buf + i*4, tmp + i*4, 4);
    printf("%u -> alloc %u\n", n, total);
}
```

Input `n = 0x40000001` → `total = 4`, loop happily writes past the 4-byte
chunk: ASan `heap-buffer-overflow`, root cause the `n * 4` at line 7.
