# Off-by-one and null-byte overflow

## (a) Source patterns

**Classic `<=` loop**:

```c
char buf[64];
for (i = 0; i <= 64; i++) buf[i] = src[i];   // writes buf[64]: one past
```

**Terminator one past the end** (the "null byte poison"):

```c
char *p = malloc(size);
read_exact(fd, p, size);
p[size] = '\0';                 // index == size: writes into the NEXT chunk
// also: strlen-based: buf[strlen(s)] after a copy that already filled buf;
// snprintf(buf, sizeof(buf)+1, ...); strncat(dst, src, sizeof(dst)) [counts
// src bytes, still appends NUL]; off-by-one in a bounds check (idx <= max).
```

The overflow is exactly **one byte**, usually `\0` — looks harmless, is not.

## (b) Binary / disassembly signature

- Loop bound using `jle`/`jbe` against the exact buffer size (where `jl`/
  `jb` would be correct):

```
cmp    eax, 0x40
jle    loop_body            ; <= size: one extra iteration
```

- Isolated single-byte store at `[base + size]` right after a copy:

```
call   memcpy@plt            ; copies `size` bytes
mov    rax, qword [rbp-0x18] ; base
mov    rcx, qword [rbp-0x20] ; size
mov    byte [rax+rcx], 0     ; terminator at index == size  <-- the byte
```

- Ghidra: `local_48[uVar1] = 0;` where `local_48` is `char local_48[uVar1]`
  / `p[size] = '\0'` right after `malloc(size)`. Compare the index
  expression against the allocation/declaration size — equal ⇒ off-by-one.
- `strncat(dst, src, sizeof(dst))` call sites: third arg equals the full
  destination size (correct code passes `sizeof(dst)-strlen(dst)-1`).

## (c) Dynamic confirmation

- ASan: `heap-buffer-overflow WRITE of size 1 ... 0 bytes to the right of
  N-byte region` — the size-1-at-region-end signature is specific to this
  class (so `scripts/classify_crash.py` keys on it). Stack variant:
  `stack-buffer-overflow WRITE of size 1`.
- Poison-null-byte effect in pwndbg (heap case — note malloc(0x88)-style
  sizes matter, the NUL must hit the next chunk's `size` LSB):

```
pwndbg> vis_heap_chunks
0x...290  0x0000000000000000  0x0000000000000091   <- victim size 0x91
# trigger the p[size]=0 write
pwndbg> vis_heap_chunks
0x...290  0x0000000000000000  0x0000000000000000   <- wait, LSB case:
# 0x91 -> 0x00? no: single NUL at the right offset turns 0x101 into 0x100
# i.e. size shrinks AND prev_inuse clears -> allocator thinks prev is free
```

  The canonical setup: next chunk size `0x101` → NUL write → `0x100`
  (prev_inuse cleared). Then `free(next)` consults the (attacker-forged)
  `prev_size` and backward-consolidates **over the victim** → overlapping
  chunks.
- Stack variant: one byte into saved RBP's low byte → on `leave; ret` the
  caller's frame shifts — confirm by watching `rbp` get its LSB zeroed and
  the parent function misbehave.

## (d) Primitive and hand-off

- **Heap null-byte**: next-chunk `size` LSB / `prev_inuse` corruption →
  backward consolidation with forged `prev_size` → overlapping chunks →
  full read/write of a live chunk → tcache poisoning → arbitrary write.
  This is the "poison null byte" / House-of-Einherjar family — load
  `heap-exploitation` with glibc version in hand (≥2.29 adds a
  `prev_size == chunk size` consolidation check; needs an extra forged
  header).
- **One non-NUL byte**: partial overwrite of a pointer's low byte —
  redirect within a page (e.g. bend a `fd` pointer to an adjacent fake
  chunk) → `heap-exploitation`.
- **Stack off-by-one over saved RBP**: frame pivot — caller's locals move,
  `ret` eventually consumes attacker stack data → `rop-chains`.

## Worked micro-example

```c
// gcc -g -fsanitize=address -o nul nul.c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    size_t size = 0x88;
    char *a = malloc(size);
    char *b = malloc(0xf8);         // victim: size field 0x101
    fread(a, 1, size, stdin);
    a[size] = '\0';                 // off-by-one NUL -> b's size LSB
    free(b); free(a);
    (void)printf("%p %p\n", a, b);
}
```

ASan: `heap-buffer-overflow WRITE of size 1 ... 0 bytes to the right of
136-byte region`. Plain build in pwndbg: `b`'s chunk size `0x101 → 0x100`
after the write — the exact precondition `heap-exploitation` builds on.
