# Heap buffer overflow

## (a) Source pattern

A write past the end of a `malloc`'d chunk — the copy length and the
allocation size come from different expressions:

```c
char *p = malloc(len);              // size from header field
memcpy(p, body, body_len);          // size from actual data -> can exceed len
// also: strcpy into malloc(strlen(a)) then strcat(p, b);
// p = malloc(n); for (i = 0; i < m; i++) p[i] = src[i];  // m != n
// records: malloc(sizeof(struct s)) then writing a flexible array unbounded
```

Often downstream of an integer bug (`references/integer-bugs.md`): the
allocation was undersized by a wrap, the copy is "correct".

## (b) Binary / disassembly signature

```
mov    edi, dword [rbx+0x8]     ; alloc size = header.len
call   malloc@plt
mov    r12, rax                 ; chunk ptr
...
mov    rdx, qword [rbx+0x10]    ; copy size = header.body_len   <-- different!
mov    rsi, r14
mov    rdi, r12
call   memcpy@plt
```

Markers:

- `call malloc` where the size register (`rdi`/`edi`) and a later
  `memcpy/strcpy/loop` length trace back to **different** input fields, or
  the copy is unbounded (`strcpy/strcat/sprintf` into heap memory).
- In Ghidra: `pvVar1 = malloc(uVar2); memcpy(pvVar1, src, uVar3);` — diff
  the two size expressions and ask "can uVar3 > uVar2?".
- r2: `axt @ sym.imp.malloc` to list all malloc call sites, then inspect
  each caller's copy code.
- Write loops: `mov byte [rax+rcx], dl; inc rcx; cmp rcx, <len>; jb` where
  `<len>` isn't derived from the malloc size.

## (c) Dynamic confirmation

- ASan (best): `heap-buffer-overflow ... WRITE of size N ... 0 bytes to
  the right of 64-byte region [0x602...,0x602...) allocated by thread T0
  here:` — gives the overflowing write stack AND the allocation stack.
- pwndbg without ASan:

```
pwndbg> break *<addr of memcpy call>
pwndbg> r < input
pwndbg> vis_heap_chunks        # note the next chunk's size field
pwndbg> ni                     # step over the copy
pwndbg> vis_heap_chunks        # size/fd of the next chunk now overwritten?
pwndbg> heap                   # glibc may also abort later: malloc(): corrupted top size
```

- glibc aborts (`malloc(): invalid size`, `corrupted size vs. prev_size`,
  `free(): invalid next size`) on the *next* allocator call are the
  no-sanitizer tell: corruption happened earlier — set a hardware
  watchpoint on the corrupted header (`watch *(long*)0x...`) and rerun.

## (d) Primitive and hand-off

You overwrite whatever is physically after the chunk:

- **Adjacent application data**: function pointers, vtable pointers, size
  fields, is_admin flags — often enough on its own.
- **Chunk metadata**: next chunk's `size`/`prev_size`/flags → overlapping
  chunks, tcache/fastbin `fd` poisoning once the neighbor is freed →
  arbitrary allocation → arbitrary write. Load `heap-exploitation` for the
  glibc-version-specific technique (tcache poisoning ≥2.26, safe-linking
  ≥2.32 needs a heap leak, hooks removed ≥2.34).
- Heap grooming (allocation order/sizes to choose the victim neighbor) is
  part of the `heap-exploitation` skill.

## Worked micro-example

```c
// gcc -g -fsanitize=address -o hbo hbo.c   (and a plain build for pwndbg)
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *a = malloc(32);
    char *b = malloc(32);           // victim neighbor
    strcpy(b, "SAFE");
    strcpy(a, argv[1]);             // unbounded into 32-byte chunk
    free(b); free(a);
}
```

`./hbo $(python3 -c 'print("A"*48)')` → ASan `heap-buffer-overflow WRITE of
size 49 ... 16 bytes to the right of 32-byte region`. The plain build in
pwndbg shows `b`'s chunk header smashed with `0x4141414141414141`.
