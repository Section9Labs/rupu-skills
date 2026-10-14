# Use-after-free and double-free

## (a) Source pattern

```c
free(session->buf);
...
log_line(session->buf);          // UAF read
session->buf[0] = c;             // UAF write
free(session->buf);              // double-free (pointer never nulled)
```

Typical shapes: object freed on an error path but the caller keeps using
it; two owners of one pointer; callback/timer firing after its context was
freed; reference-count bug reaching zero early. The pointer is *stale*, not
wild — it still points at the old chunk, now owned by the allocator (or by
a new allocation: "heap spray the hole").

## (b) Binary / disassembly signature

```
mov    rdi, qword [rbx+0x18]
call   free@plt
; no  mov qword [rbx+0x18], 0   <-- the missing null-out is the tell
...
mov    rax, qword [rbx+0x18]    ; later load of the SAME slot
mov    rdx, qword [rax]         ; deref  -> UAF
; or:  call free@plt again with [rbx+0x18] -> double free
```

Hunting procedure (Ghidra/r2):

- `axt @ sym.imp.free` / xrefs to `free` — for each site, note the
  struct+offset the pointer came from, check whether it is zeroed after the
  call, then search later reads of that slot (Ghidra: right-click field →
  references; r2: `/x` on the displacement, or `aflj` + grep).
- Error paths are prime: a `free` inside an `if (err) { ...; goto out; }`
  while the success path frees the same thing again in `out:`.
- Indirect calls through freed objects (`call qword [rax+0x10]` where
  `rax` is a freed object) are the jackpot: vtable-style UAF.

## (c) Dynamic confirmation

- ASan: `heap-use-after-free on address 0x... READ/WRITE of size N` with
  **three stacks**: the use, the free, and the original allocation —
  everything you need. Double-free: `attempting double-free on 0x...` with
  both free stacks.
- glibc without ASan: `free(): double free detected in tcache 2` (same
  pointer freed twice while in tcache; the tcache `key` field is the
  detector — bypassing it is `heap-exploitation` material).
- pwndbg:

```
pwndbg> break free
pwndbg> r < input
pwndbg> finish; tcachebins          # freed chunk sits in tcache, fd/key visible
pwndbg> watch *(long*)<chunk_addr>  # catch the UAF write changing fd
pwndbg> c                           # watchpoint hit = the use site
```

- `ltrace -e 'malloc+free' ./target < input` shows the free/alloc sequence;
  the same address freed twice, or returned by malloc *between* a free and
  a use, confirms the window.

## (d) Primitive and hand-off

- **UAF write** into a tcache/fastbin-resident chunk → overwrite `fd` →
  tcache poisoning → malloc returns an arbitrary address → arbitrary write.
  (glibc ≥2.32: `fd` is mangled — need a heap address leak; a UAF *read* of
  a freed chunk leaks exactly that, or a libc arena pointer from an
  unsorted-bin-sized chunk.)
- **Double-free** → the same chunk in a bin twice → allocate it, write
  `fd`, allocate again twice → arbitrary chunk. (tcache `key` check must be
  dodged: overwrite key via another bug, or free into fastbin via count.)
- **Type-confusion UAF**: reallocate the hole with attacker-controlled data
  of the same size class, then let the stale pointer "use" your fake object
  (fake vtable/function pointer → PC control → `rop-chains`).

Load `heap-exploitation` with: glibc version, chunk size class, whether you
have UAF-read (leak), UAF-write, or double-free, and how allocations are
triggered (the alloc primitive).

## Worked micro-example

```c
// gcc -g -fsanitize=address -o uaf uaf.c
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    free(p);
    char *q = malloc(32);          // same chunk back (tcache LIFO)
    strcpy(q, "/bin/id");
    p[0] = 'X';                    // write through stale p hits q
}
```

ASan flags the `p[0]` write as `heap-use-after-free` with all three stacks.
Without ASan, pwndbg shows `p == q` after the second malloc — the aliasing
that every UAF exploit is built on.
