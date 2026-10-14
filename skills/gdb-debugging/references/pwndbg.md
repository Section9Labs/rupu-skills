# pwndbg command map

Install: `git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh`
(appends to `~/.gdbinit`). Prompt: `pwndbg>`. Help: `pwndbg` (lists all commands),
`<cmd> -h`. Context (regs/disasm/stack/backtrace) prints on every stop; `context` to
re-print, `set context-sections 'regs disasm stack backtrace'` to tune, `ctx-watch`
to pin expressions.

## Patterns / offsets

| Command | Effect |
|---|---|
| `cyclic 200` | De Bruijn pattern (amd64 default n=8; `cyclic -n 4 200` for 4) |
| `cyclic -l $rsp` | dereference and find offset |
| `cyclic -l 0x6161616161616166` | find a raw value |
| `cyclic -o <offset>` | inverse: print the bytes at an offset |

Match `-n` with pwntools (`cyclic`/`cyclic_find`, default n=4) when mixing tools.

## State / inspection

| Command | Effect |
|---|---|
| `checksec` | mitigations summary |
| `vmmap [filter|addr]` | mappings + perms; `vmmap libc`, `vmmap $rsp` |
| `telescope <addr> [n]` | recursive dereference; `telescope $rsp 30` |
| `stack [n]` | telescope at $rsp |
| `regs` / `context regs` | registers |
| `got` / `gotplt` / `plt` | GOT entries (resolved vs not), .got.plt, PLT stubs — diff before/after to catch GOT overwrites |
| `canary` | canary value + all stack copies of it |
| `piebase` | PIE load base |
| `libc` | libc base address |
| `libcinfo` | libc version detection |
| `search [-t byte\|word\|dword\|qword\|pointer\|string] <val>` | search all/one mapping: `search "/bin/sh"`, `search -t qword 0x41414141414141`, `search -p <ptr>` |
| `leakfind <addr>` | BFS pointer chains from addr — find paths to libc/stack for leaks |
| `probeleak <addr> <len>` | scan a region for pointers into interesting mappings |
| `xinfo <addr>` | owner mapping + offset |
| `hexdump <addr> [n]` / `x/...` | dumps |
| `distance <a> <b>` | delta between two addresses |
| `errno` | last errno |
| `elfsections` / `elfheader` | ELF structure |

## Control

| Command | Effect |
|---|---|
| `start` / `entry` / `sstart` | tbreak main / entrypoint / __libc_start_main |
| `break *$rebase(0x1234)` | PIE-relative breakpoint (via `$rebase` convenience fn) |
| `nextcall` / `nextjmp` / `nextret` / `nextsyscall` | run to next call/jmp/ret/syscall |
| `stepret` / `stepover` | step helpers |
| `dumpargs` | print the arguments of the call at $rip (also shown in context) |
| `attachp <name|pid>` | attach by process name |
| `catch syscall execve` | plain gdb |

## Heap (ptmalloc)

| Command | Effect |
|---|---|
| `heap` | all chunks in current arena |
| `bins` | every bin class at once |
| `tcachebins` / `fastbins` / `unsortedbin` / `smallbins` / `largebins` | one class, with the chain of fd/bk pointers — a repeated pointer = double free; a corrupted fd = poisoned list |
| `tcache` | raw tcache_perthread_struct (counts + entries) |
| `vis_heap_chunks [n] [addr]` | colorized heap hexdump; overlapping chunks and smashed size fields are visually obvious |
| `malloc_chunk <addr>` | decode a chunk (user ptr or chunk ptr) |
| `top_chunk` | the wilderness |
| `arena` / `arenas` | malloc_state structs |
| `find_fake_fast <addr> [size]` | candidate fake-fastbin chunks whose fd overlays addr — feeds fastbin-dup attacks |
| `try_free <addr>` | simulate free(): which glibc integrity checks pass/fail |
| `heap_config` | set glibc version/offsets when symbols are missing |

## Exploit-dev helpers

| Command | Effect |
|---|---|
| `aslr [on|off]` | debuggee ASLR toggle |
| `ropgadget` / `rop` | ROPgadget integration |
| `onegadget` | one_gadget integration (if installed) |
| `p2p <mapping-A> <mapping-B>` | pointers from A into B |
| `ignore <bpnum> <count>` | plain gdb, skip N hits |
| `$rebase(off)` / `$base()` | PIE math in any expression |
