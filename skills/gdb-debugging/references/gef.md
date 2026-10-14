# GEF command map

GEF (GDB Enhanced Features) — single-file Python extension, no deps beyond gdb's
Python. Install: `bash -c "$(curl -fsSL https://gef.blah.cat/sh)"`; load manually with
`gdb -nx -ex 'source ~/.gdbinit-gef.py'`. Prompt: `gef➤`. Help: `gef help`,
`gef config` (persistent settings), `<cmd> --help`.

On every stop GEF prints the **context**: registers (changed = red), stack telescope,
disassembly around `$rip`, threads, trace. Re-print with `context`; configure panes
with `gef config context.layout`.

## Patterns / offsets

| Command | Effect |
|---|---|
| `pattern create 200` | De Bruijn pattern, default n=8 on amd64 (`pattern create 200 4` for n=4) |
| `pattern offset $rsp` | dereference reg/addr, locate value in pattern, print offset |
| `pattern offset 0x6161616161616166` | locate a raw value |
| `pattern search <val>` | alias |

n must match between create and offset. pwntools default n=4 — pass `4` explicitly to
interoperate.

## State / inspection

| Command | Effect |
|---|---|
| `checksec` | RELRO/canary/NX/PIE/Fortify for the loaded binary |
| `vmmap [filter]` | process mappings with perms; filter by name or address |
| `xinfo <addr>` | which mapping/section/symbol contains addr, base + offset |
| `telescope <addr> [n]` / `dereference` | recursive pointer dump (stack reading) |
| `registers` | all regs, dereferenced |
| `got [filter]` | GOT entries; green = resolved into libc, yellow = still PLT stub |
| `canary` | current stack canary value and its location |
| `elf-info`, `got`, `xfiles` | binary structure |
| `grep <string>` / `search-pattern <val> [little|big] [range]` | search memory for string/bytes/value |
| `scan <haystack> <needle>` | find pointers FROM one region INTO another (e.g. `scan stack libc` → leak candidates) |
| `hexdump byte|word|dword|qword <addr> [n]` | formatted dumps |
| `memory watch <addr> <n> <fmt>` | pin a memory region into the context display |
| `$ <expr>` | quick eval, e.g. `$ $rsp+0x40` |
| `edit-flags` / `set $eflags` | flip flags to force a branch |

## Control

| Command | Effect |
|---|---|
| `entry-break` / `start` | break at entrypoint (works on stripped/PIE) |
| `nb` / `break *$rebase(0xoffset)` | PIE-relative breakpoints |
| `stepuntil`, `trace-run` | tracing helpers |
| `heap-analysis-helper` | hook malloc/free/realloc live: flags double-free, UAF, heap overlap as the program runs — turn it on, then `continue` |
| `catch syscall <name>` | plain gdb, fully usable |
| `process-status` | fds, connections, cwd of the debuggee |

## Heap

| Command | Effect |
|---|---|
| `heap chunks [arena]` | walk all chunks: addr, size, flags, preview |
| `heap chunk <addr>` | decode one chunk (pass user pointer; `--allow-unaligned` for fakes) |
| `heap bins` | all bins |
| `heap bins tcache` / `fast` / `unsorted` / `small` / `large` | one class |
| `heap arenas` | list arenas; `heap set-arena <addr>` for threads |

## Exploit-dev helpers

| Command | Effect |
|---|---|
| `aslr [on|off]` | toggle the debuggee's personality ASLR flag |
| `format-string-helper` | breakpoints on printf-family with user-controlled fmt detection |
| `shellcode search/get <os>` | fetch shellcode from shell-storm |
| `ropper` / integration | run ropper inside gdb if installed |
| `pcustom` | define C-struct overlays and apply to memory (`pcustom malloc_chunk 0x405290`) |
| `gef-remote <host> <port>` | debug a gdbserver target with full GEF features |
| `pie breakpoint/attach/run` | PIE-aware breakpoint set (pre-run) |

## Useful config

```
gef config context.nb_lines_stack 16
gef config gef.autosave_breakpoints_file /tmp/bps.gdb
gef save / gef restore
```
