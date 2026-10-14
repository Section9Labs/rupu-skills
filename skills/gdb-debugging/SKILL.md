---
name: gdb-debugging
description: Dynamic analysis and exploit development with gdb plus the GEF and pwndbg extensions — launching/attaching, finding overflow offsets with cyclic patterns, inspecting memory/registers/GOT/heap, setting breakpoints and watchpoints to catch corruption, and deriving runtime addresses to defeat ASLR. Use when you have a target binary (crash triage, offset discovery, heap-state inspection, leak verification) during exploit development.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# gdb debugging with GEF and pwndbg

Drive gdb against a live target to turn a static suspicion (from `vuln-classes` /
disassembly) into a confirmed, measured primitive: a controlled saved-RIP offset, a
corrupted heap chunk, a verified leak. Commands below are tagged **(GEF)**, **(pwndbg)**,
or plain gdb when they work everywhere. Full command maps: `references/gef.md`,
`references/pwndbg.md`.

Pick ONE extension per gdb session (they conflict):

```
# GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"      # installs to ~/.gdbinit-gef.py
# pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
```

Swap by editing `~/.gdbinit` or `gdb -nx -ex 'source ~/.gdbinit-gef.py' ./target`.

## 1. Launch, attach, cores

```
gdb ./target                      # load binary, no run yet
gdb -q ./target                   # quiet banner
gdb -p 1337                       # attach to running PID (needs ptrace_scope=0 or root)
gdb ./target core                 # post-mortem on a core dump
gdb --args ./target arg1 arg2     # preset argv
```

Inside gdb:

```
run AAAA BBBB                     # start with argv
run < input.bin                   # stdin from file
run <<< $(python3 -c 'print("A"*200)')
starti                            # stop at the very first instruction (before _start / ld.so)
start                             # tbreak main + run
set args $(python3 -c '...')      # change argv without re-running gdb
set follow-fork-mode child        # follow into fork()ed child (servers, sandboxes)
set detach-on-fork off            # keep both parent and child under control (inferiors)
catch syscall execve              # break on any execve — catches shell spawns
catch syscall                     # break on EVERY syscall (entry and exit)
catch signal SIGSEGV              # explicit stop on segfault (default anyway)
info inferiors / inferior 2       # switch between forked processes
```

For `ptrace: Operation not permitted` on attach:
`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` (or run gdb as root).

## 2. Find the offset to saved RIP/RBP with a cyclic pattern

The core loop: send a De Bruijn pattern, crash, read which pattern bytes landed in the
control value, convert back to an offset.

**GEF:**
```
gef➤ pattern create 200
[+] Generating a pattern of 200 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaad...
gef➤ run <<< aaaaaaaabaaaaaaac...        # or paste into argv
...SIGSEGV...
gef➤ pattern offset $rsp                 # 64-bit: ret faulted, pattern sits AT rsp
[+] Found at offset 72 (little-endian search)
gef➤ pattern offset $rip                 # 32-bit: pattern IS eip
gef➤ pattern offset 0x6161616161616166   # raw faulting value also works
```

**pwndbg:**
```
pwndbg> cyclic 200
aaaaaaaabaaaaaaac...
pwndbg> run
...SIGSEGV...
pwndbg> cyclic -l $rsp                   # dereferences and finds offset
pwndbg> cyclic -l 0x6161616161616166     # or pass the value directly
Finding cyclic pattern of 8 bytes: ... (offset 72)
```

**pwntools equivalents** (same math, scriptable — load the `pwntools` skill):
`cyclic(200)` / `cyclic_find(0x6161616166)` (default n=4; pwndbg/GEF default n=8 on
amd64 — match `n` or the lookup fails).

**Reading the SIGSEGV state.** On amd64 an overwritten return address that is
non-canonical (`0x4141414141414141`) never reaches RIP — the `ret` itself faults and RIP
still points at the `ret` instruction. The pattern you want is **at `$rsp`**. On i386 the
pattern lands directly in `$eip`. After the crash:

```
gef➤ context            # GEF auto-shows regs/stack/code; pwndbg same on each stop
gef➤ info registers
gef➤ x/4gx $rsp         # the qwords that would have been popped into rip
gef➤ bt                 # if frames survive
```

Also check `$rbp` (saved-RBP offset = saved-RIP offset − 8 on amd64) and, for SIGSEGVs
inside a read/write instruction, the faulting *address* printed by gdb — that address is
often itself pattern bytes (controlled pointer deref ≠ plain stack smash; different
primitive, still an offset).

**Automated:** `python3 scripts/gdb_offset.py ./target --mode stdin --length 400`
runs the whole loop in batch gdb, no pwntools needed, prints the offset and a
finding stub. `--mode argv` for argv overflows. See script `--help`.

## 3. Inspection

```
checksec                          # both: RELRO / canary / NX / PIE / FORTIFY
vmmap                             # both: segments, perms (find rwx, writable GOT),
                                  #   PIE base = first binary mapping, libc base = first libc-*.so mapping
vmmap libc                        # filter
telescope $rsp 30                 # both: recursive dereference — pointer chains, stack layout
telescope &__free_hook            # inspect any address
dereference $rsp -l 20            # GEF alias
got                               # pwndbg: all GOT entries, resolved-vs-unresolved coloring
gotplt / plt                      # pwndbg: .got.plt / PLT stubs
got                               # GEF has `got` too (color: green=resolved to libc)
search -t qword 0x4141414141414141   # pwndbg: typed search of all mappings
search "/bin/sh"                     # pwndbg: string search (→ libc "/bin/sh" address)
search -p 0x7f0123456789             # pwndbg: pointer search (who points at X?)
grep /bin/sh                         # GEF: search string in memory
search-pattern 0x4141414141 little   # GEF: value search
x/20gx $rsp        x/10i $rip        x/s 0x404050      # raw gdb: n*format at addr
info registers     p/x $rax          p $_siginfo       # fault details incl. si_addr
canary                               # both: print current stack canary value
xinfo <addr>                         # GEF: which mapping/section/symbol owns addr
```

Compare GOT across time to detect GOT overwrites: `got` before and after the suspect
write; a `.got.plt` entry pointing into the heap/stack instead of libc = hijacked.

## 4. Breakpoints and watchpoints

```
break main                        # symbol
break *0x401136                   # exact address (use for stripped bins; add PIE base)
break *$rebase(0x1136)            # pwndbg/GEF: PIE-relative (pwndbg: break *(&_start-0x... ) alt: `piebase`)
tbreak main                       # one-shot
break vuln if $rdi > 0x100        # conditional (first arg too big)
break read if $rdx > 0x400        # catch the oversized read
watch *(long*)0x404080            # HW watchpoint: break when VALUE at addr is WRITTEN
rwatch *(long*)0x404080           # break when it is READ (find who consumes a value)
awatch *(long*)0x404080           # read or write
watch -l some_global              # watch the location, not the expression
commands 2                        # auto-run commands at breakpoint 2
  silent
  printf "free(%p)\n", $rdi
  continue
end
info breakpoints / delete 2 / disable 3
```

Watchpoints are THE tool for "who corrupts this memory?": set `watch` on the canary
slot, a GOT entry, a heap chunk's size field, or a function pointer; `continue`; gdb
stops on the exact corrupting instruction with old/new value printed. Hardware
watchpoints are limited (4 on x86) — delete stale ones.

## 5. Heap

**pwndbg:**
```
heap                      # walk all chunks in the main arena
bins                      # every bin: tcache, fast, unsorted, small, large
tcachebins / fastbins / unsortedbin / smallbins / largebins
tcache                    # raw tcache_perthread_struct
vis_heap_chunks           # color-coded hexdump of the heap — spot overlaps instantly
malloc_chunk 0x4052a0     # decode one chunk: prev_size/size/flags/fd/bk
find_fake_fast &target    # find addresses usable as fake fastbin chunks over target
arena / arenas            # malloc_state
try_free 0x4052a0         # dry-run: what would free() do / which checks fail
```

**GEF:**
```
heap chunks               # walk chunks
heap bins                 # all bins (also: heap bins tcache / fast / unsorted / small / large)
heap chunk 0x4052a0       # decode one chunk
heap arenas
heap set-arena <addr>     # non-main arena
```

Workflow to spot UAF / double-free: break on `malloc`/`free`
(`break free` + `commands` printing `$rdi`, `break malloc` printing `$rdi` then
`finish` to grab `$rax`), build a timeline of pointers; after each `free`, check
`bins`/`tcachebins` — the same pointer appearing twice in a tcache bin = double-free;
a freed pointer still used by the program (set `rwatch` on its fd field) = UAF.
`vis_heap_chunks` after the overflow shows the smashed size field in red.

Once you have the corruption primitive characterized (which chunk, which field, how
many bytes, allocator version via `ldd`/`vmmap` libc path), **hand off to the
`heap-exploitation` skill** with: libc version, chunk layout dump, primitive type
(overflow into size / UAF / double-free), and controllable sizes.

## 6. Runtime addresses and ASLR

```
set disable-randomization on      # gdb default: ASLR OFF inside gdb — deterministic debugging
set disable-randomization off     # realistic addresses (what the live target sees)
aslr                              # pwndbg: show; `aslr on|off` to toggle
aslr                              # GEF: same
```

Deriving bases (see `references/offsets-and-aslr.md` for the full method):

```
vmmap                                     # libc base = start of first libc mapping
p &system                                 # absolute runtime address (symbols loaded)
p/x (long)&system - (long)&__libc_start_main   # libc-internal deltas survive ASLR
info proc mappings                        # plain-gdb vmmap
libc                                      # pwndbg: print libc base directly
piebase                                   # pwndbg: PIE base
xinfo $rip                                # GEF: base + offset of current mapping
```

Rule: `leaked_symbol_addr − offset_of_symbol_in_libc = libc_base`; every other gadget
= `libc_base + static_offset`. Debug with ASLR off for repeatability, but the exploit
MUST compute bases from a leak at runtime — the live target has ASLR on, and gdb-off
addresses (`0x7ffff7...` stack/libc) will be wrong outside the debugger. Verify the
final exploit with `set disable-randomization off` before shipping.

## 7. Script

```
python3 scripts/gdb_offset.py ./target                     # stdin pattern, 400 bytes
python3 scripts/gdb_offset.py ./target --mode argv -l 600  # pattern as argv[1]
python3 scripts/gdb_offset.py ./target --prefix 'CMD '     # bytes before the pattern
```

Prints crash signal, faulting value, where the pattern was found (rip / [rsp] / rbp /
fault address), the computed offset, and a one-line finding stub (JSON) ready for
`findings.report`. Works without GEF/pwndbg/pwntools; degrades with a clear message if
gdb is missing.

## 8. Record results (rupu)

Every confirmed crash or primitive gets recorded — see `references/rupu.md`:
mark the binary asset `binary:file` to `vuln-identified` with `assets.mark`, report the
crash via `findings.report` (field contract in the shared `finding-report` skill), and
keep raw gdb transcripts / core files in the run workspace as evidence.

## Chain

- Offsets confirmed, need ROP/payload automation → `pwntools` skill.
- Heap primitive characterized → `heap-exploitation` skill.
- Need the library/syscall timeline around the crash → `dynamic-tracing` skill.
- Hunting for the vuln in the first place → `vuln-classes` skill, then come back here.
