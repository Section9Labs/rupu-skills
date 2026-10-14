# strace — full flag reference and reading guide

strace intercepts syscalls via ptrace. One line per syscall:
`name(decoded-args) = return <annotations>`. Unfinished/resumed pairs appear when
another thread's event interleaves: `read(3, <unfinished ...>` /
`<... read resumed>"data", 4096) = 17`.

## Invocation forms

```
strace ./target args                 # launch
strace -p 1337                       # attach (repeatable -p; Ctrl-C detaches cleanly)
strace -p 1337 -f                    # attach AND follow future children
strace -u www-data ./target          # run as another user
strace -E VAR=val -E REMOVE_ME ./target   # set/unset env for the child
```

## Output control

| Flag | Effect |
|---|---|
| `-o FILE` | write trace to FILE (stderr otherwise); with `-f`, pid-prefixed lines |
| `-ff -o PFX` | one file per process: `PFX.<pid>` — best for fork+exec daemons |
| `-s N` | max string length printed (default 32 — always raise, e.g. `-s 4096`) |
| `-x` | non-ASCII strings in hex; `-xx` ALL strings in hex (binary protocols) |
| `-v` | unabbreviated structs/arrays (full stat, full envp on execve) |
| `-y` | fd → path annotation: `read(3</etc/passwd>, ...)` |
| `-yy` | also sockets/pipes: `connect(3<TCP:[192.0.2.10:43210->198.51.100.5:443]>...` |
| `-tt` | absolute timestamps (µs); `-t` seconds; `-ttt` epoch |
| `-T` | append per-call wall time `<0.000045>` — find the blocking recv |
| `-r` | relative timestamp deltas |
| `-k` | stack trace after each call (needs libunwind/libdw build) |
| `-i` | instruction pointer at syscall time |
| `-c` | summary only (count/time/errors per syscall); `-C` summary AND live trace |
| `-D` | run tracer as detached grandchild (less process-tree interference) |
| `-A` | append to -o file |

## Filtering (`-e`)

```
-e trace=openat,read,write,connect,execve     # explicit list
-e trace=%file                                # all syscalls taking a path
-e trace=%network                             # socket family
-e trace=%process                             # fork/exec/wait/exit
-e trace=%desc                                # fd operations
-e trace=%memory                              # mmap/mprotect/brk
-e trace=%signal                              # signal-related
-e trace=network,file                         # legacy class spelling, still valid
-e trace=/^clock_.*                           # regex
-e trace=!close                               # negate (quote the ! in shells)
-e signal=none / -e signal=SIGSEGV            # which signals to print
-e status=failed                              # only failing calls (path discovery!)
-e status=unfinished,unavailable
-e read=3 / -e write=4                        # full hex+ascii dump of I/O on that fd
-e quiet=attach,exit                          # suppress noise lines
-e abbrev=none                                # like -v
```

Fault/response injection (turn observations into quick robustness tests):

```
-e inject=openat:error=EACCES                 # make opens fail — error-path bugs
-e inject=read:error=EIO:when=3               # fail the 3rd read
-e inject=recvfrom:delay_enter=100000         # add latency (µs)
-e fault=open                                 # shorthand error=ENOSYS
```

## Reading patterns (what to grep for)

```
grep -n 'execve('        trace            # every exec; argv shows injection
grep -n 'O_CREAT\|O_WRONLY\|O_RDWR' trace # files written — planting/overwrite targets
grep -n '= -1 ENOENT'    trace            # missing files = search-path hijack candidates
grep -nE 'connect|bind|listen|accept' trace
grep -n 'MARKER'         trace            # where your tainted input surfaces
grep -nE 'read\(|recv'   trace            # input sizes: 3rd arg is the buffer length
grep -n 'mprotect.*PROT_EXEC' trace       # runtime code pages (packers, JITs)
grep -n 'ptrace'         trace            # anti-debugging (PTRACE_TRACEME)
grep -n 'prctl\|seccomp' trace            # sandboxing to plan around
```

Return-value idioms: `= 5` success; `= -1 EACCES (Permission denied)`;
`= ? ERESTARTSYS` interrupted; `+++ exited with 0 +++`; `--- SIGSEGV {si_signo=SIGSEGV,
si_code=SEGV_MAPERR, si_addr=0x41414141} ---` — the si_addr line IS your crash triage
(hand to `gdb-debugging` with the same input).

execve lines show the full new argv/envp (`-v` for untruncated envp): watch for your
bytes in argv of `sh -c`, in `PATH=`, in `LD_PRELOAD=`.

## Multi-process notes

- `-f` prefixes each line with the pid; children appear after
  `clone(...)= <childpid>`.
- `-ff` splits per pid; thread vs process both get files. Map the tree with
  `grep -h 'clone\|fork\|execve' trace.* | sort`.
- A traced `execve` REPLACES the image but keeps the pid — same trace file continues
  with the new program (unlike ltrace, which loses it).

## Permissions

Attaching needs `kernel.yama.ptrace_scope=0`, root, or `CAP_SYS_PTRACE`. Setuid
binaries drop privileges when traced by an unprivileged user — trace them as root to
see real behavior, and note that *this changes exploitability analysis* for
setuid-related bugs.
