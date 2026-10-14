# ltrace — full flag reference and reading guide

ltrace intercepts calls crossing the PLT into shared libraries (plus, optionally,
syscalls). One line per call: `funcname(args) = retval`; with `-f`,
`[pid NNN] funcname(...)`. Pointer args to strings are dereferenced and printed.

## Invocation forms

```
ltrace ./target args
ltrace -p 1337                      # attach
ltrace -f ./target                  # follow fork/clone (NOT execve — child exec is lost)
ltrace -u user ./target
```

## Core flags

| Flag | Effect |
|---|---|
| `-o FILE` | write to FILE |
| `-s N` | max string chars (default 32 — use 4096) |
| `-S` | ALSO trace syscalls, shown as `SYS_openat(...)` inline between libcalls |
| `-C` | demangle C++ names |
| `-f` | follow forks |
| `-n N` | indent nested calls by N spaces (readability with callbacks) |
| `-i` | print instruction pointer of the call site — feed to gdb `break *ADDR` |
| `-t`/`-tt`/`-ttt` | timestamps (s/µs/epoch) |
| `-T` | per-call duration |
| `-r` | relative timestamps |
| `-c` | count summary (calls/time per function) |
| `-A N` | max array elements printed |
| `-D MASK` | debug output of ltrace itself |
| `-F conffile` | extra prototype definitions (better arg decoding; see ltrace.conf(5)) |
| `-w N` | print N stack frames on each call (where built with unwinding) |

## Filtering: `-e`, `-l`, `-x`

`-e` selects which library→main-binary boundary calls are shown. Rules are
`+`-joined glob patterns; `!` negates; `@sofile` scopes to a library:

```
-e 'strcpy+strcat+sprintf+vsprintf+gets+memcpy+system+popen'   # dangerous set
-e '*cpy*+*cat*'                 # globs on names
-e 'malloc+free'                 # allocator timeline (pair with gdb heap cmds)
-e '@libcrypto.so*'              # every call into libcrypto
-e '!printf*'                    # everything EXCEPT printf family
-e 'SSL_read@libssl*'            # one symbol in one library — plaintext before/after TLS
```

`-l LIB` (repeatable): only calls INTO LIB (which library's symbols get traced).
`-x PATTERN`: trace symbols by name even if not called through the main binary's PLT —
includes library-internal cross-calls and (if symbols exist) static functions:

```
ltrace -x 'parse_*' -x 'EVP_*@libcrypto*' ./target
```

A useful dangerous-call baseline for triage:

```
ltrace -f -s 4096 -S \
  -e 'strcpy+strncpy+strcat+strncat+sprintf+vsprintf+snprintf+gets+memcpy+memmove+alloca+system+popen+execl+execlp+execv+execvp+printf+fprintf+syslog+getenv+setuid+setgid' \
  -o evidence/ltrace.out ./target args
```

## Reading patterns

```
strcpy(0x7ffd8a2c3410, "AAAA...TOTAL 968 CHARS") = 0x7ffd8a2c3410
```
→ destination on the stack (0x7ff… near rsp) + source length under your control =
overflow candidate. Compute: your input length vs. the frame size (confirm in gdb:
`break strcpy`, `telescope $rdi`).

```
memcpy(0x55d3f2a012a0, 0x7ffd8a2c0000, 16384) = ...
```
→ heap destination; is the 3rd arg derived from your input (length field)? Replay with
a bigger length.

```
printf("User: %s logged in from %s", ...)     # constant fmt — fine
printf("AAAA%p%p%p")                           # YOUR bytes as fmt = format string vuln
```

```
system("ping -c1 198.51.100.7; MARKER")        # injection proven by the marker
popen("tar xf /tmp/upload.tgz", "r")
getenv("LD_AUDIT") / getenv("DEBUG_SHELL")     # hidden env switches
strcmp("s3cr3t-backdoor", 0x7ffd...)           # comparison leaks the expected value
AES_set_encrypt_key(0x55d3f29f1100, 128, ...)  # key pointer — dump it in gdb
```

Signals and exits are reported inline: `--- SIGSEGV (Segmentation fault) ---`,
`+++ exited (status 0) +++` — a dangerous call immediately followed by SIGSEGV is your
crash site; take the `-i` address to `gdb-debugging`.

## Limitations (know when to switch tools)

- Statically linked binaries: no PLT → nearly empty output. Use strace + gdb.
- `-fno-plt` / `-z now` + inlined calls: fewer boundary crossings visible; `-x` helps.
- Cannot follow `execve` into a new image (strace `-f` can).
- dlopen()ed plugins: symbols appear once loaded; use `-x` patterns.
- Heavy slowdown on hot paths — filter with `-e` for long runs.
