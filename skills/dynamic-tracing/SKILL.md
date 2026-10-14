---
name: dynamic-tracing
description: Observe a target's library calls and syscalls with ltrace and strace — follow forks, decode fds, capture full argument strings, and spot attacker-reachable file/network/exec/dangerous-libcall behavior that points at vulnerabilities. Use early in binary triage to map what a program actually does with input before diving into gdb.
metadata:
  author: Section9Labs
---

# Dynamic tracing with strace and ltrace

Run the target under a tracer and read its behavior directly: which files it opens
from your input, where it connects, what it executes, which unsafe libc functions it
feeds your bytes to, and what sizes it passes to read/memcpy. This is the fastest way
to turn "unknown binary" into a short list of attack-surface candidates to hand to
`gdb-debugging` and `vuln-classes`. Full flag references: `references/strace.md`,
`references/ltrace.md`.

## 1. strace — syscalls

Baseline run (always use these flags; defaults truncate strings at 32 chars and miss
children entirely):

```
strace -f -s 4096 -yy -o evidence/strace.out ./target args
```

- `-f` follow forks/clones/vforks — **essential for servers and anything that
  spawns workers**; without it the interesting child is invisible.
- `-ff -o evidence/trace` one output file PER process (`trace.<pid>`) — the right
  mode for fork+exec daemons; triage each child file separately.
- `-s 4096` print up to 4096 chars of string args (default 32 hides the payload).
- `-y` decode fd numbers to paths; `-yy` also decodes sockets to
  `<TCP:[192.0.2.10:43210->198.51.100.5:443]>` — read/write lines become
  self-explanatory.
- `-p 1337` attach to a running PID (repeatable: `-p 1 -p 2`); `-p $(pgrep httpd)`.
- `-e trace=...` filter: named sets `-e trace=%network`, `%file`, `%process`,
  `%signal`, `%memory`, `%desc`, or explicit lists
  `-e trace=open,openat,read,write,connect,execve`. Legacy spelling
  `-e trace=network,file` also works. Combine: `-e trace=%network,%process`.
- `-tt` microsecond timestamps, `-T` per-call duration (spot blocking reads = where
  input is consumed), `-r` relative timestamps.
- `-k` print a stack trace after each syscall — maps a syscall back to the code path
  (needs unwinding support; slow, use with a tight `-e trace=` filter).
- `-xx` print ALL strings as hex — mandatory when the protocol is binary, otherwise
  non-printables are escaped ambiguously.
- `-v` unabbreviate structs; `-e signal=` / `-e status=failed` further filters;
  `-e inject=` fault injection (see reference).
- `-c` summary table (counts/time per syscall) — quick profile, no args shown.

### Reading strace output

Each line: `syscall(decoded args) = retval <errno/duration>`. Hunt for:

- **Files opened from your input**: feed a marker (`AAAA_MARKER`) and grep the trace —
  `openat(AT_FDCWD, "/tmp/AAAA_MARKER.cfg", O_RDONLY) = -1 ENOENT` means your string
  reaches a path → traversal/symlink/overwrite candidates. Also watch `access`,
  `stat`, `unlink`, `rename`, `chmod` on predictable `/tmp` paths (TOCTOU).
- **Exec of a shell/command**: `execve("/bin/sh", ["sh", "-c", "ping 192.0.2.9"], ...)`
  — if any argv byte is yours, that's command injection. `-f` required to see it
  (it happens in the child).
- **Network**: `connect(3<TCP:...>, {sa_family=AF_INET, sin_port=htons(443),
  sin_addr=inet_addr("203.0.113.7")}, 16)` — callbacks, license checks, C2-style
  beacons; `bind`/`listen`/`accept4` show the listening surface.
- **Sizes feeding later overflows**: `read(0, "...", 65536) = 1200` then a crash in a
  512-byte stack buffer — the syscall layer shows the true attacker-controlled
  length. Correlate `recvfrom(fd, buf, LEN, ...)` LEN against buffer sizes you find
  in `gdb-debugging`/disassembly.
- **Secrets/config**: `openat(..., "/etc/target/secret.key", O_RDONLY) = 4` followed by
  `read(4</etc/target/secret.key>, "-----BEGIN", 4096)` — `-yy` + `-s 4096` prints it.
- Failed calls (`= -1 ENOENT`) enumerate search paths: missing config files, missing
  libraries (`LD_PRELOAD`/plugin planting), writable-dir lookups.

## 2. ltrace — library calls

```
ltrace -f -s 4096 -o evidence/ltrace.out ./target args
```

- `-e 'strcpy+strcat+sprintf+vsprintf+memcpy+strncpy+gets+system+popen+printf'`
  filter to dangerous libcalls (`+`-joined glob patterns; `-e '*cpy*'` works too;
  `@libname` suffix restricts the matched symbol's library).
- `-s 4096` full strings; `-n 2` indent nested calls.
- `-S` ALSO show syscalls inline (prefixed `SYS_`) — library→syscall correlation in
  one stream, often removes the need for a separate strace pass.
- `-C` demangle C++ symbols.
- `-p 1337` attach; `-f` follow forks.
- `-l libcrypto.so.3` only calls INTO that library (repeatable) — isolate crypto or a
  custom parser lib; `-x 'pattern'` traces calls to matching symbols including
  **internal/static-ish** functions and symbols inside libraries (not just the
  PLT boundary).
- `-c` count summary; `-tt`/`-T` timestamps/durations; `-i` instruction pointer per
  call (feed addresses straight to `break *` in gdb).

### Reading ltrace output

Each line: `lib->func(args) = ret` (with `-f`: `[pid NNN]` prefix). Hunt for:

- `strcpy(0x7ffc1234, "AAAA...968 bytes...")` — unbounded copy of your input: measure
  the string length vs. the destination (stack addr near `rsp` = stack buffer).
  Same for `strcat`, `sprintf`, `gets`.
- `memcpy(0x7ffc..., 0x55d3..., 8192)` — attacker-influenced length param.
- `printf("%s%n...")` or `printf(user_input)` — format string: the first arg being
  your bytes (not a constant) is the tell; also `syslog`, `fprintf`, `snprintf`.
- `system("ping -c1 203.0.113.9; id")` / `popen(...)` — the exact command line,
  injection confirmed if your marker appears inside it.
- Crypto: `EVP_EncryptInit_ex`, `AES_set_encrypt_key(key=0x..., bits=128)`,
  `MD5_Init` — hardcoded keys show up as pointer args you then dump in gdb;
  weak-algorithm usage is itself a finding.
- `getenv("DEBUG")`, `strcmp("secret", input)` — hidden switches and comparisons
  that leak expected values.

Caveats: ltrace sees calls crossing the PLT; statically linked or `-fno-plt` binaries
show little — fall back to strace plus gdb breakpoints. ltrace can't follow into
`execve`d children the way strace does.

## 3. Combining: tracing a forking network daemon

```
strace -ff -tt -T -s 4096 -yy -o evidence/trace ./daemon --port 8080 &
# drive it: curl http://192.0.2.10:8080/ , nc, your protocol client with a marker
ls evidence/trace.*                     # one file per pid
grep -l MARKER evidence/trace.*         # which child handled your request
grep -nE 'execve|system|connect|openat' evidence/trace.<pid>
```

Triage order per child file: (1) the `accept4`/`recvfrom` that received your bytes,
(2) every syscall whose args contain the marker, (3) any `execve`, (4) `read`/`recv`
size arguments. Then rerun the interesting child path under
`ltrace -S -e '<dangerous set>'`, or attach: `ltrace -f -p <parent-pid>` before
sending the request. For already-running services, `strace -f -p <pid> -s 4096 -yy`
attaches live without restart.

## 4. Automated scan

```
python3 scripts/trace_scan.py ./target -- arg1 arg2
python3 scripts/trace_scan.py ./target --stdin-marker 'AAAA_MARKER' --outdir evidence
python3 scripts/trace_scan.py --attach 1337 --duration 15
```

Runs strace (and ltrace when installed) with the flags above, keeps raw traces under
the evidence dir, parses them for files opened / network endpoints / shell execs /
dangerous libcalls with argument sizes, prints a summary, and writes
`work-units.json` — a rupu-ingestible array of candidate issues
(`{id,title,targets,hints}`, hints like `["gdb-debugging","vuln-classes"]`).
Degrades with a clear message if strace/ltrace are absent.

## 5. Record results (rupu)

See `references/rupu.md`: mark the binary `binary:file` → `triaged`/`analyzed` and
each dangerous sink as `binary:symbol`; verified issues (your marker in a `system()`
arg, traversal reaching `openat`) go to `findings.report` per the shared
`finding-report` skill; fan-out follow-ups via `work-units.json` (shared `work-units`
skill). Keep every raw trace file as evidence.

## Chain

- Candidate overflow/format-string sink spotted → `gdb-debugging` (break on the sink,
  cyclic pattern for the offset), then `pwntools`.
- Dangerous call patterns need classification → `vuln-classes`.
- Heap churn around the suspicious free/malloc sequence → `gdb-debugging` heap
  commands, then `heap-exploitation`.
