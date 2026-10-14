# Attack surface mapping — imports/strings → input sources

The question triage must answer: **which bytes does an attacker control, and
through which channel do they enter?** Every later phase (fuzzing targets,
exploit I/O plumbing in `pwntools`, which functions to open first in Ghidra)
depends on this answer.

## 1. argv — command-line arguments

Evidence:
- Imports: `getopt`, `getopt_long`, `getopt_long_only`, `argp_parse`.
- Strings: usage banners (`Usage: %s [-v] <file>`), option strings like
  `"hvo:f:"` (the getopt optstring — each letter followed by `:` takes an
  argument), `--`-prefixed long option names.
- Disasm: `main` reading `rdi`/`rsi` (argc/argv on x86-64 SysV).

Exploitation notes: argv is unbounded in length (up to ARG_MAX ≈ 2 MB), fully
attacker-controlled on setuid binaries and via `exec` from another process.
`argv[0]` is also controlled. Classic: `strcpy(buf, argv[1])`.

Confirm: `./target $(python3 -c 'print("A"*5000)')` under
`ulimit -c unlimited`, look for SIGSEGV.

## 2. stdin

Evidence:
- Imports: `gets`, `fgets`, `getline`, `getchar`, `fgetc`, `scanf`,
  `read` (fd 0 — confirm the fd in disasm), `fread` on `stdin`.
- Strings: prompts (`Enter name: `, `> `), menu text (`1. create  2. delete`
  — a menu binary is a heap-exploitation CTF pattern).
- `isatty` import → behaves differently piped vs interactive.

Exploitation notes: easiest channel to script (`p = process(); p.sendline()`).
`gets` on stdin = overflow by definition. `scanf("%s")` = overflow.
`scanf("%d")` into an index without bounds = OOB read/write.

Confirm: `python3 -c 'print("A"*5000)' | ./target`; also test negative numbers
and `-` / `+` on numeric prompts.

## 3. Files

Evidence:
- Imports: `fopen`, `fopen64`, `open`, `openat`, `read`/`fread`/`mmap`,
  `stat`/`access` (TOCTOU candidates when paired with open), `getline`.
- Strings: file extensions (`.cfg`, `.dat`, `.png`), magic constants near
  parse errors (`bad magic`, `invalid header`), config paths
  (`/etc/example.conf`, `~/.exrc`), format error messages
  (`truncated chunk at %d`).

Exploitation notes: file parsers are the richest bug class — length fields
trusted into `memcpy`, offset fields used unchecked, decompression into
fixed buffers. This is the fuzzing hand-off: harvest sample inputs from
strings/magic, feed AFL++. `access()` then `open()` on the same path = TOCTOU
race on setuid targets.

## 4. Network

Evidence:
- Imports: `socket`, `bind`, `listen`, `accept`/`accept4` → **server**;
  `connect`, `getaddrinfo`/`gethostbyname` → client; `recv`, `recvfrom`,
  `recvmsg`, `send*`; `select`/`poll`/`epoll_create` → event loop;
  `fork` + `accept` → forking server (canary brute becomes viable — see
  `binary-protections`); `htons` usage near a constant = the port.
- Strings: port numbers, protocol keywords (`GET `, `POST`, `USER`, `PASS`,
  `220 `, `HTTP/1.1`, `\r\n\r\n`), IPs/hostnames, TLS strings (OpenSSL error
  strings = version fingerprint).

Exploitation notes: a listening daemon means remote exploitation; a
**forking** daemon means the child shares the parent's memory layout —
canary and ASLR become byte-by-byte brute-forceable because they do not
re-randomize per connection. Find the port: strings near `htons`, or run it:
`./target & ss -ltnp | grep target`.

Confirm live: `ncat 192.0.2.10 9000` and poke the protocol keywords you found.

## 5. Environment

Evidence:
- Imports: `getenv`, `secure_getenv`, `setenv`, `putenv`, `clearenv`.
- Strings: ALL-CAPS names (`HOME`, `PATH`, `LD_PRELOAD`, `EXAMPLE_DEBUG`,
  `TERM`) — any custom-looking name is a hidden input channel.

Exploitation notes: environment is attacker-controlled whenever the attacker
starts the process (local privesc on setuid, CGI, `ssh`-forced commands).
`system("foo")` with attacker `PATH` = trivial hijack. `getenv` straight into
`strcpy`/`sprintf` = overflow. On setuid targets check whether the binary
sanitizes (glibc drops `LD_PRELOAD` etc. for AT_SECURE, but not custom vars).

Confirm: `EXAMPLE_DEBUG=$(python3 -c 'print("A"*5000)') ./target`.

## 6. Secondary surfaces

- **Signals**: `signal`/`sigaction` handlers doing non-async-safe work
  (`syslog`, `free`) = race bugs.
- **IPC**: `shmget`/`mmap(MAP_SHARED)`/`msgget`/`mq_open`, Unix sockets
  (strings like `/tmp/example.sock`, `/var/run/…`) — another process's data
  is still attacker data.
- **Time/PRNG**: `time` + `srand` + `rand` → predictable tokens; replicate
  the seed and predict.
- **dlopen with computed path**: strings with `.so` plus `%s` → library
  planting; combine with writable RPATH/RUNPATH from `readelf -d`.

## Putting it together

For each binary, the triage report should end with one line per live channel:

```
surface: stdin   (fgets, scanf; prompt "Enter name: ")
surface: network (socket/bind/listen/accept/recv + fork; "220 example FTP" banner, htons→2121)
surface: env     (getenv; strings EXAMPLE_DEBUG, PATH + system() import)
```

Priority order for the next phase: whatever channel reaches a red-flag import
with the fewest parsing layers in between. `recv → sprintf` beats
`fopen → 12-layer TLV parser` for a first exploit attempt — fuzz the latter,
hand-exploit the former.
