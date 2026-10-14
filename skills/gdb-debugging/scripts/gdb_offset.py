#!/usr/bin/env python3
"""gdb_offset.py — find the overflow offset to saved RIP/RBP with batch gdb.

Runs the target under `gdb -q -batch` with a De Bruijn (cyclic) pattern delivered
on stdin or argv, captures the crash state, extracts candidate faulting values
(RIP, [RSP], [RSP+8], RBP, si_addr), looks each up in the pattern (n=8 and n=4),
and prints the offset plus a one-line finding stub for rupu findings.report.

No pwntools required. Degrades gracefully if gdb is absent.

Usage:
  python3 scripts/gdb_offset.py ./target                      # stdin, 400 bytes
  python3 scripts/gdb_offset.py ./target --mode argv -l 600
  python3 scripts/gdb_offset.py ./target --prefix 'OVERFLOW ' # bytes before pattern
"""

import argparse
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile

ALPHABET = string.ascii_lowercase.encode()


# ---------------------------------------------------------------- de Bruijn

def de_bruijn(length, n):
    """First `length` bytes of the De Bruijn sequence B(26, n) over a-z.

    Matches pwntools cyclic(length, n=n) / GEF `pattern create` / pwndbg `cyclic`.
    Standard FKM algorithm (iterative-friendly recursion via sys.setrecursionlimit).
    """
    k = len(ALPHABET)
    a = [0] * (k * n)
    out = bytearray()

    def db(t, p):
        if len(out) >= length:
            return
        if t > n:
            if n % p == 0:
                out.extend(ALPHABET[a[j]] for j in range(1, p + 1))
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                if len(out) >= length:
                    return
                a[t] = j
                db(t + 1, t)

    sys.setrecursionlimit(max(sys.getrecursionlimit(), n * k + 100))
    db(1, 1)
    return bytes(out[:length])


def cyclic_find(value, pattern, n):
    """Offset of `value` (int or bytes) in `pattern`, using an n-byte window.

    For an integer, the low n bytes little-endian are searched (pwntools behavior).
    Returns -1 if not found.
    """
    if isinstance(value, int):
        if value <= 0:
            return -1
        try:
            needle = value.to_bytes(8, "little")[:n]
        except OverflowError:
            return -1
    else:
        needle = bytes(value)[:n]
    if len(needle) < n or not needle:
        return -1
    return pattern.find(needle)


# ---------------------------------------------------------------- gdb driving

GDB_SCRIPT = """\
set pagination off
set confirm off
set disable-randomization on
set height unlimited
set width unlimited
run {runargs}
echo \\n===CRASH-STATE===\\n
info registers
echo ===STACK===\\n
x/4gx $rsp
echo ===SIGINFO===\\n
p/x $_siginfo._sifields._sigfault.si_addr
echo ===STACK32===\\n
x/4wx $esp
echo ===END===\\n
quit
"""


def run_gdb(gdb, target, mode, pattern, prefix, workdir):
    pat_file = os.path.join(workdir, "pattern.bin")
    with open(pat_file, "wb") as f:
        f.write(prefix + pattern + b"\n")

    if mode == "stdin":
        runargs = "< " + pat_file
    else:  # argv
        runargs = (prefix + pattern).decode("latin-1")

    script = os.path.join(workdir, "cmds.gdb")
    with open(script, "w") as f:
        f.write(GDB_SCRIPT.format(runargs=runargs))

    proc = subprocess.run(
        [gdb, "-q", "-nx", "-batch", "-x", script, target],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120,
    )
    out = proc.stdout.decode("latin-1", errors="replace")
    log = os.path.join(workdir, "gdb-transcript.log")
    with open(log, "w") as f:
        f.write(out)
    return out, pat_file, log


REG_RE = re.compile(r"^(rip|rsp|rbp|rax|rdi|rsi|rdx|eip|esp|ebp)\s+(0x[0-9a-f]+)", re.M)
SIG_RE = re.compile(r"Program received signal (SIG\w+)|Program terminated with signal (SIG\w+)")
MEM_RE = re.compile(r"^0x[0-9a-f]+[^:]*:\s+((?:0x[0-9a-f]+\s*)+)", re.M)
SIADDR_RE = re.compile(r"===SIGINFO===\s*\n\$\d+ = (0x[0-9a-f]+)")


def parse_crash(out):
    sig = None
    m = SIG_RE.search(out)
    if m:
        sig = m.group(1) or m.group(2)

    regs = {name: int(val, 16) for name, val in REG_RE.findall(out)}

    candidates = []  # (label, int_value)
    for r in ("rip", "eip"):
        if r in regs:
            candidates.append(("$" + r, regs[r]))
    for r in ("rbp", "ebp"):
        if r in regs:
            candidates.append(("$" + r, regs[r]))

    m = SIADDR_RE.search(out)
    if m:
        candidates.append(("si_addr (faulting access address)", int(m.group(1), 16)))

    # stack qwords after ===STACK===
    for marker, label in (("===STACK===", "[$rsp"), ("===STACK32===", "[$esp")):
        seg = out.split(marker, 1)
        if len(seg) == 2:
            body = seg[1].split("===", 1)[0]
            vals = []
            for mm in MEM_RE.finditer(body):
                vals.extend(int(v, 16) for v in mm.group(1).split())
            width = 8 if "rsp" in label else 4
            for i, v in enumerate(vals[:4]):
                candidates.append(("%s+%d]" % (label, i * width), v))
    return sig, regs, candidates


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="path to the binary to crash")
    ap.add_argument("--mode", choices=("stdin", "argv"), default="stdin",
                    help="deliver the pattern on stdin (default) or as argv[1]")
    ap.add_argument("-l", "--length", type=int, default=400,
                    help="pattern length in bytes (default 400)")
    ap.add_argument("--prefix", default="",
                    help="literal bytes to place before the pattern (e.g. a command word)")
    ap.add_argument("--gdb", default="gdb", help="gdb binary to use")
    args = ap.parse_args()

    gdb = shutil.which(args.gdb)
    if not gdb:
        print("[!] gdb not found on PATH. Install gdb (e.g. `apt install gdb`) and re-run.")
        print("    Manual fallback: GEF `pattern create %d` / pwndbg `cyclic %d`, crash the"
              % (args.length, args.length))
        print("    target yourself, then `pattern offset $rsp` / `cyclic -l $rsp`.")
        return 1

    if not os.path.exists(args.target):
        print("[!] target not found: %s" % args.target)
        return 1
    target = os.path.abspath(args.target)
    prefix = args.prefix.encode("latin-1")

    # n=8 pattern (GEF/pwndbg amd64 default): every 8-byte window is unique, so a
    # recovered qword maps to exactly one offset. The n=4 fallback lookup below covers
    # 32-bit targets, where only a dword is captured; n=8 hits are reported first
    # because 4-byte windows can repeat inside an n=8 sequence.
    pattern = de_bruijn(args.length, 8)
    workdir = tempfile.mkdtemp(prefix="gdb_offset_")
    print("[*] target     : %s" % target)
    print("[*] mode       : %s   length: %d   prefix: %r" % (args.mode, args.length, args.prefix))
    print("[*] evidence   : %s" % workdir)

    try:
        out, pat_file, log = run_gdb(gdb, target, args.mode, pattern, prefix, workdir)
    except subprocess.TimeoutExpired:
        print("[!] gdb timed out — target may block on input/network. Try --mode argv,")
        print("    or attach interactively: gdb -p <pid>.")
        return 1

    sig, regs, candidates = parse_crash(out)
    print("[*] transcript : %s" % log)
    print("[*] input file : %s" % pat_file)

    if not sig:
        print("[-] no crash signal observed. The target exited cleanly for %d bytes."
              % args.length)
        print("    Try a longer pattern (-l 2000), the other --mode, or a protocol-aware")
        print("    prefix (--prefix). Transcript kept for review.")
        return 2

    print("[+] crash signal: %s" % sig)
    if "rip" in regs:
        print("    rip=%#x rsp=%#x rbp=%#x" % (regs.get("rip", 0), regs.get("rsp", 0),
                                               regs.get("rbp", 0)))

    hit = None
    for label, val in candidates:
        for n in (8, 4):
            off = cyclic_find(val, pattern, n)
            if off >= 0:
                adj = off  # offset within the pattern; prefix bytes come before it
                print("[+] pattern hit: %-34s value=%#018x n=%d offset=%d"
                      % (label, val, n, adj))
                if hit is None:
                    hit = (label, val, adj)
    if hit is None:
        print("[-] crash reproduced but no pattern bytes found in rip/rbp/[rsp]/si_addr.")
        print("    Inspect the transcript: the corruption may be indirect (heap, canary")
        print("    abort via SIGABRT, or pointer mangling). Hand to interactive gdb.")
        return 2

    label, val, off = hit
    total = off + len(prefix)
    where = ("saved RIP (pattern at %s)" % label) if "rsp" in label or "rip" in label \
        else ("%s control" % label)
    print()
    print("[+] OFFSET: %d pattern bytes (%d including %d prefix bytes) -> %s"
          % (off, total, len(prefix), where))
    print("    payload layout: prefix(%d) + padding(%d) + <8-byte value>"
          % (len(prefix), off))

    stub = {
        "title": "Memory corruption in %s: %s at pattern offset %d (%s)"
                 % (os.path.basename(target), where, off, sig),
        "target": {"kind": "binary:file", "t": "file", "v": target},
        "severity": "high",
        "primitive": {"signal": sig, "controlled": label, "offset": off,
                      "value": "%#x" % val, "mode": args.mode,
                      "pattern_length": args.length},
        "repro": "python3 scripts/gdb_offset.py %s --mode %s -l %d%s"
                 % (target, args.mode, args.length,
                    (" --prefix %r" % args.prefix) if args.prefix else ""),
        "evidence": [log, pat_file],
    }
    import json
    print("FINDING-STUB: " + json.dumps(stub, separators=(",", ":")))
    print("[*] next: mark the asset vuln-identified (assets.mark), report via")
    print("    findings.report (see references/rupu.md), then load `pwntools` to build")
    print("    the payload.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
