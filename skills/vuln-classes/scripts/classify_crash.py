#!/usr/bin/env python3
"""classify_crash.py - classify a crash into a vulnerability class.

Input: an ASan/UBSan report or a gdb crash dump (register dump + faulting
instruction + optional backtrace), as a file argument or '-' for stdin.

Output: the vulnerability class, the primitive, the exploitation skill to
load next, and (optionally) a finding stub JSON for rupu findings.report.

Usage:
  python3 scripts/classify_crash.py report.txt [--json finding.json] [--binary ./target]
  ./target_asan crash.min 2>&1 | python3 scripts/classify_crash.py -

Standard library only; degrades gracefully on unrecognized input.
Signed: vulture (peach-cape).
"""

import argparse
import json
import re
import sys

# (class, primitive, skill) keyed by marker priority order.
CLASSES = {
    "stack-overflow": (
        "stack buffer overflow",
        "saved-RIP / stack-frame control",
        ["gdb-debugging", "pwntools", "rop-chains"],
    ),
    "heap-overflow": (
        "heap buffer overflow",
        "adjacent-chunk data/metadata corruption",
        ["heap-exploitation", "pwntools"],
    ),
    "uaf": (
        "use-after-free",
        "dangling-pointer / tcache-fastbin control",
        ["heap-exploitation", "pwntools"],
    ),
    "double-free": (
        "double free",
        "tcache/fastbin duplication -> arbitrary alloc",
        ["heap-exploitation", "pwntools"],
    ),
    "format-string": (
        "format string",
        "arbitrary read/write via %p/%s/%n",
        ["format-string-exploitation", "pwntools"],
    ),
    "integer-bug": (
        "integer overflow/underflow or signedness error",
        "undersized allocation / oversized copy -> OOB",
        ["fuzzing", "heap-exploitation"],
    ),
    "off-by-one": (
        "off-by-one / null-byte overflow",
        "chunk-size (prev_inuse/LSB) corruption",
        ["heap-exploitation"],
    ),
    "oob-read": (
        "out-of-bounds read",
        "information leak (addresses/canary/secrets)",
        ["format-string-exploitation", "gdb-debugging"],
    ),
    "unknown": (
        "unclassified crash",
        "unknown - inspect in a debugger",
        ["gdb-debugging", "vuln-classes"],
    ),
}

FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")
REG_RE = re.compile(r"\b(rip|eip|pc|rsp|rbp|rdi|rsi|rax|rbx)\b[\s=:]+"
                    r"(0x[0-9a-fA-F]+)", re.I)
WRITE_SIZE_RE = re.compile(r"\b(READ|WRITE) of size (\d+)")
REGION_END_RE = re.compile(r"(\d+) bytes? to the right of")
NOISE = ("__asan", "__interceptor", "__sanitizer", "__ubsan", "__lsan")

PRINTF_FNS = ("printf", "vfprintf", "vsnprintf", "vprintf", "fprintf",
              "snprintf", "sprintf", "__vfprintf_internal", "vasprintf",
              "syslog")
ALLOC_FNS = ("malloc", "_int_malloc", "_int_free", "free", "calloc",
             "realloc", "unlink_chunk", "tcache_", "malloc_consolidate",
             "malloc_printerr")


def cyclic_like(val):
    """True if a value looks like a de Bruijn / 'AAAA' style pattern."""
    try:
        b = int(val, 16).to_bytes(8, "little").rstrip(b"\x00")
    except (ValueError, OverflowError):
        return False
    return len(b) >= 4 and all(0x41 <= c <= 0x7a for c in b)


def frames_of(text):
    out = []
    for m in FRAME_RE.finditer(text):
        fn = m.group(1)
        if not any(n in fn for n in NOISE):
            out.append(fn)
    return out


def classify(text):
    """Return (class_key, reasons:list, details:dict)."""
    t = text
    low = t.lower()
    frames = frames_of(t)
    regs = {m.group(1).lower(): m.group(2) for m in REG_RE.finditer(t)}
    rw = WRITE_SIZE_RE.search(t)
    reasons = []

    # --- ASan keywords (most reliable) ---
    if "stack-buffer-overflow" in low or "stack smashing detected" in low \
            or "stack-buffer-underflow" in low:
        return "stack-overflow", ["ASan/libc stack overflow marker"], \
            {"frames": frames, "regs": regs}
    if "heap-use-after-free" in low or "use-after-poison" in low:
        return "uaf", ["ASan heap-use-after-free"], {"frames": frames, "regs": regs}
    if "double-free" in low or "double free or corruption" in low \
            or "free(): double free" in low:
        return "double-free", ["double-free marker"], {"frames": frames, "regs": regs}
    if "allocation-size-too-big" in low or "negative-size-param" in low \
            or "calloc-overflow" in low or "signed integer overflow" in low \
            or "unsigned integer overflow" in low:
        return "integer-bug", ["sanitizer size/arith overflow marker"], \
            {"frames": frames, "regs": regs}
    if "heap-buffer-overflow" in low:
        # off-by-one: WRITE of size 1 exactly at region end
        if rw and rw.group(1) == "WRITE" and rw.group(2) == "1":
            m = REGION_END_RE.search(t)
            if m and int(m.group(1)) <= 1:
                return "off-by-one", ["ASan heap WRITE size 1 at region end"], \
                    {"frames": frames, "regs": regs}
        if rw and rw.group(1) == "READ":
            return "oob-read", ["ASan heap-buffer-overflow READ"], \
                {"frames": frames, "regs": regs}
        return "heap-overflow", ["ASan heap-buffer-overflow WRITE"], \
            {"frames": frames, "regs": regs}

    # --- gdb-dump heuristics ---
    pc = regs.get("rip") or regs.get("eip") or regs.get("pc")
    if pc and cyclic_like(pc):
        return "stack-overflow", ["PC = cyclic/ASCII pattern bytes (%s)" % pc], \
            {"frames": frames, "regs": regs}
    if any(any(fn.startswith(p) or p in fn for p in PRINTF_FNS) for fn in frames[:3]):
        reasons.append("fault inside printf family: %s" % frames[0])
        return "format-string", reasons, {"frames": frames, "regs": regs}
    if any(any(a in fn for a in ALLOC_FNS) for fn in frames[:3]) \
            or "malloc(): " in low or "free(): invalid" in low \
            or "corrupted size vs. prev_size" in low \
            or "invalid pointer" in low and "free" in low:
        reasons.append("fault/abort inside allocator internals")
        return "heap-overflow", reasons, {"frames": frames, "regs": regs}
    if pc:
        try:
            v = int(pc, 16)
            if v > 0xffffffff00000000 or v < 0x1000:
                return "integer-bug", ["PC/fault address wrapped (%s)" % pc], \
                    {"frames": frames, "regs": regs}
        except ValueError:
            pass
    if "segv on unknown address" in low or "sigsegv" in low:
        return "unknown", ["SEGV without class marker - debug it"], \
            {"frames": frames, "regs": regs}
    return "unknown", ["no recognized markers"], {"frames": frames, "regs": regs}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", help="ASan report / gdb dump file, or '-' for stdin")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="write a finding stub JSON here")
    ap.add_argument("--binary", default=None, help="target binary path (for the stub)")
    args = ap.parse_args()

    try:
        if args.report == "-":
            text = sys.stdin.read()
        else:
            with open(args.report, errors="replace") as f:
                text = f.read()
    except OSError as e:
        print("[!] cannot read input: %s" % e)
        return 1
    if not text.strip():
        print("[!] empty input - nothing to classify")
        return 1

    key, reasons, det = classify(text)
    name, primitive, skills = CLASSES[key]
    frames = det.get("frames", [])

    print("class      : %s (%s)" % (name, key))
    print("evidence   : %s" % "; ".join(reasons))
    if frames:
        print("fault fn   : %s" % frames[0])
        print("frames     : %s" % " <- ".join(frames[:5]))
    if det.get("regs"):
        print("registers  : %s" % " ".join("%s=%s" % kv
                                           for kv in sorted(det["regs"].items())))
    print("primitive  : %s" % primitive)
    print("next skill : load %s" % ", ".join("`%s`" % s for s in skills))
    print("reference  : skills/vuln-classes/references/%s.md"
          % {"uaf": "uaf-double-free", "double-free": "uaf-double-free",
             "integer-bug": "integer-bugs", "oob-read": "heap-overflow",
             "unknown": "stack-overflow"}.get(key, key))

    if args.json_out:
        stub = {
            "title": "%s in %s" % (name, frames[0] if frames else "unknown function"),
            "vuln_class": key,
            "primitive": primitive,
            "binary": args.binary,
            "faulting_function": frames[0] if frames else None,
            "frames": frames[:8],
            "evidence_excerpt": text[:2000],
            "next_skills": skills,
            "status": "identified-unconfirmed" if key == "unknown" else "identified",
        }
        try:
            with open(args.json_out, "w") as f:
                json.dump(stub, f, indent=2)
                f.write("\n")
            print("[*] finding stub -> %s (feed to rupu findings.report; "
                  "see the finding-report skill)" % args.json_out)
        except OSError as e:
            print("[!] cannot write %s: %s" % (args.json_out, e))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
