#!/usr/bin/env python3
"""
find_gadgets.py — run ROPgadget and/or ropper on a binary, parse the output, and
print a categorized gadget table plus a JSON file of the key gadgets.

Usage:
    python3 scripts/find_gadgets.py ./target
    python3 scripts/find_gadgets.py ./target --json gadgets.json
    python3 scripts/find_gadgets.py ./target --badbytes 0a00
    python3 scripts/find_gadgets.py ./target --work-units units.json

Degrades gracefully: if neither ROPgadget nor ropper is installed, prints install
hints and exits 0. Standard library only.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys

GADGET_LINE = re.compile(r"^(0x[0-9a-fA-F]+)\s*:\s*(.+?)\s*$")

# category name -> list of normalized instruction-sequence regexes
CATEGORIES = {
    "pop rdi ; ret":        [r"^pop rdi ; ret$"],
    "pop rsi ; ret":        [r"^pop rsi ; ret$"],
    "pop rsi ; pop r15 ; ret": [r"^pop rsi ; pop r15 ; ret$"],
    "pop rdx ; ret":        [r"^pop rdx ; ret$", r"^pop rdx ; pop rbx ; ret$",
                             r"^pop rdx ; pop r12 ; ret$"],
    "pop rax ; ret":        [r"^pop rax ; ret$"],
    "pop rsp":              [r"^pop rsp( ; pop \w+)* ; ret$"],
    "other pop reg ; ret":  [r"^pop \w+ ; ret$"],
    "ret":                  [r"^ret$"],
    "syscall ; ret":        [r"^syscall ; ret$"],
    "syscall":              [r"^syscall$"],
    "int 0x80":             [r"^int 0x80( ; ret)?$"],
    "leave ; ret":          [r"^leave ; ret$"],
    "xchg reg, rsp/esp":    [r"^xchg [er]ax, [er]sp ; ret$",
                             r"^xchg [er]sp, [er]ax ; ret$"],
    "write-what-where":     [r"^mov (qword|dword)? ?\[\w+\], \w+ ; ret$",
                             r"^mov \[\w+\], \w+ ; ret$"],
}

# keys exported in the JSON summary -> category above (first/lowest address wins)
KEY_EXPORTS = {
    "pop_rdi_ret": "pop rdi ; ret",
    "pop_rsi_ret": "pop rsi ; ret",
    "pop_rsi_pop_r15_ret": "pop rsi ; pop r15 ; ret",
    "pop_rdx_ret": "pop rdx ; ret",
    "pop_rax_ret": "pop rax ; ret",
    "pop_rsp": "pop rsp",
    "ret": "ret",
    "syscall_ret": "syscall ; ret",
    "syscall": "syscall",
    "int_0x80": "int 0x80",
    "leave_ret": "leave ; ret",
    "xchg_rsp": "xchg reg, rsp/esp",
}


def norm(insns: str) -> str:
    """Normalize an instruction sequence: lowercase, single spaces, ' ; ' seps."""
    parts = [p.strip() for p in insns.lower().split(";") if p.strip()]
    parts = [re.sub(r"\s+", " ", p) for p in parts]
    return " ; ".join(parts)


def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return out.stdout + "\n" + out.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"[-] {cmd[0]} failed: {e}", file=sys.stderr)
        return ""


def gadgets_from_output(text):
    """Yield (addr_int, normalized_insns) from ROPgadget or ropper output lines."""
    for line in text.splitlines():
        m = GADGET_LINE.match(line.strip())
        if not m:
            continue
        insns = m.group(2)
        # ropper appends '(1 found)' etc. on search lines; strip annotations
        insns = re.sub(r"\(\d+ found\)", "", insns).strip()
        if not insns or insns.startswith("Gadgets information"):
            continue
        yield int(m.group(1), 16), norm(insns)


def collect(binary, badbytes):
    """Run whichever tools exist; return (toolname(s), {norm_insns: min_addr})."""
    tools, found = [], {}
    if shutil.which("ROPgadget"):
        cmd = ["ROPgadget", "--binary", binary, "--depth", "10"]
        if badbytes:
            cmd += ["--badbytes", "|".join(badbytes[i:i+2] for i in range(0, len(badbytes), 2))]
        text = run(cmd)
        for addr, insns in gadgets_from_output(text):
            if insns not in found or addr < found[insns]:
                found[insns] = addr
        tools.append("ROPgadget")
    if shutil.which("ropper"):
        cmd = ["ropper", "--file", binary, "--nocolor", "--all"]
        if badbytes:
            cmd += ["--badbytes", badbytes]
        text = run(cmd)
        for addr, insns in gadgets_from_output(text):
            if insns not in found or addr < found[insns]:
                found[insns] = addr
        tools.append("ropper")
    return tools, found


def categorize(found):
    cats = {name: [] for name in CATEGORIES}
    for insns, addr in found.items():
        for name, patterns in CATEGORIES.items():
            if any(re.match(p, insns) for p in patterns):
                cats[name].append((addr, insns))
                break
    for name in cats:
        cats[name].sort()
    return cats


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", help="target ELF")
    ap.add_argument("--json", default="gadgets.json", help="key-gadget JSON output path")
    ap.add_argument("--badbytes", default="", help="bad bytes as hex string, e.g. 0a00")
    ap.add_argument("--work-units", help="also emit a rupu work-units JSON array here")
    args = ap.parse_args()

    tools, found = collect(args.binary, args.badbytes)
    if not tools:
        print("[-] Neither ROPgadget nor ropper is installed.")
        print("    pip install ROPgadget   (or)   pip install ropper")
        print("    Fallback: r2 -q -c '/R pop rdi' " + args.binary)
        sys.exit(0)
    print(f"[+] tools: {', '.join(tools)} | unique gadget sequences: {len(found)}")

    cats = categorize(found)
    print(f"\n{'category':<26} {'count':>5}  best (lowest) address")
    print("-" * 72)
    for name, items in cats.items():
        best = f"{items[0][0]:#x}  {items[0][1]}" if items else "-"
        print(f"{name:<26} {len(items):>5}  {best}")

    # ready-to-paste lines for the usual suspects
    print("\n[+] paste-ready:")
    for label in ("pop rdi ; ret", "pop rsi ; ret", "pop rsi ; pop r15 ; ret",
                  "ret", "syscall ; ret", "leave ; ret"):
        if cats[label]:
            addr, insns = cats[label][0]
            print(f"    {insns:<28} = {addr:#x}")

    digest = sha256(args.binary)
    summary = {
        "binary": args.binary,
        "sha256": digest,
        "tools": tools,
        "gadgets": {
            key: (f"{cats[cat][0][0]:#x}" if cats[cat] else None)
            for key, cat in KEY_EXPORTS.items()
        },
        "counts": {name: len(items) for name, items in cats.items()},
    }
    with open(args.json, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[+] key-gadget JSON written to {args.json}")

    if args.work_units:
        slug = re.sub(r"[^a-z0-9-]+", "-", args.binary.lower()).strip("-")
        g = summary["gadgets"]
        hints = sorted({"pwntools", "rop-chains"} |
                       ({"srop"} if g["syscall"] or g["syscall_ret"] else set()))
        units = [{
            "id": f"build-rop-chain-{slug}",
            "title": f"Build ROP chain for {args.binary} from discovered gadgets",
            "targets": [{"kind": "binary:file", "t": "file",
                         "v": digest or args.binary}],
            "hints": hints,
        }]
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)
        print(f"[+] work units written to {args.work_units}")


if __name__ == "__main__":
    main()
