#!/usr/bin/env python3
"""binary-protections normalizer.

Reads a binary's exploit mitigations, preferring `checksec --output=json`,
falling back to `rabin2 -Ij`, then to raw readelf parsing. Prints a
normalized JSON record per file:

    {file, sha256, relro, canary, nx, pie, fortify, rpath, runpath, source}

(JSON array on stdout) plus one "plan implication" line per protection and a
ready-to-replay `[rupu] assets.mark` line on stderr. Degrades gracefully when
tools are missing.

Usage:
    python3 scripts/checksec_json.py ./target [more...] [-o protections.json]
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

MISSING = set()


def have(tool):
    ok = shutil.which(tool) is not None
    if not ok:
        MISSING.add(tool)
    return ok


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1, ""


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def norm_yesno(v):
    if v in (True, "yes", "Yes", "true", "True", "Canary found", "Enabled"):
        return "yes"
    if v in (False, "no", "No", "false", "False", "N/A", "Disabled"):
        return "no"
    return "unknown"

# ---------------------------------------------------------------- sources


def from_checksec(path):
    """checksec.sh JSON output. Returns normalized dict or None."""
    if not have("checksec"):
        return None
    rc, out = run(["checksec", "--output=json", "--file=%s" % path])
    out = out.strip()
    if rc != 0 or not out.startswith("{"):
        return None
    try:
        data = json.loads(out)
    except ValueError:
        return None
    rec = data.get(os.path.abspath(path)) or data.get(path)
    if rec is None and len(data) == 1:
        rec = next(iter(data.values()))
    if not isinstance(rec, dict):
        return None
    relro = str(rec.get("relro", "unknown")).lower()
    return {
        "relro": relro if relro in ("full", "partial") else
                 ("none" if relro in ("no", "none") else "unknown"),
        "canary": norm_yesno(rec.get("canary")),
        "nx": norm_yesno(rec.get("nx")),
        "pie": str(rec.get("pie", "unknown")).lower(),  # yes/no/dso/rel
        "fortify": norm_yesno(rec.get("fortify_source",
                                      rec.get("fortify"))),
        "rpath": "none" if norm_yesno(rec.get("rpath")) == "no"
                 else str(rec.get("rpath")),
        "runpath": "none" if norm_yesno(rec.get("runpath")) == "no"
                   else str(rec.get("runpath")),
        "source": "checksec",
    }


def from_rabin2(path):
    if not have("rabin2"):
        return None
    rc, out = run(["rabin2", "-Ij", path])
    if rc != 0 or not out.strip():
        return None
    try:
        data = json.loads(out)
    except ValueError:
        return None
    if isinstance(data, dict):
        data = data.get("info", data)
    if not isinstance(data, dict) or ("nx" not in data and
                                      "canary" not in data):
        return None
    relro = str(data.get("relro", "unknown")).lower()
    return {
        "relro": relro if relro in ("full", "partial") else
                 ("none" if "relro" in data else "unknown"),
        "canary": "yes" if data.get("canary") else "no",
        "nx": "yes" if data.get("nx") else "no",
        "pie": "yes" if data.get("pic") else "no",
        "fortify": "unknown",       # rabin2 -I does not report it reliably
        "rpath": "unknown",
        "runpath": "unknown",
        "source": "rabin2",
    }


def from_readelf(path):
    if not have("readelf"):
        return None
    _, hdr = run(["readelf", "-h", path])
    if "ELF Header" not in hdr:
        return None                 # not ELF (or readelf failed)
    _, seg = run(["readelf", "-lW", path])
    _, dyn = run(["readelf", "-d", path])
    _, dsym = run(["readelf", "--dyn-syms", "-W", path])

    m = re.search(r"Type:\s+(\w+)", hdr)
    etype = m.group(1) if m else ""
    pie = ("no" if etype == "EXEC"
           else ("yes" if "INTERP" in seg else "dso") if etype == "DYN"
           else "rel" if etype == "REL" else "unknown")
    if "GNU_STACK" in seg:
        nx = "no" if re.search(r"GNU_STACK\s+(?:\S+\s+){5}RWE", seg) else "yes"
    else:
        nx = "unknown"              # no PT_GNU_STACK: loader-dependent, often exec
    relro_seg = "GNU_RELRO" in seg
    bind_now = bool(re.search(r"\b(BIND_NOW|FLAGS_1.*\bNOW\b)", dyn))
    relro = ("full" if relro_seg and bind_now
             else "partial" if relro_seg else "none")
    canary = "yes" if "__stack_chk_fail" in (dsym + dyn) else "no"
    fortify = "yes" if re.search(r"__\w+_chk\b", dsym) else "no"
    rp = re.search(r"\(RPATH\)\s+.*\[(.*)\]", dyn)
    rn = re.search(r"\(RUNPATH\)\s+.*\[(.*)\]", dyn)
    return {
        "relro": relro, "canary": canary, "nx": nx, "pie": pie,
        "fortify": fortify,
        "rpath": rp.group(1) if rp else "none",
        "runpath": rn.group(1) if rn else "none",
        "source": "readelf",
    }

# ---------------------------------------------------------------- plan text

def implications(p):
    out = []
    nx = p["nx"]
    if nx == "no":
        out.append("nx=no       -> writable memory executes: inject shellcode "
                   "and jump to it (jmp rsp gadget avoids address guessing)")
    elif nx == "yes":
        out.append("nx=yes      -> no injected shellcode: plan ROP / ret2libc "
                   "/ SROP, or mprotect-stage back to shellcode")
    can = p["canary"]
    if can == "yes":
        out.append("canary=yes  -> plain stack smash aborts ('stack smashing "
                   "detected'): need a leak, a byte-wise brute on a forking "
                   "server, or a write that skips the canary")
    elif can == "no":
        out.append("canary=no   -> linear stack overflow straight to the "
                   "return address")
    pie = p["pie"]
    if pie == "no":
        out.append("pie=no      -> binary addresses fixed: ret2plt leak and "
                   "GOT work with NO prior leak")
    elif pie in ("yes", "dso"):
        out.append("pie=%s -> leak one .text/libc pointer before any "
                   "absolute-address work; low 12 bits are never randomized "
                   "(partial overwrite trick)" % pie.ljust(3))
    rel = p["relro"]
    if rel in ("none", "partial"):
        out.append("relro=%s -> GOT writable: prime write-what-where target; "
                   "lazy binding also enables ret2dlresolve" % rel)
    elif rel == "full":
        out.append("relro=full  -> GOT read-only: pivot to hooks (glibc<2.34) "
                   "/ FSOP / exit handlers / pure ROP")
    if p["fortify"] == "yes":
        out.append("fortify=yes -> *_chk variants: %n in writable format "
                   "strings blocked; %p/%s leaks still work; audit for raw "
                   "unfortified call sites")
    for k in ("rpath", "runpath"):
        if p[k] not in ("none", "unknown", "no"):
            out.append("%s=%s -> library search hijack candidate (plant a "
                       ".so if the dir is writable/relative)" % (k, p[k]))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("-o", "--output", default=None,
                    help="also write the JSON array to this file")
    args = ap.parse_args()

    records = []
    for path in args.binaries:
        if not os.path.isfile(path):
            print("[!] not a file, skipping: %s" % path, file=sys.stderr)
            continue
        rec = from_checksec(path) or from_rabin2(path) or from_readelf(path)
        if rec is None:
            print("[!] %s: no usable reader (install checksec, radare2 or "
                  "binutils) -- emitting unknowns" % path, file=sys.stderr)
            rec = {k: "unknown" for k in
                   ("relro", "canary", "nx", "pie", "fortify",
                    "rpath", "runpath")}
            rec["source"] = "none"
        digest = sha256(path)
        rec = dict({"file": os.path.abspath(path), "sha256": digest}, **rec)
        records.append(rec)

        print("# %s  (source: %s)" % (path, rec["source"]), file=sys.stderr)
        for line in implications(rec):
            print("  %s" % line, file=sys.stderr)
        coord = digest or os.path.abspath(path)
        print("  [rupu] assets.mark kind=binary:file coords=[{t: file, v: %s}]"
              " depth=analyzed note=\"relro=%s canary=%s nx=%s pie=%s "
              "fortify=%s rpath=%s runpath=%s\""
              % (coord, rec["relro"], rec["canary"], rec["nx"], rec["pie"],
                 rec["fortify"], rec["rpath"], rec["runpath"]),
              file=sys.stderr)
        print(file=sys.stderr)

    print(json.dumps(records, indent=2))
    if args.output:
        with open(args.output, "w") as f:
            json.dump(records, f, indent=2)
            f.write("\n")
        print("[+] wrote %s" % args.output, file=sys.stderr)
    if MISSING:
        print("[i] tools not found (fallbacks used where possible): %s"
              % ", ".join(sorted(MISSING)), file=sys.stderr)


if __name__ == "__main__":
    main()
