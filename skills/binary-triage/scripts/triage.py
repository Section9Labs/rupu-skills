#!/usr/bin/env python3
"""binary-triage consolidated runner.

Shells out to file/strings/nm/readelf/objdump/rabin2 (and checksec when
present), parses their output, prints a human report with a protections
summary and a dangerous-imports table, and writes a rupu work-units JSON
array (one unit per binary). Degrades gracefully when a tool is missing.

Usage:
    python3 scripts/triage.py ./target [more binaries...] \
        [-o work-units.json] [--evidence-dir DIR] [--max-strings 10]
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------- knowledge

DANGEROUS_IMPORTS = {
    "gets":      "unbounded stdin read -- guaranteed stack overflow",
    "strcpy":    "no bounds check -- overflow if source is tainted",
    "strcat":    "no bounds check -- overflow by concatenation",
    "sprintf":   "no bounds check on destination buffer",
    "vsprintf":  "no bounds check on destination buffer",
    "scanf":     "overflow if %s/%[ used without a width",
    "sscanf":    "overflow if %s/%[ used without a width",
    "fscanf":    "overflow if %s/%[ used without a width",
    "system":    "shell execution -- injection if argument is tainted; ret2libc target",
    "popen":     "shell execution -- injection if argument is tainted",
    "execve":    "process execution -- audit argv/envp provenance",
    "execl":     "process execution -- audit arguments",
    "execlp":    "process execution, PATH lookup -- PATH hijack",
    "execv":     "process execution -- audit arguments",
    "execvp":    "process execution, PATH lookup -- PATH hijack",
    "memcpy":    "audit every length argument (tainted length = overflow)",
    "strncpy":   "truncation / missing NUL -- audit size argument",
    "printf":    "format string vuln if arg1 is user data",
    "fprintf":   "format string vuln if format is user data",
    "snprintf":  "format string vuln if format is user data",
    "syslog":    "format string vuln if message is user data",
    "malloc":    "heap in play -- UAF/double-free/overflow class",
    "free":      "heap in play -- double-free/UAF class",
    "realloc":   "heap in play -- stale pointer bugs",
    "alloca":    "runtime-sized stack allocation -- stack clash",
    "setuid":    "privilege transition -- check ordering and return values",
    "setgid":    "privilege transition",
    "seteuid":   "privilege transition",
    "dlopen":    "runtime library load -- path hijack if tainted",
    "rand":      "non-crypto PRNG -- predictable values",
    "srand":     "PRNG seeding -- often time(NULL), predictable",
    "mktemp":    "predictable temp file name -- race",
    "tmpnam":    "predictable temp file name -- race",
}

SURFACE_IMPORTS = {
    "argv":    {"getopt", "getopt_long", "getopt_long_only", "argp_parse"},
    "stdin":   {"gets", "fgets", "getline", "getchar", "fgetc", "scanf"},
    "file":    {"fopen", "fopen64", "open", "openat", "fread", "mmap"},
    "network": {"socket", "bind", "listen", "accept", "accept4", "connect",
                "recv", "recvfrom", "recvmsg", "send", "sendto", "getaddrinfo"},
    "env":     {"getenv", "secure_getenv", "putenv", "setenv"},
}

STRING_HUNTS = [
    ("credential",  re.compile(r"(?i)(password|passwd|secret|api[_-]?key|"
                               r"token|BEGIN [A-Z ]*PRIVATE KEY)")),
    ("url",         re.compile(r"https?://[\w.\-/:%?=&+]+")),
    ("ip",          re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("format-%n",   re.compile(r"%[-#0-9.$lh]*n")),
    ("shell-tmpl",  re.compile(r"(/bin/(?:ba|da)?sh|\bsh -c\b|2>&1|\|\s*sh\b)")),
    ("sql",         re.compile(r"(?i)\b(SELECT\s|INSERT INTO|UPDATE\s.*\bSET|"
                               r"DELETE FROM)")),
    ("version",     re.compile(r"(GCC: \(|GNU C Library|glibc 2\.\d|"
                               r"OpenSSL \d|libcurl/|clang version)")),
    ("build-path",  re.compile(r"(/home/\S+|/Users/\S+|/build/\S+|"
                               r"\S+\.(?:c|cc|cpp|go|rs):?)$")),
]

HINTS = sorted(["binary-protections", "ghidra-headless", "radare2"])

# ---------------------------------------------------------------- plumbing

MISSING_TOOLS = set()


def have(tool):
    ok = shutil.which(tool) is not None
    if not ok:
        MISSING_TOOLS.add(tool)
    return ok


def run(cmd, timeout=180):
    """Run a command; return stdout ('' on any failure, never raises)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        print("  [!] cannot hash %s: %s" % (path, e), file=sys.stderr)
        return None


def save_evidence(evdir, base, tool, text):
    if not evdir or not text:
        return
    os.makedirs(evdir, exist_ok=True)
    fn = os.path.join(evdir, "%s.%s.txt" % (base, tool))
    try:
        with open(fn, "w", errors="replace") as f:
            f.write(text)
    except OSError:
        pass


def slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "bin"

# ---------------------------------------------------------------- collectors


def identify(path, base, evdir):
    info = {"format": "unknown", "arch": "unknown", "bits": None,
            "linkage": "unknown", "stripped": None, "pie": None,
            "raw_file": ""}
    if have("file"):
        out = run(["file", "-b", path]).strip()
        outk = run(["file", "-b", "-k", path]).strip()
        save_evidence(evdir, base, "file", out + "\n--- file -k ---\n" + outk)
        info["raw_file"] = out
        if out.startswith("ELF"):
            info["format"] = "elf"
        elif "PE32+" in out:
            info["format"], info["bits"] = "pe", 64
        elif "PE32" in out:
            info["format"], info["bits"] = "pe", 32
        elif "Mach-O" in out:
            info["format"] = "mach-o"
        elif out:
            info["format"] = "blob"
        m = re.search(r"(x86-64|x86_64|aarch64|arm64|ARM|Intel 80386|i386|"
                      r"MIPS\S*|PowerPC|RISC-V|SPARC\S*)", out, re.I)
        if m:
            info["arch"] = m.group(1).lower().replace("intel 80386", "i386")
        if "64-bit" in out:
            info["bits"] = 64
        elif "32-bit" in out:
            info["bits"] = 32
        if "statically linked" in out:
            info["linkage"] = "static"
        elif "dynamically linked" in out:
            info["linkage"] = "dynamic"
        if "not stripped" in out:
            info["stripped"] = False
        elif "stripped" in out:
            info["stripped"] = True
        if "pie executable" in out or "shared object" in out:
            info["pie"] = True
        elif info["format"] == "elf" and " executable" in out:
            info["pie"] = False
        # trailing data after the primary match => appended payload
        extra = [l for l in outk.splitlines()[1:] if l.strip(" -")]
        if extra:
            info["appended_data"] = "; ".join(extra)[:200]
    return info


def rabin2_info(path, base, evdir, info):
    if not have("rabin2"):
        return
    out = run(["rabin2", "-Ij", path])
    save_evidence(evdir, base, "rabin2-I", out)
    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        return
    if isinstance(data, dict):
        data = data.get("info", data)
    if not isinstance(data, dict):
        return
    info.setdefault("rabin2", {})
    for k in ("canary", "nx", "pic", "relro", "stripped", "static",
              "arch", "bits", "endian", "lang", "os"):
        if k in data:
            info["rabin2"][k] = data[k]
    if info["arch"] == "unknown" and data.get("arch"):
        info["arch"] = str(data["arch"])
    if info["bits"] is None and data.get("bits"):
        info["bits"] = data["bits"]
    if info["pie"] is None and "pic" in data:
        info["pie"] = bool(data["pic"])
    if info["stripped"] is None and "stripped" in data:
        info["stripped"] = bool(data["stripped"])


def collect_imports(path, base, evdir, fmt):
    imports = set()
    if fmt == "elf" and have("nm"):
        out = run(["nm", "-D", "--undefined-only", path])
        save_evidence(evdir, base, "nm-D-undef", out)
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[-1] not in ("symbols", ""):
                imports.add(parts[-1].split("@")[0])
    if not imports and have("rabin2"):
        out = run(["rabin2", "-ij", path])
        save_evidence(evdir, base, "rabin2-i", out)
        try:
            data = json.loads(out)
            rows = data.get("imports", data) if isinstance(data, dict) else data
            for row in rows or []:
                name = row.get("name", "")
                # strip PE "KERNEL32.dll_" style prefixes for matching
                imports.add(name.split("::")[-1].split("_", 1)[-1]
                            if name.lower().startswith(("kernel32", "msvcrt"))
                            else name)
        except (ValueError, TypeError, AttributeError):
            pass
    return sorted(imports)


def readelf_protections(path, base, evdir):
    """Fallback/confirmation protections read for ELF."""
    p = {}
    if not have("readelf"):
        return p
    hdr = run(["readelf", "-h", path])
    seg = run(["readelf", "-lW", path])
    dyn = run(["readelf", "-d", path])
    dsym = run(["readelf", "--dyn-syms", "-W", path])
    save_evidence(evdir, base, "readelf",
                  hdr + "\n" + seg + "\n" + dyn + "\n" + dsym)
    m = re.search(r"Type:\s+(\w+)", hdr)
    etype = m.group(1) if m else ""
    has_interp = "INTERP" in seg
    if etype == "EXEC":
        p["pie"] = "no"
    elif etype == "DYN":
        p["pie"] = "yes" if has_interp else "dso"
    if "GNU_STACK" in seg:
        p["nx"] = "no" if re.search(r"GNU_STACK\s+(\S+\s+){5}RWE", seg) else "yes"
    relro_seg = "GNU_RELRO" in seg
    bind_now = bool(re.search(r"\b(BIND_NOW|FLAGS_1.*\bNOW\b)", dyn))
    p["relro"] = ("full" if relro_seg and bind_now
                  else "partial" if relro_seg else "none")
    p["canary"] = ("yes" if ("__stack_chk_fail" in dsym or
                             "__stack_chk_fail" in dyn) else "no")
    p["fortify"] = "yes" if re.search(r"__\w+_chk\b", dsym) else "no"
    rp = re.search(r"\(RPATH\)\s+.*\[(.*)\]", dyn)
    rn = re.search(r"\(RUNPATH\)\s+.*\[(.*)\]", dyn)
    p["rpath"] = rp.group(1) if rp else None
    p["runpath"] = rn.group(1) if rn else None
    p["needed"] = re.findall(r"\(NEEDED\)\s+Shared library: \[(.*?)\]", dyn)
    return p


def checksec_read(path, base, evdir):
    if not have("checksec"):
        return {}
    out = run(["checksec", "--output=json", "--file=%s" % path])
    save_evidence(evdir, base, "checksec", out)
    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        return {}
    rec = data.get(os.path.abspath(path)) or data.get(path)
    if rec is None and isinstance(data, dict) and len(data) == 1:
        rec = next(iter(data.values()))
    return rec if isinstance(rec, dict) else {}


def hunt_strings(path, base, evdir, max_per):
    hits = {}
    if not have("strings"):
        return hits
    ascii_out = run(["strings", "-a", "-t", "x", "-n", "8", path])
    utf16_out = run(["strings", "-a", "-e", "l", "-t", "x", "-n", "8", path])
    save_evidence(evdir, base, "strings", ascii_out)
    save_evidence(evdir, base, "strings-utf16le", utf16_out)
    for blob in (ascii_out, utf16_out):
        for line in blob.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            off, s = parts
            for name, rx in STRING_HUNTS:
                if rx.search(s):
                    hits.setdefault(name, [])
                    if len(hits[name]) < max_per:
                        hits[name].append((off, s[:160]))
    return hits

# ---------------------------------------------------------------- reporting


def triage_one(path, evdir, max_strings):
    base = os.path.basename(path)
    print("=" * 72)
    print("TARGET: %s" % path)
    digest = sha256(path)
    if digest:
        print("sha256: %s" % digest)

    info = identify(path, base, evdir)
    rabin2_info(path, base, evdir, info)
    print("file:   %s" % (info["raw_file"] or "(file(1) unavailable)"))
    if info.get("appended_data"):
        print("  [!] trailing/appended data (file -k): %s"
              % info["appended_data"])

    # protections summary (checksec > rabin2 > readelf)
    cs = checksec_read(path, base, evdir)
    re_p = readelf_protections(path, base, evdir) if info["format"] == "elf" else {}
    rb = info.get("rabin2", {})

    def pick(*vals):
        for v in vals:
            if v not in (None, "", {}):
                return v
        return "unknown"

    prot = {
        "relro":  pick(cs.get("relro"), rb.get("relro"), re_p.get("relro")),
        "canary": pick(cs.get("canary"),
                       None if "canary" not in rb else ("yes" if rb["canary"] else "no"),
                       re_p.get("canary")),
        "nx":     pick(cs.get("nx"),
                       None if "nx" not in rb else ("yes" if rb["nx"] else "no"),
                       re_p.get("nx")),
        "pie":    pick(cs.get("pie"),
                       None if "pic" not in rb else ("yes" if rb["pic"] else "no"),
                       re_p.get("pie")),
        "fortify": pick(cs.get("fortify_source"), re_p.get("fortify")),
        "rpath":  pick(cs.get("rpath"), re_p.get("rpath"), "no"),
        "runpath": pick(cs.get("runpath"), re_p.get("runpath"), "no"),
    }
    print("\nPROTECTIONS (interpret with the binary-protections skill)")
    for k in ("relro", "canary", "nx", "pie", "fortify", "rpath", "runpath"):
        print("  %-8s %s" % (k, prot[k]))
    if re_p.get("needed"):
        print("  needed   %s" % ", ".join(re_p["needed"]))

    # imports
    imports = collect_imports(path, base, evdir, info["format"])
    flagged = [(i, DANGEROUS_IMPORTS[i]) for i in imports
               if i in DANGEROUS_IMPORTS]
    print("\nIMPORTS: %d total, %d flagged" % (len(imports), len(flagged)))
    for name, why in flagged:
        print("  [!] %-10s %s" % (name, why))

    surfaces = {ch for ch, names in SURFACE_IMPORTS.items()
                if names & set(imports)}
    if surfaces:
        print("\nATTACK SURFACE (from imports): %s"
              % ", ".join(sorted(surfaces)))

    # strings
    hits = hunt_strings(path, base, evdir, max_strings)
    if hits:
        print("\nSTRING HITS (offset:hex  string)")
        for cat in sorted(hits):
            print("  [%s]" % cat)
            for off, s in hits[cat]:
                print("    %-10s %s" % (off, s))

    if "format-%n" in hits or any(n in dict(flagged)
                                  for n in ("printf", "syslog")):
        print("\n  [*] format-string indicators present -- xref the format "
              "strings in radare2/ghidra")

    # rupu lines
    if digest:
        pie_s = prot["pie"]
        print("\n[rupu] assets.mark kind=binary:file "
              "coords=[{t: file, v: %s}] depth=triaged "
              "note=\"%s: %s %s pie=%s stripped=%s; dangerous: %s; surface: %s\""
              % (digest, base, info["format"], info["arch"], pie_s,
                 info["stripped"],
                 ",".join(n for n, _ in flagged) or "none",
                 ",".join(sorted(surfaces)) or "unknown"))

    unit = None
    if digest:
        unit = {
            "id": "%s-%s" % (slug(base), digest[:8]),
            "title": "Triage follow-up: %s (%s %s %s-bit)"
                     % (base, info["format"], info["arch"], info["bits"]),
            "targets": [{
                "file": os.path.abspath(path),
                "sha256": digest,
                "format": info["format"],
                "arch": info["arch"],
                "bits": info["bits"],
                "pie": True if prot["pie"] in ("yes", "dso", True)
                       else False if prot["pie"] == "no" else None,
                "stripped": info["stripped"],
                "dangerous_imports": [n for n, _ in flagged],
            }],
            "hints": list(HINTS),
        }
    return unit


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binaries", nargs="+", help="binaries to triage")
    ap.add_argument("-o", "--output", default="work-units.json",
                    help="rupu work-units JSON array (default: %(default)s)")
    ap.add_argument("--evidence-dir", default=None,
                    help="save raw tool output under this directory")
    ap.add_argument("--max-strings", type=int, default=10,
                    help="max string hits shown per category")
    args = ap.parse_args()

    units = []
    for path in args.binaries:
        if not os.path.isfile(path):
            print("[!] not a file, skipping: %s" % path, file=sys.stderr)
            continue
        unit = triage_one(path, args.evidence_dir, args.max_strings)
        if unit:
            units.append(unit)

    if MISSING_TOOLS:
        print("\n[!] missing tools (degraded output): %s"
              % ", ".join(sorted(MISSING_TOOLS)), file=sys.stderr)

    with open(args.output, "w") as f:
        json.dump(units, f, indent=2)
        f.write("\n")
    print("\n[+] wrote %d work unit(s) to %s" % (len(units), args.output))
    print("    next: binary-protections, ghidra-headless, radare2 "
          "(see hints[] per unit)")


if __name__ == "__main__":
    main()
