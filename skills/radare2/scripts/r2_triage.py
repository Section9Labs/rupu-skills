#!/usr/bin/env python3
"""r2_triage.py — radare2/rizin binary triage via r2pipe (or a built-in stdlib
pipe fallback). Runs aaa, pulls functions/imports/strings/protections, finds
call sites of dangerous sinks via axtj, prints a summary, and emits rupu work
units.

Usage:
  python3 scripts/r2_triage.py ./target --out ./r2_out
  python3 scripts/r2_triage.py ./target --sinks "system,custom_eval" --deep
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

DEFAULT_SINKS = [
    "system", "popen", "execve", "execl", "execle", "execlp", "execv", "execvp",
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "memcpy", "memmove", "strncpy", "strncat",
    "read", "recv", "recvfrom", "fread",
    "printf", "fprintf", "syslog", "dlopen",
]

NO_TOOL_MSG = """\
[!] Neither the r2pipe Python module nor a radare2/rizin binary was found.
    Fix one of:
      pip install r2pipe          (works with radare2)
      pip install rzpipe          (works with rizin; this script will use it too)
      apt install radare2  /  install rizin  /  build from git:
        git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
    This script needs an `r2` (or `radare2`/`rizin`/`rz`) binary on PATH even
    for the stdlib fallback.
"""


class PipeFallback:
    """Minimal r2pipe clone over `r2 -q0` (stdlib only). rizin speaks the same
    protocol: commands in on stdin, NUL-terminated output on stdout."""

    def __init__(self, binpath, target):
        self.p = subprocess.Popen(
            [binpath, "-q0", "-2", "-e", "scr.color=0", "-e", "scr.interactive=false", target],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self._read_until_nul()  # initial \x00 banner

    def _read_until_nul(self):
        buf = bytearray()
        while True:
            b = self.p.stdout.read(1)
            if not b or b == b"\x00":
                return bytes(buf)
            buf += b

    def cmd(self, c):
        self.p.stdin.write(c.encode() + b"\n")
        self.p.stdin.flush()
        return self._read_until_nul().decode("utf-8", "replace")

    def cmdj(self, c):
        out = self.cmd(c).strip()
        try:
            return json.loads(out) if out else None
        except ValueError:
            return None

    def quit(self):
        try:
            self.p.stdin.write(b"q!\n")
            self.p.stdin.flush()
        except OSError:
            pass
        self.p.terminate()


def open_r2(target):
    try:
        import r2pipe  # type: ignore
        r2 = r2pipe.open(target, flags=["-2"])
        return r2, "r2pipe"
    except ImportError:
        pass
    try:
        import rzpipe  # type: ignore
        r2 = rzpipe.open(target, flags=["-2"])
        return r2, "rzpipe"
    except ImportError:
        pass
    for name in ("r2", "radare2", "rizin", "rz"):
        binpath = shutil.which(name)
        if binpath:
            return PipeFallback(binpath, target), "stdlib pipe (%s)" % name
    return None, None


def cmdj(r2, c):
    try:
        v = r2.cmdj(c)
        return v if v is not None else []
    except Exception:
        return []


def slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "x"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="binary to triage")
    ap.add_argument("--out", default="./r2_out", help="output/evidence dir (default ./r2_out)")
    ap.add_argument("--sinks", default="", help="extra sink names, comma-separated")
    ap.add_argument("--deep", action="store_true", help="use aaaa instead of aaa")
    args = ap.parse_args()

    if not os.path.isfile(args.target):
        sys.stderr.write("[!] no such file: %s\n" % args.target)
        return 1

    r2, mode = open_r2(args.target)
    if r2 is None:
        sys.stderr.write(NO_TOOL_MSG)
        return 1
    print("[*] backend: %s" % mode)

    sinks = DEFAULT_SINKS + [s.strip() for s in args.sinks.split(",") if s.strip()]
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    target_path = os.path.abspath(args.target)
    target_name = os.path.basename(target_path)

    print("[*] analyzing (%s)..." % ("aaaa" if args.deep else "aaa"))
    r2.cmd("aaaa" if args.deep else "aaa")

    info = cmdj(r2, "iIj") or {}
    funcs = cmdj(r2, "aflj")
    imports = cmdj(r2, "iij")
    strings = cmdj(r2, "izzj")

    # ---- sink xrefs ------------------------------------------------------
    import_names = {i.get("name", "") for i in imports}
    func_by_name = {f.get("name", ""): f for f in funcs}
    sink_hits = []
    for sink in sinks:
        # Try every spelling r2 may have flagged this symbol under.
        candidates = ["sym.imp.%s" % sink, "sym.imp._%s" % sink,
                      "sym.%s" % sink, "fcn.%s" % sink]
        candidates = [c for c in candidates if c in func_by_name] or (
            ["sym.imp.%s" % sink] if sink in import_names else [])
        for sym in candidates:
            for x in cmdj(r2, "axtj @ %s" % sym):
                sink_hits.append({
                    "sink": sink,
                    "symbol": sym,
                    "vaddr": "0x%x" % x.get("from", 0),
                    "caller": x.get("fcn_name") or x.get("refname") or "(unknown)",
                    "type": x.get("type", ""),
                })

    # ---- evidence --------------------------------------------------------
    for name, obj in (("info", info), ("functions", funcs), ("imports", imports),
                      ("strings", strings), ("sink_xrefs", sink_hits)):
        with open(os.path.join(out_dir, name + ".json"), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)

    # ---- summary ---------------------------------------------------------
    print("\n=== r2 triage: %s ===" % target_name)
    print("  arch=%s bits=%s  canary=%s nx=%s pic/pie=%s relro=%s stripped=%s static=%s"
          % (info.get("arch"), info.get("bits"), info.get("canary"), info.get("nx"),
             info.get("pic"), info.get("relro"), info.get("stripped"), info.get("static")))
    print("  %d functions, %d imports, %d strings" % (len(funcs), len(imports), len(strings)))
    present = sorted({h["sink"] for h in sink_hits})
    print("  dangerous sinks with call sites: %s" % (", ".join(present) or "none found"))
    for h in sink_hits:
        print("    %-12s <- %-10s in %s (%s)" % (h["sink"], h["vaddr"], h["caller"], h["type"]))

    # ---- rupu work units -------------------------------------------------
    by_sink = {}
    for h in sink_hits:
        if h["type"].upper() not in ("CALL", "CODE", ""):  # keep calls + code refs
            continue
        by_sink.setdefault(h["sink"], []).append(h)
    units = []
    for sink, hits in sorted(by_sink.items()):
        units.append({
            "id": "r2-sink-%s-%s" % (slug(target_name), slug(sink)),
            "title": "%s: %d call site(s) of %s — trace argument provenance"
                     % (target_name, len(hits), sink),
            "targets": [{"file": target_path, "function": sink,
                         "vaddr": h["vaddr"], "caller": h["caller"]} for h in hits],
            "hints": ["gdb-debugging", "ghidra-headless", "vuln-classes"],
        })
    wu_path = os.path.join(out_dir, "work_units.json")
    with open(wu_path, "w", encoding="utf-8") as f:
        json.dump(units, f, indent=2)

    try:
        digest = sha256(target_path)
    except OSError:
        digest = ""
    print("\n[*] sha256: %s" % digest)
    print("[*] %d work unit(s) -> %s" % (len(units), wu_path))
    print("[*] raw evidence under %s (keep it)" % out_dir)
    print("[*] next: rupu for_each over work_units.json; "
          "see references/rupu.md for assets.mark / findings.report wiring")

    try:
        r2.quit()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
