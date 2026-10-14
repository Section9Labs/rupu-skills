#!/usr/bin/env python3
"""ghidra_headless.py — drive Ghidra's analyzeHeadless over a binary or a tree,
run the shipped ExportAnalysis postScript, collect the JSON exports, and emit
rupu work units for candidate dangerous sinks.

Usage:
  python3 scripts/ghidra_headless.py ./target_bin --out ./gh_out
  python3 scripts/ghidra_headless.py ./squashfs-root --recursive --timeout 300
  python3 scripts/ghidra_headless.py ./fw.bin --loader BinaryLoader \\
      --processor ARM:LE:32:v7 --base 0x8000
  python3 scripts/ghidra_headless.py --project-dir ./proj --process target_bin
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra")
POST_SCRIPT = "ExportAnalysis.java"

GHIDRA_HINTS = """\
[!] analyzeHeadless not found.
    Looked in: PATH, $GHIDRA_INSTALL_DIR/support, /opt/ghidra*/support,
    /usr/share/ghidra/support, /usr/local/ghidra*/support, ~/ghidra*/support.

    Install: download a release from https://github.com/NationalSecurityAgency/ghidra/releases
    unzip it, install a JDK 17+, then either:
      export GHIDRA_INSTALL_DIR=/opt/ghidra_11.x_PUBLIC
    or pass --analyze-headless /path/to/support/analyzeHeadless
"""


def find_analyze_headless(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for name in ("analyzeHeadless", "analyzeHeadless.bat"):
        p = shutil.which(name)
        if p:
            return p
    cands = []
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        cands.append(os.path.join(env, "support", "analyzeHeadless"))
    for pat in ("/opt/ghidra*/support/analyzeHeadless",
                "/usr/share/ghidra/support/analyzeHeadless",
                "/usr/local/ghidra*/support/analyzeHeadless",
                os.path.expanduser("~/ghidra*/support/analyzeHeadless"),
                "/Applications/ghidra*/support/analyzeHeadless"):
        cands.extend(sorted(glob.glob(pat), reverse=True))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "x"


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


SINK_REASONS = {
    "system": "command execution — any attacker-influenced argument is command injection",
    "popen": "command execution via shell",
    "gets": "unbounded read into buffer — overflow by construction",
    "strcpy": "unbounded copy — overflow if source is attacker-controlled",
    "strcat": "unbounded append — overflow",
    "sprintf": "unbounded formatted write — overflow / format string",
    "vsprintf": "unbounded formatted write",
    "scanf": "%s without width — overflow",
    "sscanf": "%s without width — overflow",
    "memcpy": "check length argument provenance — size confusion / overflow",
    "memmove": "check length argument provenance",
    "strncpy": "check size arg + missing NUL termination",
    "read": "check count vs destination size",
    "recv": "network input — check count vs destination size",
    "recvfrom": "network input — check count vs destination size",
    "printf": "non-constant format string — format string bug",
    "fprintf": "non-constant format string — format string bug",
    "syslog": "non-constant format string",
    "dlopen": "attacker-influenced library path — code load",
    "execve": "argument/path provenance — command execution",
}


def build_work_units(out_dir):
    """Group sink xrefs per (program, sink) into rupu work units."""
    units = []
    for meta_path in sorted(glob.glob(os.path.join(out_dir, "*", "meta.json"))):
        prog_dir = os.path.dirname(meta_path)
        meta = load_json(meta_path, {})
        binfile = meta.get("exec_path") or meta.get("program") or os.path.basename(prog_dir)
        xrefs = load_json(os.path.join(prog_dir, "xrefs.json"), [])
        by_sink = {}
        for x in xrefs:
            if not x.get("is_call"):
                continue
            by_sink.setdefault(x["sink"], []).append(x)
        for sink, calls in sorted(by_sink.items()):
            reason = SINK_REASONS.get(sink, "dangerous API — review argument provenance")
            targets = [{
                "file": binfile,
                "function": c.get("function") or "(no containing function)",
                "vaddr": c.get("from", ""),
                "reason": reason,
            } for c in calls]
            units.append({
                "id": "ghidra-sink-%s-%s" % (slug(os.path.basename(binfile)), slug(sink)),
                "title": "%s: %d call site(s) of %s — trace argument provenance"
                         % (os.path.basename(binfile), len(calls), sink),
                "targets": targets,
                "hints": ["gdb-debugging", "vuln-classes"],
            })
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="binary file or directory to import")
    ap.add_argument("--out", default="./gh_out", help="output dir (default ./gh_out)")
    ap.add_argument("--project-dir", default=None,
                    help="Ghidra project dir (default: temp dir, deleted project)")
    ap.add_argument("--project-name", default="headless")
    ap.add_argument("--process", default=None,
                    help="re-run script on an already-imported program (name/glob) "
                         "instead of -import; requires --project-dir")
    ap.add_argument("--recursive", action="store_true", help="recurse into a directory")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--timeout", type=int, default=600,
                    help="-analysisTimeoutPerFile seconds (default 600)")
    ap.add_argument("--loader", default=None, help="e.g. BinaryLoader for raw blobs")
    ap.add_argument("--processor", default=None, help="language ID, e.g. ARM:LE:32:v7")
    ap.add_argument("--cspec", default=None, help="compiler spec, e.g. default")
    ap.add_argument("--base", default=None, help="loader base address for BinaryLoader, e.g. 0x8000")
    ap.add_argument("--sinks", default="", help="extra sink names, comma-separated")
    ap.add_argument("--jython", action="store_true",
                    help="use the Jython postScript instead of the Java one")
    ap.add_argument("--analyze-headless", default=None, help="explicit path to analyzeHeadless")
    args = ap.parse_args()

    if not args.target and not args.process:
        ap.error("give a target to -import, or --process with --project-dir")

    ah = find_analyze_headless(args.analyze_headless)
    if not ah:
        sys.stderr.write(GHIDRA_HINTS)
        return 1

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    tmp_proj = None
    proj_dir = args.project_dir
    delete_project = proj_dir is None
    if proj_dir is None:
        tmp_proj = tempfile.mkdtemp(prefix="ghproj_")
        proj_dir = tmp_proj

    post = "export_analysis.py" if args.jython else POST_SCRIPT
    cmd = [ah, proj_dir, args.project_name]
    if args.process:
        cmd += ["-process", args.process]
    else:
        cmd += ["-import", os.path.abspath(args.target)]
        if args.recursive or (args.target and os.path.isdir(args.target)):
            cmd += ["-recursive"]
        if args.overwrite:
            cmd += ["-overwrite"]
    cmd += ["-scriptPath", SCRIPT_DIR,
            "-postScript", post, out_dir, args.sinks,
            "-analysisTimeoutPerFile", str(args.timeout)]
    if args.loader:
        cmd += ["-loader", args.loader]
        if args.base:
            cmd += ["-loader-baseAddr", args.base]
    if args.processor:
        cmd += ["-processor", args.processor]
    if args.cspec:
        cmd += ["-cspec", args.cspec]
    if delete_project and not args.process:
        cmd += ["-deleteProject"]

    print("[*] exec: %s" % " ".join(cmd))
    log_path = os.path.join(out_dir, "analyzeHeadless.log")
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    errors="replace")
            for line in proc.stdout:
                log.write(line)
                if any(k in line for k in ("ERROR", "ExportAnalysis", "export_analysis",
                                           "ANALYZING", "Import succeeded", "REPORT")):
                    print("    " + line.rstrip())
            rc = proc.wait()
    except OSError as e:
        sys.stderr.write("[!] failed to run analyzeHeadless: %s\n" % e)
        return 1
    finally:
        if tmp_proj:
            shutil.rmtree(tmp_proj, ignore_errors=True)
    if rc != 0:
        print("[!] analyzeHeadless exited %d — see %s" % (rc, log_path))

    # ---- collect + summarize --------------------------------------------
    units = build_work_units(out_dir)
    wu_path = os.path.join(out_dir, "work_units.json")
    with open(wu_path, "w", encoding="utf-8") as f:
        json.dump(units, f, indent=2)

    progs = sorted(glob.glob(os.path.join(out_dir, "*", "functions.json")))
    print("\n=== ghidra-headless export summary ===")
    for fp in progs:
        d = os.path.dirname(fp)
        nfun = len(load_json(fp, []))
        nxr = sum(1 for x in load_json(os.path.join(d, "xrefs.json"), []) if x.get("is_call"))
        nstr = len(load_json(os.path.join(d, "strings.json"), []))
        print("  %-30s %5d funcs  %4d sink calls  %5d strings"
              % (os.path.basename(d), nfun, nxr, nstr))
    print("\n[*] %d work unit(s) -> %s" % (len(units), wu_path))
    for u in units:
        print("  - %-45s %d target(s)" % (u["id"], len(u["targets"])))
    print("[*] evidence under %s (keep it); log: %s" % (out_dir, log_path))
    print("[*] next: rupu for_each over work_units.json; "
          "see references/rupu.md for assets.mark / findings.report wiring")
    return 0


if __name__ == "__main__":
    sys.exit(main())
