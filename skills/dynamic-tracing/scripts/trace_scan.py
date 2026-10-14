#!/usr/bin/env python3
"""trace_scan.py — run strace/ltrace on a target and triage the traces.

Runs:  strace -ff -tt -T -s 4096 -yy -o <outdir>/trace  ./target args
       ltrace -f -s 4096 -S -e '<dangerous set>' -o <outdir>/ltrace.out ./target args
(or attaches with -p). Parses the raw traces for:
  (a) files opened (flags, result),
  (b) network endpoints (connect/bind, decoded sockaddrs),
  (c) exec of shells/commands (execve/system/popen argv),
  (d) dangerous libcalls with argument sizes (strcpy/memcpy/sprintf/printf/...),
prints a summary, and writes <outdir>/work-units.json — a rupu-ingestible JSON array
of {id, title, targets, hints} follow-up units. Raw traces are kept as evidence.

Degrades gracefully when strace/ltrace are absent.

Usage:
  python3 scripts/trace_scan.py ./target -- arg1 arg2
  python3 scripts/trace_scan.py ./target --stdin-marker AAAA_MARKER
  python3 scripts/trace_scan.py --attach 1337 --duration 15
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

DANGEROUS_LIBCALLS = (
    "strcpy+strncpy+strcat+strncat+sprintf+vsprintf+snprintf+gets+memcpy+memmove"
    "+system+popen+execl+execlp+execv+execvp+printf+fprintf+syslog+getenv"
)
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "ash", "busybox"}
EXEC_WRAPPERS = {"system", "popen", "execl", "execlp", "execv", "execvp"}
COPY_CALLS = {"strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf",
              "snprintf", "gets", "memcpy", "memmove"}
FMT_CALLS = {"printf", "fprintf", "syslog"}
BORING_PATHS = re.compile(
    r"^(/proc/|/sys/|/usr/lib|/lib|/etc/ld\.so|/dev/null$|/usr/share/locale)")

# ------------------------------------------------------------------ regexes

RE_OPEN = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:[\d:.]+\s+)?'
    r'open(?:at)?\((?:AT_FDCWD(?:<[^>]*>)?,\s*)?"([^"]*)",\s*([A-Z_|]+)[^)]*\)'
    r'\s*=\s*(-?\d+)')
RE_CONNECT = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:[\d:.]+\s+)?'
    r'(connect|bind)\(\d+(?:<[^>]*>)?,\s*\{(.*?)\}')
RE_INET = re.compile(r'sin6?_port=htons\((\d+)\).*?'
                     r'(?:inet_addr\("([^"]+)"\)|inet_pton\([^,]+,\s*"([^"]+)")')
RE_UNIX = re.compile(r'sun_path="([^"]*)"')
RE_EXECVE = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:[\d:.]+\s+)?'
    r'execve\("([^"]*)",\s*\[(.*?)\]')
RE_READSZ = re.compile(
    r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:[\d:.]+\s+)?'
    r'(read|recv|recvfrom|recvmsg)\((\d+)(?:<([^>]*)>)?,.*?,\s*(\d+)[,)]')
RE_LTRACE = re.compile(
    r'^(?:\[pid\s+\d+\]\s+)?(?:[\d:.]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*=')


def slugify(text, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen].strip("-") or "unit"


def split_args(argstr):
    """Split a trace arg string on top-level commas (strings/brackets respected)."""
    out, depth, cur, instr = [], 0, [], False
    i = 0
    while i < len(argstr):
        c = argstr[i]
        if instr:
            cur.append(c)
            if c == "\\":
                i += 1
                if i < len(argstr):
                    cur.append(argstr[i])
            elif c == '"':
                instr = False
        elif c == '"':
            instr = True
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        out.append("".join(cur).strip())
    return out


# ------------------------------------------------------------------ runners

def run_tool(cmd, stdin_data, timeout):
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.communicate(input=stdin_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            time.sleep(1)
            proc.kill()
            proc.wait()
        return True
    except OSError as e:
        print("[!] failed to run %s: %s" % (cmd[0], e))
        return False


def attach_tool(cmd, duration):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return True
    except OSError as e:
        print("[!] failed to attach with %s: %s" % (cmd[0], e))
        return False


# ------------------------------------------------------------------ parsers

def parse_strace(paths, marker):
    files, endpoints, execs, bigreads, marker_hits = [], [], [], [], []
    for path in paths:
        try:
            lines = open(path, "r", errors="replace").read().splitlines()
        except OSError:
            continue
        for ln, line in enumerate(lines, 1):
            where = "%s:%d" % (os.path.basename(path), ln)
            if marker and marker in line:
                marker_hits.append((where, line.strip()[:300]))
            m = RE_OPEN.search(line)
            if m:
                files.append({"path": m.group(1), "flags": m.group(2),
                              "ret": int(m.group(3)), "where": where})
                continue
            m = RE_CONNECT.search(line)
            if m:
                call, sa = m.group(1), m.group(2)
                mi = RE_INET.search(sa)
                mu = RE_UNIX.search(sa)
                if mi:
                    host = mi.group(2) or mi.group(3)
                    endpoints.append({"call": call,
                                      "endpoint": "%s:%s" % (host, mi.group(1)),
                                      "where": where})
                elif mu:
                    endpoints.append({"call": call, "endpoint": "unix:" + mu.group(1),
                                      "where": where})
                continue
            m = RE_EXECVE.search(line)
            if m:
                execs.append({"call": "execve", "prog": m.group(1),
                              "argv": m.group(2)[:300], "where": where})
                continue
            m = RE_READSZ.search(line)
            if m:
                size = int(m.group(4))
                if size >= 1024:
                    bigreads.append({"call": m.group(1), "fd": m.group(2),
                                     "fdinfo": m.group(3) or "",
                                     "size": size, "where": where})
    return files, endpoints, execs, bigreads, marker_hits


def parse_ltrace(path, marker):
    calls, marker_hits = [], []
    try:
        lines = open(path, "r", errors="replace").read().splitlines()
    except OSError:
        return calls, marker_hits
    for ln, line in enumerate(lines, 1):
        where = "%s:%d" % (os.path.basename(path), ln)
        if marker and marker in line:
            marker_hits.append((where, line.strip()[:300]))
        m = RE_LTRACE.match(line)
        if not m:
            continue
        name, rawargs = m.group(1), m.group(2)
        if name not in COPY_CALLS | FMT_CALLS | EXEC_WRAPPERS and name != "getenv":
            continue
        args = split_args(rawargs)
        detail = ""
        if name in COPY_CALLS:
            # size = longest quoted string arg, or an explicit numeric length arg
            strlens = [len(a) - 2 for a in args if a.startswith('"')]
            nums = [int(a) for a in args if re.fullmatch(r"\d+", a)]
            size = max(nums or strlens or [0])
            detail = "arg size %d; args: %s" % (size, rawargs[:200])
        elif name in FMT_CALLS:
            fmt = args[0] if args else ""
            # variable (non-literal) format or %n = red flag
            if not fmt.startswith('"') or "%n" in fmt:
                detail = "NON-CONSTANT or %n format: " + rawargs[:200]
            else:
                continue
        elif name in EXEC_WRAPPERS:
            detail = "command: " + rawargs[:300]
        else:  # getenv
            detail = rawargs[:120]
        calls.append({"call": name, "detail": detail, "where": where})
    return calls, marker_hits


# ------------------------------------------------------------------ work units

def build_units(target_path, files, endpoints, execs, bigreads, libcalls, marker_hits):
    units, seen = [], set()

    def add(idbase, title, targets, hints):
        uid = slugify(idbase)
        n, base = 2, uid
        while uid in seen:
            uid = "%s-%d" % (base, n)
            n += 1
        seen.add(uid)
        units.append({"id": uid, "title": title, "targets": targets,
                      "hints": sorted(hints)})

    tf = target_path or "attached-process"

    for e in execs:
        base = os.path.basename(e["prog"])
        label = "shell exec" if base in SHELLS else "exec"
        add("exec-%s-%s" % (base, e["where"]),
            "%s of %s by %s (%s)" % (label, e["prog"], tf, e["where"]),
            [{"file": tf, "call": "execve", "detail": "%s argv=[%s] @ %s"
              % (e["prog"], e["argv"], e["where"])}],
            ["gdb-debugging", "vuln-classes"])

    for c in libcalls:
        if c["call"] in EXEC_WRAPPERS:
            hints = ["dynamic-tracing", "vuln-classes"]
        elif c["call"] in FMT_CALLS:
            hints = ["gdb-debugging", "vuln-classes"]
        else:
            hints = ["gdb-debugging", "pwntools", "vuln-classes"]
        add("dangerous-call-%s-%s" % (c["call"], c["where"]),
            "Dangerous libcall %s in %s (%s)" % (c["call"], tf, c["where"]),
            [{"file": tf, "call": c["call"], "detail": "%s @ %s"
              % (c["detail"], c["where"])}], hints)

    interesting = [f for f in files
                   if not BORING_PATHS.search(f["path"])
                   and ("O_CREAT" in f["flags"] or "O_WRONLY" in f["flags"]
                        or "O_RDWR" in f["flags"] or f["ret"] < 0
                        or f["path"].startswith("/tmp"))]
    for f in interesting[:40]:
        why = ("write-open" if ("O_WRONLY" in f["flags"] or "O_CREAT" in f["flags"]
                                or "O_RDWR" in f["flags"])
               else ("missing (hijack candidate)" if f["ret"] < 0 else "tmp path"))
        add("file-%s-%s" % (why.split()[0], f["path"]),
            "File access %s (%s) by %s" % (f["path"], why, tf),
            [{"file": tf, "call": "openat",
              "detail": "%s flags=%s ret=%d (%s) @ %s"
              % (f["path"], f["flags"], f["ret"], why, f["where"])}],
            ["dynamic-tracing", "vuln-classes"])

    for e in endpoints:
        add("net-%s-%s" % (e["call"], e["endpoint"]),
            "Network %s to %s by %s" % (e["call"], e["endpoint"], tf),
            [{"file": tf, "call": e["call"], "endpoint": e["endpoint"],
              "detail": "@ " + e["where"]}],
            ["dynamic-tracing", "vuln-classes"])

    for r in bigreads[:20]:
        add("input-size-%s-%s" % (r["call"], r["where"]),
            "%s of up to %d bytes (fd %s %s) in %s — overflow length source?"
            % (r["call"], r["size"], r["fd"], r["fdinfo"], tf),
            [{"file": tf, "call": r["call"],
              "detail": "size arg %d, fd %s<%s> @ %s"
              % (r["size"], r["fd"], r["fdinfo"], r["where"])}],
            ["gdb-debugging", "vuln-classes"])

    for where, line in marker_hits[:40]:
        add("marker-hit-%s" % where,
            "Marker surfaced in trace at %s" % where,
            [{"file": tf, "call": "taint", "detail": line}],
            ["gdb-debugging", "vuln-classes"])
    return units


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(
        description="strace/ltrace triage scanner",
        usage="trace_scan.py [options] [./target [-- args...]]")
    ap.add_argument("target", nargs="?", help="binary to launch and trace")
    ap.add_argument("args", nargs="*", help="target arguments (use -- before them)")
    ap.add_argument("--attach", type=int, metavar="PID",
                    help="attach to a running PID instead of launching")
    ap.add_argument("--duration", type=int, default=20,
                    help="seconds to trace (timeout for launch, window for attach)")
    ap.add_argument("--stdin-marker", default=None,
                    help="string fed on stdin and tracked through the traces")
    ap.add_argument("--outdir", default=None,
                    help="evidence dir (default: trace-evidence-<ts>)")
    opts = ap.parse_args()

    if not opts.target and not opts.attach:
        ap.error("give a target binary or --attach PID")

    strace = shutil.which("strace")
    ltrace = shutil.which("ltrace")
    if not strace and not ltrace:
        print("[!] neither strace nor ltrace found on PATH.")
        print("    Install them (e.g. `apt install strace ltrace`) and re-run.")
        return 1
    if not strace:
        print("[!] strace missing — syscall view skipped (ltrace -S partially covers it).")
    if not ltrace:
        print("[!] ltrace missing — libcall view skipped.")

    outdir = opts.outdir or ("trace-evidence-%d" % int(time.time()))
    os.makedirs(outdir, exist_ok=True)
    stdin_data = (opts.stdin_marker + "\n").encode() if opts.stdin_marker else b""
    target_path = os.path.abspath(opts.target) if opts.target else None

    strace_files = []
    if strace:
        prefix = os.path.join(outdir, "trace")
        if opts.attach:
            cmd = [strace, "-f", "-tt", "-T", "-s", "4096", "-yy",
                   "-o", prefix + ".attach", "-p", str(opts.attach)]
            print("[*] strace: attaching to pid %d for %ds" % (opts.attach, opts.duration))
            attach_tool(cmd, opts.duration)
        else:
            cmd = [strace, "-ff", "-tt", "-T", "-s", "4096", "-yy",
                   "-o", prefix, "--", target_path] + opts.args
            print("[*] strace: %s" % " ".join(cmd))
            run_tool(cmd, stdin_data, opts.duration)
        strace_files = sorted(
            os.path.join(outdir, f) for f in os.listdir(outdir)
            if f.startswith("trace"))

    ltrace_out = os.path.join(outdir, "ltrace.out")
    ran_ltrace = False
    if ltrace:
        if opts.attach:
            cmd = [ltrace, "-f", "-s", "4096", "-S", "-e", DANGEROUS_LIBCALLS,
                   "-o", ltrace_out, "-p", str(opts.attach)]
            print("[*] ltrace: attaching to pid %d for %ds" % (opts.attach, opts.duration))
            ran_ltrace = attach_tool(cmd, opts.duration)
        else:
            cmd = [ltrace, "-f", "-s", "4096", "-S", "-e", DANGEROUS_LIBCALLS,
                   "-o", ltrace_out, "--", target_path] + opts.args
            print("[*] ltrace: %s" % " ".join(cmd))
            ran_ltrace = run_tool(cmd, stdin_data, opts.duration)

    files, endpoints, execs, bigreads, mh1 = parse_strace(strace_files,
                                                          opts.stdin_marker)
    libcalls, mh2 = ([], [])
    if ran_ltrace:
        libcalls, mh2 = parse_ltrace(ltrace_out, opts.stdin_marker)
    marker_hits = mh1 + mh2

    print("\n===== SUMMARY =====")
    print("files opened      : %d (%d interesting shown in work units)"
          % (len(files), len([f for f in files if not BORING_PATHS.search(f['path'])])))
    for f in files[:15]:
        if not BORING_PATHS.search(f["path"]):
            print("    %-50s flags=%s ret=%d" % (f["path"], f["flags"], f["ret"]))
    print("network endpoints : %d" % len(endpoints))
    for e in endpoints:
        print("    %s -> %s (%s)" % (e["call"], e["endpoint"], e["where"]))
    print("execs             : %d" % len(execs))
    for e in execs:
        print("    execve %s [%s] (%s)" % (e["prog"], e["argv"][:120], e["where"]))
    print("large reads/recvs : %d (>=1024 bytes)" % len(bigreads))
    for r in bigreads[:10]:
        print("    %s size=%d fd=%s<%s> (%s)"
              % (r["call"], r["size"], r["fd"], r["fdinfo"], r["where"]))
    print("dangerous libcalls: %d" % len(libcalls))
    for c in libcalls[:20]:
        print("    %-10s %s (%s)" % (c["call"], c["detail"][:120], c["where"]))
    if opts.stdin_marker:
        print("marker hits       : %d" % len(marker_hits))
        for where, line in marker_hits[:10]:
            print("    %s: %s" % (where, line[:140]))

    units = build_units(target_path, files, endpoints, execs, bigreads,
                        libcalls, marker_hits)
    wu_path = os.path.join(outdir, "work-units.json")
    with open(wu_path, "w") as f:
        json.dump(units, f, indent=2)
    print("\n[+] %d work units -> %s (rupu for_each ingestible)" % (len(units), wu_path))
    print("[+] raw evidence kept under %s/ — do not delete" % outdir)
    print("[*] next: assets.mark the binary (triaged/analyzed) and each sink as")
    print("    binary:symbol; verified marker-in-sink issues -> findings.report")
    print("    (see references/rupu.md); fan out units to `gdb-debugging`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
