#!/usr/bin/env python3
"""run_findsecbugs.py - run SpotBugs + findsecbugs and emit rupu work units.

Runs SpotBugs with the Find Security Bugs plugin twice over the target
(once for SARIF, once for native XML, since the text UI writes one report
per run), then invokes fsb_to_workunits.py to produce a clean JSON array of
work units.

Usage:
    python3 scripts/run_findsecbugs.py \
        --plugin /opt/findsecbugs-plugin.jar \
        --aux target/deps --source src/main/java \
        --out-dir fsb-out target/classes [more.jar app.war ...]

Outputs: <out-dir>/fsb.sarif, <out-dir>/fsb.xml, <out-dir>/workunits.json
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARSER = os.path.join(HERE, "fsb_to_workunits.py")
PATHSEP = os.pathsep  # ':' on POSIX, ';' on Windows


def build_auxclasspath(entries):
    """Expand --aux entries: a dir of jars, a single jar, or a cp string."""
    parts = []
    for entry in entries:
        if PATHSEP in entry:
            parts.extend(p for p in entry.split(PATHSEP) if p)
        elif os.path.isdir(entry):
            jars = []
            for dirpath, _dirs, files in os.walk(entry):
                jars.extend(os.path.join(dirpath, f)
                            for f in files if f.endswith(".jar"))
            if jars:
                parts.extend(sorted(jars))
            else:
                parts.append(entry)  # a dir of .class files is also valid
        else:
            parts.append(entry)
    # dedup, keep order
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return PATHSEP.join(out)


def spotbugs_cmd(args, aux_cp, fmt_flag, output_path, targets):
    cmd = [args.spotbugs, "-textui"]
    if args.plugin:
        cmd += ["-pluginList", args.plugin]
    cmd += ["-effort:" + args.effort, "-" + args.threshold]
    if args.max_rank:
        cmd += ["-maxRank", str(args.max_rank)]
    if aux_cp:
        cmd += ["-auxclasspath", aux_cp]
    if args.source:
        cmd += ["-sourcepath", PATHSEP.join(args.source)]
    if args.include:
        cmd += ["-include", args.include]
    if args.exclude:
        cmd += ["-exclude", args.exclude]
    for pkg in args.only_analyze:
        cmd += ["-onlyAnalyze", pkg]
    if args.max_heap:
        cmd += ["-maxHeap", str(args.max_heap)]
    cmd += [fmt_flag, "-output", output_path]
    cmd += targets
    return cmd


def run(cmd):
    print("[fsb] $ " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    if proc.stdout.strip():
        sys.stderr.write(proc.stdout)
    if proc.stderr.strip():
        sys.stderr.write(proc.stderr)
    # SpotBugs exit code is a bitmask: 1=analysis errors, 2=missing classes,
    # 4=bugs found. "Bugs found" is success for our purposes.
    if proc.returncode & 1:
        print("[fsb] WARNING: analysis errors reported (exit %d)"
              % proc.returncode, file=sys.stderr)
    missing = re.search(
        r"The following classes needed for analysis were missing:(.*)",
        proc.stderr, re.S)
    if missing or (proc.returncode & 2):
        print("[fsb] WARNING: classes missing from auxclasspath -- taint "
              "accuracy degraded. Fix -auxclasspath and re-run. See stderr "
              "above for the class list.", file=sys.stderr)
    return proc.returncode


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("targets", nargs="+",
                    help="classes dirs / .jar / .war / .ear to analyze")
    ap.add_argument("--spotbugs", default=None,
                    help="spotbugs launcher (default: 'spotbugs' on PATH, "
                         "falls back to 'findsecbugs.sh')")
    ap.add_argument("--plugin", default=None,
                    help="findsecbugs-plugin.jar path (omit when using the "
                         "findsecbugs.sh wrapper, which preloads it)")
    ap.add_argument("--aux", action="append", default=[],
                    help="auxclasspath entry: dir of jars, jar, or cp string "
                         "(repeatable). CRITICAL for accuracy.")
    ap.add_argument("--source", action="append", default=[],
                    help="source root(s) for line mapping (repeatable)")
    ap.add_argument("--effort", default="max",
                    choices=["min", "default", "max"])
    ap.add_argument("--threshold", default="low",
                    choices=["low", "medium", "high"],
                    help="min confidence to report (default low)")
    ap.add_argument("--max-rank", type=int, default=None,
                    help="pass -maxRank N to spotbugs")
    ap.add_argument("--include", default=None, help="include filter XML")
    ap.add_argument("--exclude", default=None, help="exclude filter XML")
    ap.add_argument("--only-analyze", action="append", default=[],
                    help="restrict analysis, e.g. 'com.example.-' (repeatable)")
    ap.add_argument("--max-heap", type=int, default=None,
                    help="JVM heap MB for the analysis")
    ap.add_argument("--out-dir", default="fsb-out")
    ap.add_argument("--repo-root", default=".",
                    help="repo root for sourcepath resolution in work units")
    ap.add_argument("--min-rank", type=int, default=20,
                    help="work-unit filter: drop rank worse than N")
    args = ap.parse_args(argv)

    if args.spotbugs is None:
        for cand in ("spotbugs", "findsecbugs.sh", "spotbugs.bat"):
            if shutil.which(cand):
                args.spotbugs = cand
                break
        else:
            print("[fsb] ERROR: no spotbugs/findsecbugs.sh launcher on PATH; "
                  "pass --spotbugs", file=sys.stderr)
            return 2
    if args.plugin and not os.path.exists(args.plugin):
        print("[fsb] ERROR: plugin jar not found: %s" % args.plugin,
              file=sys.stderr)
        return 2
    for t in args.targets:
        if not os.path.exists(t):
            print("[fsb] ERROR: target not found (did you build the "
                  "project?): %s" % t, file=sys.stderr)
            return 2

    os.makedirs(args.out_dir, exist_ok=True)
    sarif_path = os.path.join(args.out_dir, "fsb.sarif")
    xml_path = os.path.join(args.out_dir, "fsb.xml")
    units_path = os.path.join(args.out_dir, "workunits.json")

    aux_cp = build_auxclasspath(args.aux)
    if not aux_cp:
        print("[fsb] WARNING: no --aux given. Missing dependency jars cause "
              "false negatives in taint analysis.", file=sys.stderr)

    rc1 = run(spotbugs_cmd(args, aux_cp, "-sarif", sarif_path, args.targets))
    rc2 = run(spotbugs_cmd(args, aux_cp, "-xml:withMessages", xml_path,
                           args.targets))

    inputs = [p for p in (sarif_path, xml_path)
              if os.path.exists(p) and os.path.getsize(p) > 0]
    if not inputs:
        print("[fsb] ERROR: no report produced (exit codes %s/%s)"
              % (rc1, rc2), file=sys.stderr)
        return 1

    parser_cmd = [sys.executable, PARSER] + inputs + [
        "-o", units_path, "--repo-root", args.repo_root,
        "--min-rank", str(args.min_rank), "--security-only"]
    print("[fsb] $ " + " ".join(parser_cmd), file=sys.stderr)
    rc = subprocess.call(parser_cmd)
    if rc != 0:
        return rc

    print("[fsb] done:", file=sys.stderr)
    for p in inputs + [units_path]:
        print("[fsb]   %s" % p, file=sys.stderr)
    print("[fsb] next: load the `work-units` skill to split %s, verify each "
          "unit, file via the `finding-report` skill, and route %s to "
          "`sarif-triage`." % (units_path, sarif_path), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
