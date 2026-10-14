#!/usr/bin/env python3
"""Run Retire.js over a path with JSON output and emit rupu work units.

Usage:
    python3 scripts/run_retirejs.py /work/example.com-webapp \
        --out retire.json --workunits workunits.json
    python3 scripts/run_retirejs.py dist/ --severity medium -- --deep --verbose

Everything after `--` is passed through to the retire CLI verbatim.
"""
import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import retirejs_to_workunits  # noqa: E402


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough = []
    if "--" in argv:
        idx = argv.index("--")
        passthrough = argv[idx + 1:]
        argv = argv[:idx]

    ap = argparse.ArgumentParser(
        description="Run retire --outputformat json and normalize to work units.")
    ap.add_argument("path", help="directory to scan (source tree and/or built dist/)")
    ap.add_argument("--out", default="retire.json",
                    help="raw Retire.js JSON report path (default retire.json)")
    ap.add_argument("--workunits", default="workunits.json",
                    help="normalized work-unit array path (default workunits.json)")
    ap.add_argument("--severity", default=None,
                    choices=["low", "medium", "high", "critical"],
                    help="retire --severity gate (also used as work-unit filter)")
    ap.add_argument("--ignorefile", default=None,
                    help="path to .retireignore.json")
    ap.add_argument("--retire-bin", default="retire",
                    help="retire executable (default: retire on PATH)")
    ap.add_argument("--exitwith", default="13",
                    help="exit code retire uses when vulns found (default 13)")
    args = ap.parse_args(argv)

    if shutil.which(args.retire_bin) is None:
        print("error: '%s' not found on PATH (npm install -g retire)"
              % args.retire_bin, file=sys.stderr)
        return 2

    cmd = [args.retire_bin,
           "--path", args.path,
           "--outputformat", "json",
           "--outputpath", args.out,
           "--exitwith", args.exitwith]
    if args.severity:
        cmd += ["--severity", args.severity]
    if args.ignorefile:
        cmd += ["--ignorefile", args.ignorefile]
    cmd += passthrough

    print("+ " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)

    try:
        vuln_exit = int(args.exitwith)
    except ValueError:
        vuln_exit = 13

    if proc.returncode not in (0, vuln_exit):
        print("retire failed (exit %d):" % proc.returncode, file=sys.stderr)
        sys.stderr.write(proc.stderr or proc.stdout or "")
        return proc.returncode

    if not os.path.exists(args.out):
        print("error: retire produced no report at %s" % args.out,
              file=sys.stderr)
        return 2

    parser_args = [args.out, "-o", args.workunits]
    if args.severity:
        parser_args += ["--min-severity", args.severity]
    rc = retirejs_to_workunits.main(parser_args)
    if rc != 0:
        return rc

    if proc.returncode == vuln_exit:
        print("retire exit %d: vulnerable libraries detected "
              "(see %s / %s)" % (proc.returncode, args.out, args.workunits))
    else:
        print("retire exit 0: no findings at/above gate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
