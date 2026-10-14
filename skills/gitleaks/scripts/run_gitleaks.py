#!/usr/bin/env python3
"""Run gitleaks (git/dir/stdin mode) with JSON + SARIF reports, then convert
the results into a clean JSON array of work units via gitleaks_to_workunits.py.

Usage:
    python3 scripts/run_gitleaks.py --mode git /tmp/app.git --out-dir out/
    python3 scripts/run_gitleaks.py --mode git /tmp/app.git --log-opts "--all" --out-dir out/
    python3 scripts/run_gitleaks.py --mode dir /srv/extracted --out-dir out/ --max-mb 50
    python3 scripts/run_gitleaks.py --mode git . --config custom.toml --redact

Exit codes: 0 = clean, 1 = leaks found (work units written), >=2 = error.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARSER = os.path.join(HERE, "gitleaks_to_workunits.py")


def run(cmd):
    print("+ " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    sys.stderr.buffer.write(proc.stdout)
    sys.stderr.flush()
    return proc.returncode


def gitleaks_cmd(binary, mode, target, report_fmt, report_path, args):
    cmd = [binary, mode, target,
           "--report-format", report_fmt,
           "--report-path", report_path,
           "--no-banner"]
    if args.verbose:
        cmd.append("-v")
    if args.redact:
        cmd.append("--redact")
    if args.config:
        cmd += ["--config", args.config]
    if args.baseline:
        cmd += ["--baseline-path", args.baseline]
    if args.max_mb:
        cmd += ["--max-target-megabytes", str(args.max_mb)]
    if args.decode_depth:
        cmd += ["--max-decode-depth", str(args.decode_depth)]
    if mode == "git" and args.log_opts:
        cmd += ["--log-opts", args.log_opts]
    return cmd


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="repo path (git mode) or directory (dir mode)")
    ap.add_argument("--mode", choices=["git", "dir"], default="git")
    ap.add_argument("--out-dir", default="gitleaks-out", help="output directory")
    ap.add_argument("--gitleaks-bin", default="gitleaks", help="path to gitleaks binary")
    ap.add_argument("--log-opts", default="", help='git log options, e.g. "--all" or "origin/main..HEAD"')
    ap.add_argument("--config", default="", help="custom .gitleaks.toml")
    ap.add_argument("--baseline", default="", help="baseline JSON report to suppress known findings")
    ap.add_argument("--max-mb", type=int, default=0, help="--max-target-megabytes")
    ap.add_argument("--decode-depth", type=int, default=0, help="--max-decode-depth")
    ap.add_argument("--redact", action="store_true", help="redact secrets in gitleaks reports")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if shutil.which(args.gitleaks_bin) is None and not os.path.exists(args.gitleaks_bin):
        print("error: gitleaks binary not found: %s" % args.gitleaks_bin, file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    json_report = os.path.join(args.out_dir, "gitleaks.json")
    sarif_report = os.path.join(args.out_dir, "gitleaks.sarif")
    workunits = os.path.join(args.out_dir, "workunits.json")

    rc_json = run(gitleaks_cmd(args.gitleaks_bin, args.mode, args.target,
                               "json", json_report, args))
    rc_sarif = run(gitleaks_cmd(args.gitleaks_bin, args.mode, args.target,
                                "sarif", sarif_report, args))
    for rc in (rc_json, rc_sarif):
        if rc not in (0, 1):
            print("error: gitleaks exited %d" % rc, file=sys.stderr)
            return rc

    reports = [p for p in (json_report, sarif_report)
               if os.path.exists(p) and os.path.getsize(p) > 0]
    if not reports:
        with open(workunits, "w", encoding="utf-8") as fh:
            fh.write("[]\n")
        print("no findings; wrote empty array to %s" % workunits, file=sys.stderr)
        return 0

    rc = subprocess.run([sys.executable, PARSER] + reports + ["-o", workunits]).returncode
    if rc != 0:
        return rc

    with open(workunits, "r", encoding="utf-8") as fh:
        count = len(json.load(fh))
    print("gitleaks: %d work units -> %s" % (count, workunits), file=sys.stderr)
    print(workunits)  # stdout: path for the next workflow step
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
