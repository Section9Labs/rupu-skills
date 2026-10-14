#!/usr/bin/env python3
"""Run Brakeman against a Rails app, write JSON + SARIF reports, and convert
them into rupu work units via brakeman_to_workunits.py.

Usage:
    python3 scripts/run_brakeman.py -p /src/example-app -o out/
    python3 scripts/run_brakeman.py -p . -o out/ --min-confidence medium \
        --extra-args --interprocedural --extra-args --branch-limit=10

Defaults: -A (all checks), -w1 (include Weak), -q, --no-pager,
--no-exit-on-warn --no-exit-on-error. Stdlib only.
-- vulture (lavender-glen)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys


def find_brakeman(explicit):
    if explicit:
        return explicit
    for cand in ("brakeman",):
        path = shutil.which(cand)
        if path:
            return path
    # common gem bin fallbacks
    for path in ("/usr/local/bin/brakeman", os.path.expanduser("~/.local/share/gem/bin/brakeman")):
        if os.path.exists(path):
            return path
    sys.stderr.write("[run_brakeman] brakeman not found; install with: "
                     "gem install brakeman\n")
    sys.exit(2)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-p", "--app-path", default=".",
                    help="Rails application root (default: .)")
    ap.add_argument("-o", "--outdir", default="out",
                    help="output directory for reports + workunits")
    ap.add_argument("--brakeman-bin", default=None,
                    help="path to the brakeman executable")
    ap.add_argument("--min-confidence", default="weak",
                    choices=["weak", "medium", "high"],
                    help="work-unit confidence floor (scan always uses -w1)")
    ap.add_argument("--no-all-checks", action="store_true",
                    help="do not pass -A/--run-all-checks")
    ap.add_argument("--engine", action="append", default=[],
                    help="Rails engine path to include (--add-engine-path); "
                         "repeatable")
    ap.add_argument("--extra-args", action="append", default=[],
                    help="extra raw argument passed to brakeman; repeatable, "
                         "use --extra-args=--interprocedural form")
    args = ap.parse_args(argv)

    brakeman = find_brakeman(args.brakeman_bin)
    os.makedirs(args.outdir, exist_ok=True)
    json_out = os.path.join(args.outdir, "brakeman.json")
    sarif_out = os.path.join(args.outdir, "brakeman.sarif")
    wu_out = os.path.join(args.outdir, "workunits.json")

    cmd = [brakeman, "-p", args.app_path,
           "-q", "--no-pager", "-w1",
           "--no-exit-on-warn", "--no-exit-on-error",
           "-o", json_out, "-o", sarif_out]
    if not args.no_all_checks:
        cmd.insert(1, "-A")
    for eng in args.engine:
        cmd += ["--add-engine-path", eng]
    cmd += args.extra_args

    sys.stderr.write("[run_brakeman] %s\n" % " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        sys.stderr.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    # With --no-exit-on-warn/--no-exit-on-error, nonzero means a hard failure.
    if proc.returncode != 0 and not os.path.exists(json_out):
        sys.stderr.write("[run_brakeman] brakeman failed (exit %d) and wrote "
                         "no JSON report\n" % proc.returncode)
        return proc.returncode or 1

    # Print scan summary from the native JSON.
    try:
        with open(json_out, "r", encoding="utf-8") as fh:
            report = json.load(fh)
        info = report.get("scan_info", {})
        sys.stderr.write(
            "[run_brakeman] brakeman %s | rails %s | security warnings: %d | "
            "errors: %d | controllers: %s templates: %s models: %s\n" % (
                info.get("brakeman_version", "?"),
                info.get("rails_version", "?"),
                len(report.get("warnings", [])),
                len(report.get("errors", [])),
                info.get("number_of_controllers", "?"),
                info.get("number_of_templates", "?"),
                info.get("number_of_models", "?")))
        for err in report.get("errors", []):
            sys.stderr.write("[run_brakeman] scan error: %s\n"
                             % err.get("error", err))
    except (OSError, ValueError) as exc:
        sys.stderr.write("[run_brakeman] could not read %s: %s\n"
                         % (json_out, exc))
        return 1

    # Convert to work units with the sibling parser.
    parser = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "brakeman_to_workunits.py")
    conv = [sys.executable, parser, json_out,
            "-o", wu_out, "--min-confidence", args.min_confidence]
    if os.path.exists(sarif_out):
        conv += ["--sarif", sarif_out]
    sys.stderr.write("[run_brakeman] %s\n" % " ".join(conv))
    rc = subprocess.run(conv).returncode
    if rc != 0:
        return rc

    sys.stderr.write(
        "[run_brakeman] done.\n"
        "  reports:    %s , %s\n"
        "  work units: %s  (clean JSON array for rupu read_file + for_each)\n"
        "Next: assets.mark the repo/files/packages, load the `work-units` "
        "skill to split %s across agents, route %s to the `sarif-triage` "
        "skill, and load the `finding-report` skill to file verified "
        "issues.\n" % (json_out, sarif_out, wu_out, wu_out, sarif_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
