#!/usr/bin/env python3
"""run_bandit.py — run Bandit over a path with both JSON and SARIF output,
then convert the results into a rupu-ingestible work-unit array.

Produces in the output dir:
    bandit.json       Bandit native JSON (-f json)
    bandit.sarif      SARIF 2.1.0 (-f sarif; needs `pip install bandit[sarif]`)
    workunits.json    clean top-level JSON array of work units
    scanned_files.txt one scanned file per line (from metrics; for assets.mark)

Usage:
    python3 scripts/run_bandit.py /work/example-app -o out/
    python3 scripts/run_bandit.py src/ -o out/ -x ./tests,./.venv \
        --skip B101,B311 --severity medium --confidence medium
    python3 scripts/run_bandit.py src/ -o out/ -- --baseline baseline.json
Everything after `--` is passed to bandit verbatim.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bandit_to_workunits  # noqa: E402


def run(cmd):
    print("+ " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    # bandit exits 1 when it has findings; that's success for our purposes
    if proc.returncode not in (0, 1):
        print(proc.stderr, file=sys.stderr)
    return proc


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough = []
    if "--" in argv:
        i = argv.index("--")
        argv, passthrough = argv[:i], argv[i + 1:]

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="file or directory to scan (dirs use -r)")
    ap.add_argument("-o", "--outdir", default="out",
                    help="output directory (default: %(default)s)")
    ap.add_argument("-x", "--exclude", default=None,
                    help="comma-separated paths to exclude")
    ap.add_argument("-c", "--config", default=None,
                    help="bandit config file (bandit.yaml)")
    ap.add_argument("--skip", default=None,
                    help="comma-separated test ids to skip (-s)")
    ap.add_argument("--tests", default=None,
                    help="comma-separated test ids to run (-t)")
    ap.add_argument("--severity", default=None,
                    choices=["all", "low", "medium", "high"],
                    help="--severity-level threshold")
    ap.add_argument("--confidence", default=None,
                    choices=["all", "low", "medium", "high"],
                    help="--confidence-level threshold")
    ap.add_argument("--per-finding", action="store_true",
                    help="one work unit per finding (default groups by "
                         "test_id+file)")
    ap.add_argument("--bandit", default="bandit",
                    help="bandit executable (default: %(default)s)")
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)
    json_out = os.path.join(args.outdir, "bandit.json")
    sarif_out = os.path.join(args.outdir, "bandit.sarif")
    units_out = os.path.join(args.outdir, "workunits.json")
    files_out = os.path.join(args.outdir, "scanned_files.txt")

    base = [args.bandit]
    if os.path.isdir(args.path):
        base.append("-r")
    base.append(args.path)
    if args.exclude:
        base += ["-x", args.exclude]
    if args.config:
        base += ["-c", args.config]
    if args.skip:
        base += ["-s", args.skip]
    if args.tests:
        base += ["-t", args.tests]
    if args.severity:
        base += ["--severity-level", args.severity]
    if args.confidence:
        base += ["--confidence-level", args.confidence]
    base += passthrough

    # 1) native JSON (authoritative: metrics + full result fields)
    proc = run(base + ["-f", "json", "-o", json_out])
    if not os.path.exists(json_out):
        print("fatal: bandit produced no JSON output:\n" + proc.stderr,
              file=sys.stderr)
        return 2

    # 2) SARIF for the sarif-triage skill (best-effort; needs bandit[sarif])
    inputs = [json_out]
    sproc = run(base + ["-f", "sarif", "-o", sarif_out])
    if os.path.exists(sarif_out):
        inputs.append(sarif_out)
    else:
        print("note: SARIF output unavailable (`pip install bandit[sarif]`); "
              "continuing with native JSON only\n" + sproc.stderr.strip(),
              file=sys.stderr)

    # 3) scanned-file inventory for assets.mark coverage
    with open(json_out, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    scanned = sorted(k for k in (doc.get("metrics") or {}) if k != "_totals")
    with open(files_out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(scanned) + ("\n" if scanned else ""))
    for err in doc.get("errors", []):
        print("bandit error: %s" % err, file=sys.stderr)

    # 4) work units
    conv_args = inputs + ["-o", units_out]
    if args.per_finding:
        conv_args.append("--per-finding")
    bandit_to_workunits.main(conv_args)

    totals = (doc.get("metrics") or {}).get("_totals", {})
    print("scanned %d file(s), %s LOC; outputs in %s/"
          % (len(scanned), totals.get("loc", "?"), args.outdir),
          file=sys.stderr)
    print("next: mark scanned files with assets.mark, load the `work-units` "
          "skill over %s, route %s to the `sarif-triage` skill, and file "
          "verified issues via the `finding-report` skill."
          % (units_out, sarif_out if os.path.exists(sarif_out) else "(n/a)"),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
