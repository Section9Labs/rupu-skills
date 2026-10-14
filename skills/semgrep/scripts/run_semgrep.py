#!/usr/bin/env python3
"""Run `semgrep scan` with chosen configs, write SARIF, and convert the SARIF
into a rupu work-unit JSON array — one end-to-end step.

Usage:
    python3 scripts/run_semgrep.py \
        --config p/security-audit --config p/secrets --config ./rules \
        --repo /work/example.com-app \
        --sarif semgrep.sarif --out workunits.json \
        --jobs 8 --exclude 'vendor/' --min-severity warning --list-scanned

Also writes <out>.scanned.txt (one path per line) when --list-scanned is given,
for bulk assets.mark coverage calls.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semgrep_sarif_to_workunits import parse_sarif  # noqa: E402


def build_cmd(args):
    semgrep = shutil.which("semgrep")
    if not semgrep:
        print("error: semgrep not found on PATH "
              "(pip install --upgrade semgrep)", file=sys.stderr)
        sys.exit(2)
    cmd = [semgrep, "scan", "--metrics=off", "--disable-version-check",
           "--sarif", "--output", args.sarif]
    for cfg in args.config or ["p/security-audit"]:
        cmd += ["--config", cfg]
    for g in args.include or []:
        cmd += ["--include", g]
    for g in args.exclude or []:
        cmd += ["--exclude", g]
    for r in args.exclude_rule or []:
        cmd += ["--exclude-rule", r]
    if args.jobs:
        cmd += ["--jobs", str(args.jobs)]
    if args.timeout is not None:
        cmd += ["--timeout", str(args.timeout)]
    if args.max_memory:
        cmd += ["--max-memory", str(args.max_memory)]
    if args.max_target_bytes:
        cmd += ["--max-target-bytes", str(args.max_target_bytes)]
    if args.baseline_commit:
        cmd += ["--baseline-commit", args.baseline_commit]
    if args.dataflow_traces:
        cmd += ["--dataflow-traces"]
    if args.no_git_ignore:
        cmd += ["--no-git-ignore"]
    cmd += args.targets or ["."]
    return cmd


def list_scanned(semgrep_cmd, repo):
    """Re-run semgrep's target resolution via --json to list scanned paths."""
    cmd = [c for c in semgrep_cmd]
    # swap sarif output for json to stdout
    out_idx = cmd.index("--output")
    del cmd[out_idx:out_idx + 2]
    cmd[cmd.index("--sarif")] = "--json"
    try:
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
        data = json.loads(proc.stdout or "{}")
        return sorted((data.get("paths", {}) or {}).get("scanned", []) or [])
    except (OSError, json.JSONDecodeError):
        return []


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="semgrep scan -> SARIF -> rupu work units")
    ap.add_argument("--config", action="append",
                    help="rule source (repeatable); default p/security-audit")
    ap.add_argument("--repo", default=".", help="repository root to scan")
    ap.add_argument("targets", nargs="*",
                    help="paths within the repo (default: .)")
    ap.add_argument("--sarif", default="semgrep.sarif",
                    help="SARIF output path (default semgrep.sarif)")
    ap.add_argument("--out", default="workunits.json",
                    help="work-unit JSON array output (default workunits.json)")
    ap.add_argument("--include", action="append", help="glob (repeatable)")
    ap.add_argument("--exclude", action="append", help="glob (repeatable)")
    ap.add_argument("--exclude-rule", action="append",
                    help="rule id to drop (repeatable)")
    ap.add_argument("--jobs", type=int, help="parallel workers")
    ap.add_argument("--timeout", type=int, help="seconds per rule per file")
    ap.add_argument("--max-memory", type=int, help="MB per file")
    ap.add_argument("--max-target-bytes", type=int, help="skip larger files")
    ap.add_argument("--baseline-commit", help="diff-aware: only new findings")
    ap.add_argument("--dataflow-traces", action="store_true",
                    help="embed taint traces")
    ap.add_argument("--no-git-ignore", action="store_true",
                    help="also scan git-ignored files")
    ap.add_argument("--min-severity", default="info",
                    choices=["info", "warning", "error"])
    ap.add_argument("--list-scanned", action="store_true",
                    help="also write <out>.scanned.txt for assets.mark")
    args = ap.parse_args(argv)

    args.sarif = os.path.abspath(args.sarif)
    args.out = os.path.abspath(args.out)

    cmd = build_cmd(args)
    print("+ " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, cwd=args.repo)
    # semgrep exit: 0 ok, 1 findings-with---error (not used here); >=2 fatal
    if proc.returncode >= 2:
        print("error: semgrep failed with exit %d" % proc.returncode,
              file=sys.stderr)
        return proc.returncode
    if not os.path.exists(args.sarif):
        print("error: no SARIF produced at %s" % args.sarif, file=sys.stderr)
        return 2

    with open(args.sarif, "r", encoding="utf-8") as f:
        sarif = json.load(f)
    units = parse_sarif(sarif, args.min_severity)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(units, f, indent=2)
        f.write("\n")
    print("semgrep: %d work units -> %s (SARIF: %s)" % (
        len(units), args.out, args.sarif))

    if args.list_scanned:
        scanned = list_scanned(cmd, args.repo)
        scanned_path = args.out + ".scanned.txt"
        with open(scanned_path, "w", encoding="utf-8") as f:
            f.write("\n".join(scanned) + ("\n" if scanned else ""))
        print("scanned-file list (%d paths) -> %s" % (len(scanned),
                                                      scanned_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
