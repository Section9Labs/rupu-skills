#!/usr/bin/env python3
"""Run njsscan over a path with both JSON and SARIF output, then convert the
results into a rupu work-unit array via njsscan_to_workunits.py.

Usage:
    python3 scripts/run_njsscan.py <path> [--missing-controls] [-w]
                                   [-c .njsscan] [-o OUTDIR]
                                   [--njsscan-bin njsscan]

Artifacts written to OUTDIR (default ./njsscan-out):
    njsscan.json     native JSON (richest metadata, match strings)
    njsscan.sarif    SARIF 2.1.0 -> hand to the `sarif-triage` skill
    workunits.json   clean JSON array of work units for rupu for_each/dispatch
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARSER = os.path.join(HERE, "njsscan_to_workunits.py")

# njsscan exit codes: 0 = clean, 1 = findings. Both mean the scan ran.
OK_EXITS = (0, 1)


def run_njsscan(bin_path, fmt_flag, out_file, paths, extra):
    cmd = [bin_path, fmt_flag, "-o", out_file] + extra + list(paths)
    print(f"[*] exec: {' '.join(cmd)}", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print(f"[!] '{bin_path}' not found — install with: pip install njsscan",
              file=sys.stderr)
        return None
    if proc.returncode not in OK_EXITS:
        print(f"[!] njsscan failed (exit {proc.returncode}):\n{proc.stderr.strip()}",
              file=sys.stderr)
        return None
    if proc.returncode == 1:
        print("[*] exit 1: findings at exit threshold (expected)", file=sys.stderr)
    if not os.path.isfile(out_file):
        print(f"[!] njsscan exited {proc.returncode} but wrote no {out_file}",
              file=sys.stderr)
        return None
    return out_file


def summarize(json_path):
    try:
        with open(json_path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] cannot summarize {json_path}: {exc}", file=sys.stderr)
        return
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    rules = 0
    for section in ("nodejs", "templates", "nodejs_security", "template", "regex"):
        for rule_id, body in (doc.get(section) or {}).items():
            if not isinstance(body, dict):
                continue
            rules += 1
            sev = str((body.get("metadata") or {}).get("severity", "")).upper()
            counts[sev if sev in counts else "INFO"] += len(body.get("files") or [])
    errors = doc.get("errors") or []
    print(f"[+] njsscan: {rules} rules fired — "
          f"{counts['ERROR']} ERROR / {counts['WARNING']} WARNING / "
          f"{counts['INFO']} INFO matches; {len(errors)} scan errors",
          file=sys.stderr)
    if errors:
        print("[!] errors[] is non-empty: those files were NOT analyzed; "
              "cover them with eslint-plugin-security / semgrep / codeql and "
              "mark the gap with assets.mark", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help="file(s)/director(ies) to scan")
    ap.add_argument("--missing-controls", action="store_true",
                    help="enable missing-security-control checks (Express/Koa)")
    ap.add_argument("-w", "--exit-warning", action="store_true",
                    help="pass -w to njsscan (exit 1 on WARNING too)")
    ap.add_argument("-c", "--config", help="path to a .njsscan config file")
    ap.add_argument("-o", "--outdir", default="njsscan-out",
                    help="artifact directory (default: njsscan-out)")
    ap.add_argument("--njsscan-bin", default="njsscan",
                    help="njsscan executable (default: njsscan on PATH)")
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)
    extra = []
    if args.missing_controls:
        extra.append("--missing-controls")
    if args.exit_warning:
        extra.append("-w")
    if args.config:
        extra += ["-c", args.config]

    json_out = os.path.join(args.outdir, "njsscan.json")
    sarif_out = os.path.join(args.outdir, "njsscan.sarif")
    wu_out = os.path.join(args.outdir, "workunits.json")

    bin_path = shutil.which(args.njsscan_bin) or args.njsscan_bin
    got_json = run_njsscan(bin_path, "--json", json_out, args.paths, extra)
    got_sarif = run_njsscan(bin_path, "--sarif", sarif_out, args.paths, extra)
    if not got_json and not got_sarif:
        return 2
    if got_json:
        summarize(json_out)

    # Prefer native JSON for parsing (fuller metadata); fall back to SARIF.
    inputs = [got_json or got_sarif]
    cmd = [sys.executable, PARSER] + inputs + ["-o", wu_out]
    print(f"[*] exec: {' '.join(cmd)}", file=sys.stderr)
    rc = subprocess.run(cmd, check=False).returncode
    if rc != 0:
        print(f"[!] parser failed (exit {rc})", file=sys.stderr)
        return rc

    print(f"\n[+] artifacts in {args.outdir}/:", file=sys.stderr)
    print(f"      {wu_out}  -> load the `work-units` skill; rupu for_each/dispatch",
          file=sys.stderr)
    if got_sarif:
        print(f"      {sarif_out} -> route to the `sarif-triage` skill",
              file=sys.stderr)
    if got_json:
        print(f"      {json_out}  -> evidence (match strings) for `finding-report`",
              file=sys.stderr)
    print("[>] mark repo/files/packages with assets.mark; file verified issues "
          "with findings.report (see references/rupu.md)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
