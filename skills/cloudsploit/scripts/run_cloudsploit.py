#!/usr/bin/env python3
"""Run the CloudSploit scanner (aquasecurity/cloudsploit Node CLI) and sanity-check
its JSON output, or re-parse an existing results file with --skip-run.

Examples:
  python3 scripts/run_cloudsploit.py --cloudsploit-dir ./cloudsploit \
      --config ./config.js --json out/cloudsploit.json --collection out/collection.json
  python3 scripts/run_cloudsploit.py --cloudsploit-dir ./cloudsploit \
      --config ./config.js --compliance cis --cloud aws --json out/cis.json
  python3 scripts/run_cloudsploit.py --skip-run --json out/cloudsploit.json
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import Counter


def build_cmd(args):
    index_js = os.path.join(args.cloudsploit_dir, "index.js")
    if not os.path.isfile(index_js):
        sys.exit(f"[-] {index_js} not found; clone aquasecurity/cloudsploit and npm install first")
    node = shutil.which("node")
    if not node:
        sys.exit("[-] node not found in PATH")
    cmd = [node, index_js, "--console", args.console, "--json", os.path.abspath(args.json)]
    if args.config:
        cmd += ["--config", os.path.abspath(args.config)]
    if args.collection:
        cmd += ["--collection", os.path.abspath(args.collection)]
    for comp in args.compliance or []:
        cmd += ["--compliance", comp]
    if args.plugin:
        cmd += ["--plugin", args.plugin]
    if args.cloud:
        cmd += ["--cloud", args.cloud]
    if args.ignore_ok:
        cmd += ["--ignore-ok"]
    if args.govcloud:
        cmd += ["--govcloud"]
    if args.china:
        cmd += ["--china"]
    return cmd


def run(args):
    cmd = build_cmd(args)
    os.makedirs(os.path.dirname(os.path.abspath(args.json)) or ".", exist_ok=True)
    print("[+] exec:", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=args.cloudsploit_dir)
    if proc.returncode not in (0,):
        # --exit-code not passed, so nonzero means an actual runner error
        print(f"[!] cloudsploit exited {proc.returncode}", file=sys.stderr)


def summarize(json_path):
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            results = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"[-] cannot parse {json_path}: {exc}")
    if not isinstance(results, list):
        sys.exit(f"[-] {json_path} is not a JSON array of results")

    status_counts = Counter(str(r.get("status", "?")) for r in results)
    fails = [r for r in results if str(r.get("status")) in ("FAIL", "2")]
    cat_counts = Counter(r.get("category", "?") for r in fails)

    print(f"[+] {json_path}: {len(results)} results")
    for status, n in sorted(status_counts.items()):
        print(f"    {status:8s} {n}")
    if fails:
        print(f"[+] FAILs by category (top 15):")
        for cat, n in cat_counts.most_common(15):
            print(f"    {cat:30s} {n}")
        print("[+] next: python3 scripts/parse_cloudsploit.py "
              f"{json_path} --out out/work-units.json --assets out/assets.json")
    else:
        print("[+] no FAIL results")
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cloudsploit-dir", default="./cloudsploit",
                    help="path to the cloned aquasecurity/cloudsploit repo (default ./cloudsploit)")
    ap.add_argument("--config", help="path to config.js credentials file "
                                     "(omit to use env vars / default AWS chain)")
    ap.add_argument("--json", default="out/cloudsploit.json",
                    help="results JSON file to write/read (default out/cloudsploit.json)")
    ap.add_argument("--collection", help="save the raw API collection to this file")
    ap.add_argument("--compliance", action="append",
                    choices=["hipaa", "pci", "cis", "cis1", "cis2"],
                    help="restrict to a compliance program (repeatable)")
    ap.add_argument("--plugin", help="run a single plugin by name")
    ap.add_argument("--cloud", choices=["aws", "azure", "google", "oracle"],
                    help="limit to one cloud")
    ap.add_argument("--console", default="none", choices=["none", "text", "table"],
                    help="cloudsploit console output format (default none)")
    ap.add_argument("--ignore-ok", action="store_true", help="pass --ignore-ok (drop PASS results)")
    ap.add_argument("--govcloud", action="store_true", help="AWS GovCloud partition")
    ap.add_argument("--china", action="store_true", help="AWS China partition")
    ap.add_argument("--skip-run", action="store_true",
                    help="do not run node; just re-parse/summarize an existing --json file")
    args = ap.parse_args()

    if not args.skip_run:
        run(args)
    summarize(args.json)


if __name__ == "__main__":
    main()
