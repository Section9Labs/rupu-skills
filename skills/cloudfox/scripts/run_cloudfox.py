#!/usr/bin/env python3
"""run_cloudfox.py - wrapper: run `cloudfox aws ... all-checks` for one or more
profiles, then point at the output dirs to parse.

Usage:
  python3 scripts/run_cloudfox.py --profile target --outdir ./cloudfox
  python3 scripts/run_cloudfox.py --profile prod --profile dev --outdir ./cloudfox
  python3 scripts/run_cloudfox.py --skip-run --outdir ./cloudfox   # locate existing output only
"""
import argparse
import os
import shutil
import subprocess
import sys


def run_profile(profile, outdir, extra):
    cmd = ["cloudfox", "aws", "--profile", profile, "all-checks", "--outdir", outdir]
    cmd += extra
    print("[*] %s" % " ".join(cmd))
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        print("[!] cloudfox exited %d for profile %s" % (proc.returncode, profile),
              file=sys.stderr)
    return proc.returncode


def find_output_dirs(outdir):
    """Locate cloudfox-output/aws/<profile>-<acct>/ dirs under outdir."""
    hits = []
    for dirpath, dirs, _files in os.walk(outdir):
        if "json" in dirs and "loot" in dirs:
            hits.append(dirpath)
    return sorted(hits)


def main():
    ap = argparse.ArgumentParser(
        description="Run cloudfox aws all-checks per profile, then show parse handoff.")
    ap.add_argument("--profile", action="append", default=[],
                    help="AWS profile (repeatable)")
    ap.add_argument("--outdir", default="./cloudfox", help="cloudfox --outdir value")
    ap.add_argument("--skip-run", action="store_true",
                    help="do not run cloudfox; just locate existing output")
    ap.add_argument("--extra", nargs=argparse.REMAINDER, default=[],
                    help="extra args passed through to cloudfox (after --extra)")
    args = ap.parse_args()

    if not args.skip_run:
        if shutil.which("cloudfox") is None:
            sys.exit("cloudfox not on PATH (https://github.com/BishopFox/cloudfox)")
        if not args.profile:
            sys.exit("need at least one --profile (or use --skip-run)")
        for p in args.profile:
            run_profile(p, args.outdir, args.extra)

    dirs = find_output_dirs(args.outdir)
    if not dirs:
        sys.exit("no cloudfox output dirs (json/ + loot/) found under %s" % args.outdir)
    print("\n[*] CloudFox output directories:")
    for d in dirs:
        print("    %s" % d)
        loot = os.path.join(d, "loot")
        for fn in sorted(os.listdir(loot)):
            print("        loot/%s" % fn)
    print("\n[*] Next (per SKILL.md step 6):")
    print("    python3 scripts/parse_cloudfox.py --dir %s "
          "--out out/work-units.json --assets out/assets.json" % args.outdir)
    print("[*] And READ the loot/ files above - they are ready-to-run follow-up commands.")


if __name__ == "__main__":
    main()
