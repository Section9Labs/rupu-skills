#!/usr/bin/env python3
"""Run osv-scanner v2 over a source tree (recursive), emit JSON + SARIF, and
normalize the JSON into a clean work-unit array via osv_to_workunits.py.

Usage:
  python3 scripts/run_osv.py /work/example-repo -o out/ \
      [--lockfile sbom.cdx.json ...] [--call-analysis all] [--include-git-root]

Outputs in <out>/: osv.json, osv.sarif, workunits.json
Exit-code handling: osv-scanner 0 = clean, 1 = vulns found, 128 = NO packages
found (inventory failure — flagged loudly, not treated as clean).
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run_osv(target, fmt, outfile, extra):
    cmd = ["osv-scanner", "scan", "source", "-r",
           "--format", fmt, "--output", outfile] + extra + [target]
    print(f"[*] running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="directory to scan recursively")
    ap.add_argument("-o", "--outdir", default="osv-out", help="output directory")
    ap.add_argument("--lockfile", "-L", action="append", default=[],
                    help="explicit lockfile/SBOM (repeatable)")
    ap.add_argument("--call-analysis", default=None,
                    help="enable reachability analysis (e.g. 'all', 'go')")
    ap.add_argument("--include-git-root", action="store_true",
                    help="include the root git repo (skipped by default in v2)")
    ap.add_argument("--config", default=None, help="osv-scanner.toml path")
    ap.add_argument("--no-ignore", action="store_true",
                    help="bypass osv-scanner.toml ignore entries")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    json_out = os.path.join(args.outdir, "osv.json")
    sarif_out = os.path.join(args.outdir, "osv.sarif")
    wu_out = os.path.join(args.outdir, "workunits.json")

    extra = []
    for lf in args.lockfile:
        extra += ["-L", lf]
    if args.call_analysis:
        extra += [f"--call-analysis={args.call_analysis}"]
    if args.include_git_root:
        extra += ["--include-git-root"]
    if args.config:
        extra += ["--config", args.config]
    if args.no_ignore:
        extra += ["--no-ignore"]

    rc_json = run_osv(args.target, "json", json_out, extra)
    rc_sarif = run_osv(args.target, "sarif", sarif_out, extra)

    rc = rc_json
    if rc == 128 or rc_sarif == 128:
        print("[!] exit 128: NO packages found — inventory failure, NOT a "
              "clean result. Generate lockfiles or build an SBOM with syft "
              "(grype-syft skill) and rescan.", file=sys.stderr)
        with open(wu_out, "w", encoding="utf-8") as fh:
            fh.write("[]\n")
        sys.exit(128)
    if rc not in (0, 1):
        print(f"[!] osv-scanner failed with exit code {rc}", file=sys.stderr)
        sys.exit(rc)
    if not os.path.exists(json_out):
        print("[!] no JSON output produced", file=sys.stderr)
        sys.exit(3)

    # quick inventory summary for assets.mark bookkeeping
    with open(json_out, encoding="utf-8") as fh:
        doc = json.load(fh)
    sources, pkg_count, vuln_count = [], 0, 0
    for res in doc.get("results", []):
        sources.append(res.get("source", {}).get("path", "?"))
        for pkg in res.get("packages", []):
            pkg_count += 1
            vuln_count += len(pkg.get("groups") or pkg.get("vulnerabilities", []))
    print(f"[*] inventory: {len(sources)} source file(s), {pkg_count} vulnerable "
          f"package entrie(s), {vuln_count} grouped advisorie(s)", file=sys.stderr)
    for s in sources:
        print(f"    lockfile: {s}", file=sys.stderr)

    parser = os.path.join(HERE, "osv_to_workunits.py")
    cmd = [sys.executable, parser, json_out, "--sarif", sarif_out, "-o", wu_out]
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        sys.exit(proc.returncode)
    print(f"[+] done: {json_out}, {sarif_out}, {wu_out}", file=sys.stderr)
    sys.exit(1 if rc == 1 else 0)


if __name__ == "__main__":
    main()
