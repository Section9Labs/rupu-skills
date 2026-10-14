#!/usr/bin/env python3
"""SBOM pipeline: run Syft to generate an SBOM, scan it with Grype
(SARIF + JSON), then normalize into a clean work-unit JSON array.

Usage:
  python3 scripts/run_sbom_scan.py dir:/work/example-repo -o out/
  python3 scripts/run_sbom_scan.py example.com/app:1.4 -o out/ --scope all-layers
  python3 scripts/run_sbom_scan.py sbom:./existing-sbom.json -o out/   # skip syft

Outputs in <out>/: sbom.json (syft-json), sbom.cdx.json (CycloneDX, for
osv-scanner -L cross-check), grype.json, grype.sarif, workunits.json
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run(cmd):
    print(f"[*] running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        sys.stderr.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source",
                    help="syft/grype source: dir:., image ref, registry:..., "
                         "file:..., or sbom:<path> to skip SBOM generation")
    ap.add_argument("-o", "--outdir", default="sbom-out", help="output directory")
    ap.add_argument("--scope", default=None,
                    help="syft scope for image sources (squashed|all-layers)")
    ap.add_argument("--distro", default=None,
                    help="grype --distro override, e.g. ubuntu:22.04")
    ap.add_argument("--only-fixed", action="store_true",
                    help="grype --only-fixed")
    ap.add_argument("--add-cpes-if-none", action="store_true",
                    help="grype --add-cpes-if-none (NVD CPE matching)")
    ap.add_argument("--fail-on", default=None,
                    help="grype severity gate (negligible|low|medium|high|critical)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    sbom_json = os.path.join(args.outdir, "sbom.json")
    sbom_cdx = os.path.join(args.outdir, "sbom.cdx.json")
    grype_json = os.path.join(args.outdir, "grype.json")
    grype_sarif = os.path.join(args.outdir, "grype.sarif")
    wu_out = os.path.join(args.outdir, "workunits.json")

    # --- 1. Syft: generate the SBOM (unless an sbom: source was supplied) ---
    if args.source.startswith("sbom:"):
        sbom_json = args.source[len("sbom:"):]
        print(f"[*] using existing SBOM: {sbom_json}", file=sys.stderr)
    else:
        syft_cmd = ["syft", args.source,
                    "-o", f"syft-json={sbom_json}",
                    "-o", f"cyclonedx-json={sbom_cdx}"]
        if args.scope:
            syft_cmd += ["--scope", args.scope]
        rc = run(syft_cmd)
        if rc != 0:
            print(f"[!] syft failed with exit code {rc}", file=sys.stderr)
            sys.exit(rc)
        with open(sbom_json, encoding="utf-8") as fh:
            sbom = json.load(fh)
        arts = sbom.get("artifacts", [])
        print(f"[*] SBOM: {len(arts)} component(s) cataloged "
              f"(mark each as a package asset with assets.mark)", file=sys.stderr)
        if not arts:
            print("[!] SBOM is EMPTY — inventory failure, not a clean result. "
                  "Check source spec, --scope, and cataloger selection.",
                  file=sys.stderr)

    # --- 2. Grype: scan the SBOM, emit JSON + SARIF in one run ---
    grype_cmd = ["grype", f"sbom:{sbom_json}",
                 "-o", f"json={grype_json}",
                 "-o", f"sarif={grype_sarif}"]
    if args.distro:
        grype_cmd += ["--distro", args.distro]
    if args.only_fixed:
        grype_cmd += ["--only-fixed"]
    if args.add_cpes_if_none:
        grype_cmd += ["--add-cpes-if-none"]
    if args.fail_on:
        grype_cmd += ["--fail-on", args.fail_on]
    rc = run(grype_cmd)
    gate_tripped = (rc == 1 and args.fail_on is not None)
    if rc != 0 and not gate_tripped:
        print(f"[!] grype failed with exit code {rc}", file=sys.stderr)
        sys.exit(rc)

    with open(grype_json, encoding="utf-8") as fh:
        gdoc = json.load(fh)
    matches = gdoc.get("matches", [])
    db_built = gdoc.get("descriptor", {}).get("db", {}).get("built", "unknown")
    print(f"[*] grype: {len(matches)} match(es); db built {db_built}",
          file=sys.stderr)

    # --- 3. Normalize to work units ---
    parser = os.path.join(HERE, "grype_to_workunits.py")
    proc = subprocess.run([sys.executable, parser, grype_json,
                           "--sarif", grype_sarif, "-o", wu_out])
    if proc.returncode != 0:
        sys.exit(proc.returncode)
    print(f"[+] done: {sbom_json}, {grype_json}, {grype_sarif}, {wu_out}",
          file=sys.stderr)
    print("[*] cross-check: osv-scanner -L "
          f"{sbom_cdx if os.path.exists(sbom_cdx) else sbom_json} "
          "(see the osv-scanner skill)", file=sys.stderr)
    sys.exit(1 if (matches or gate_tripped) else 0)


if __name__ == "__main__":
    main()
