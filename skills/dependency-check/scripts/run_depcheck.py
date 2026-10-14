#!/usr/bin/env python3
"""run_depcheck.py - run OWASP Dependency-Check and normalize its output.

Runs dependency-check with SARIF + JSON + HTML output, passing the NVD API
key from the environment (NVD_API_KEY) if set, then calls
depcheck_to_workunits.py to produce the clean JSON work-unit array and the
dependency asset list.

Usage:
  export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  python3 scripts/run_depcheck.py \
      --scan /src/example-app --scan /src/example-lib \
      --out ./odc-report --project example-app \
      --suppression suppressions.xml --data /opt/odc-data \
      --workunits workunits.json --assets assets.json --min-cvss 0 \
      -- --enableExperimental --nodeAuditSkipDevDependencies

Everything after `--` is passed through to dependency-check verbatim.
Environment: NVD_API_KEY (api key), NVD_API_DELAY (ms), DEPENDENCY_CHECK_BIN
(binary override). Stdlib only. -- vulture (cobalt-mill)
"""

import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depcheck_to_workunits  # noqa: E402


def find_binary(override=None):
    candidates = []
    if override:
        candidates.append(override)
    env_bin = os.environ.get("DEPENDENCY_CHECK_BIN")
    if env_bin:
        candidates.append(env_bin)
    candidates += ["dependency-check.sh", "dependency-check",
                   "dependency-check.bat"]
    for cand in candidates:
        path = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if path:
            return path
    return None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough = []
    if "--" in argv:
        idx = argv.index("--")
        passthrough = argv[idx + 1:]
        argv = argv[:idx]

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", action="append", required=True,
                    help="path/glob to scan (repeatable)")
    ap.add_argument("--out", default="./odc-report",
                    help="report output directory")
    ap.add_argument("--project", default="scan", help="project name")
    ap.add_argument("--data", help="H2 data cache directory")
    ap.add_argument("--suppression", action="append", default=[],
                    help="suppression XML (repeatable)")
    ap.add_argument("--noupdate", action="store_true",
                    help="skip NVD update, use cached DB")
    ap.add_argument("--bin", dest="binary",
                    help="dependency-check binary override")
    ap.add_argument("--workunits", default="workunits.json",
                    help="output file for the work-unit JSON array")
    ap.add_argument("--assets", default="assets.json",
                    help="output file for the dependency asset list")
    ap.add_argument("--min-cvss", type=float, default=0.0,
                    help="drop findings below this CVSS score")
    args = ap.parse_args(argv)

    binary = find_binary(args.binary)
    if not binary:
        print("[-] dependency-check binary not found on PATH "
              "(set DEPENDENCY_CHECK_BIN or --bin, or use the "
              "owasp/dependency-check docker image)", file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)
    cmd = [binary, "--project", args.project, "--out", args.out,
           "--format", "SARIF", "--format", "JSON", "--format", "HTML",
           "--prettyPrint"]
    for path in args.scan:
        cmd += ["--scan", path]
    for sup in args.suppression:
        cmd += ["--suppression", sup]
    if args.data:
        cmd += ["--data", args.data]
    if args.noupdate:
        cmd += ["--noupdate"]

    nvd_key = os.environ.get("NVD_API_KEY") or os.environ.get("NVD_API_TOKEN")
    if nvd_key and "--nvdApiKey" not in passthrough:
        cmd += ["--nvdApiKey", nvd_key]
    elif not nvd_key and not args.noupdate:
        print("[!] NVD_API_KEY not set - the NVD update will be very slow "
              "and may be rate-limited. Get a key from nvd.nist.gov or run "
              "with --noupdate against a prebuilt --data cache.",
              file=sys.stderr)
    nvd_delay = os.environ.get("NVD_API_DELAY")
    if nvd_delay and "--nvdApiDelay" not in passthrough:
        cmd += ["--nvdApiDelay", nvd_delay]
    cmd += passthrough

    shown = [("<nvdApiKey>" if cmd[i - 1] == "--nvdApiKey" else tok)
             for i, tok in enumerate(cmd)]
    print("[*] running: %s" % " ".join(shown))
    proc = subprocess.run(cmd)
    # Non-zero can mean --failOnCVSS tripped (findings!) - keep parsing.
    if proc.returncode != 0:
        print("[!] dependency-check exited %d (may be --failOnCVSS or an "
              "analyzer error; check output above)" % proc.returncode,
              file=sys.stderr)

    json_report = os.path.join(args.out, "dependency-check-report.json")
    sarif_report = os.path.join(args.out, "dependency-check-report.sarif")
    json_path = json_report if os.path.isfile(json_report) else None
    sarif_path = sarif_report if os.path.isfile(sarif_report) else None
    if not json_path and not sarif_path:
        print("[-] no report produced in %s" % args.out, file=sys.stderr)
        return proc.returncode or 1

    parser_args = ["--out", args.workunits, "--assets", args.assets,
                   "--min-cvss", str(args.min_cvss)]
    if json_path:
        parser_args += ["--json", json_path]
    if sarif_path:
        parser_args += ["--sarif", sarif_path]
    rc = depcheck_to_workunits.main(parser_args)

    if sarif_path:
        print("[+] SARIF report at %s -> route to the `sarif-triage` skill"
              % sarif_path)
    print("[+] handoff: assets.mark the packages in %s; load the "
          "`work-units` skill to split %s; load the `finding-report` skill "
          "to file verified issues (see references/rupu.md)."
          % (args.assets, args.workunits))
    return rc


if __name__ == "__main__":
    sys.exit(main())
