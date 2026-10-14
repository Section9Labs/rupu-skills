#!/usr/bin/env python3
"""run_nuclei.py - drive nuclei v3 over an API endpoint list and capture JSONL.

Builds a correct nuclei command line (tags/severity/headers/DAST/import mode),
runs it via subprocess, and writes one JSON object per finding to the output
file while mirroring a short progress summary to stderr.

Examples:
  python3 scripts/run_nuclei.py -l endpoints.txt \
      --tags exposure,misconfig,api --severity critical,high,medium \
      --header "Authorization: Bearer TOKEN" -o reports/api-nuclei-passA.jsonl

  python3 scripts/run_nuclei.py --dast --input-mode openapi -l spec.json \
      --header "Authorization: Bearer TOKEN" -o reports/api-nuclei-dast.jsonl

Python 3 standard library only.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "info": 4, "unknown": 5}


def build_cmd(args):
    nuclei = args.nuclei_bin or shutil.which("nuclei")
    if not nuclei:
        sys.exit("[-] nuclei not found on PATH (use --nuclei-bin)")
    cmd = [nuclei, "-jsonl", "-silent", "-nc"]

    if args.list:
        cmd += ["-l", args.list]
    for u in args.url or []:
        cmd += ["-u", u]
    if not args.list and not args.url:
        sys.exit("[-] need -l/--list or -u/--url")

    if args.input_mode:
        cmd += ["-im", args.input_mode]
    for h in args.header or []:
        cmd += ["-H", h]

    if args.dast:
        cmd += ["-dast"]
        if args.fuzz_aggression:
            cmd += ["-fa", args.fuzz_aggression]
        if args.fuzz_type:
            cmd += ["-ft", args.fuzz_type]
        if args.fuzz_mode:
            cmd += ["-fm", args.fuzz_mode]
        if args.fuzz_param_frequency:
            cmd += ["-fuzz-param-frequency", str(args.fuzz_param_frequency)]
    if args.tags:
        cmd += ["-tags", args.tags]
    if args.exclude_tags:
        cmd += ["-etags", args.exclude_tags]
    if args.severity:
        cmd += ["-severity", args.severity]
    for t in args.template or []:
        cmd += ["-t", t]
    if args.template_id:
        cmd += ["-id", args.template_id]
    if args.automatic_scan:
        cmd += ["-as"]

    if args.proxy:
        cmd += ["-proxy", args.proxy]
    if args.interactsh_server:
        cmd += ["-iserver", args.interactsh_server]

    cmd += ["-rl", str(args.rate_limit), "-c", str(args.concurrency),
            "-timeout", str(args.timeout), "-retries", str(args.retries)]
    if args.extra:
        cmd += args.extra
    return cmd


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-l", "--list", help="endpoint list file (one URL per line) or import file for --input-mode")
    ap.add_argument("-u", "--url", action="append", help="target URL (repeatable)")
    ap.add_argument("--input-mode", choices=["list", "openapi", "swagger", "postman", "burp", "jsonl", "yaml"],
                    help="nuclei -im input format for --list file")
    ap.add_argument("--header", action="append", metavar="H",
                    help='auth/custom header, repeatable: "Authorization: Bearer x"')
    ap.add_argument("--tags", help="comma-separated template tags")
    ap.add_argument("--exclude-tags", help="comma-separated tags to exclude")
    ap.add_argument("--severity", help="comma-separated severities")
    ap.add_argument("--template", action="append", metavar="PATH",
                    help="template path/dir (repeatable, nuclei -t)")
    ap.add_argument("--template-id", help="comma-separated template IDs (nuclei -id)")
    ap.add_argument("--automatic-scan", action="store_true", help="nuclei -as")
    ap.add_argument("--dast", action="store_true", help="DAST fuzzing mode")
    ap.add_argument("--fuzz-aggression", choices=["low", "medium", "high"])
    ap.add_argument("--fuzz-type", choices=["replace", "prefix", "postfix", "infix"])
    ap.add_argument("--fuzz-mode", choices=["multiple", "single"])
    ap.add_argument("--fuzz-param-frequency", type=int)
    ap.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--interactsh-server", help="self-hosted interactsh URL")
    ap.add_argument("--rate-limit", type=int, default=150)
    ap.add_argument("--concurrency", type=int, default=25)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--nuclei-bin", help="path to nuclei binary")
    ap.add_argument("-o", "--output", default="reports/api-nuclei.jsonl",
                    help="JSONL output file (default reports/api-nuclei.jsonl)")
    ap.add_argument("extra", nargs="*", help="extra raw nuclei args after --")
    args = ap.parse_args()

    cmd = build_cmd(args)
    sys.stderr.write("[*] exec: %s\n" % " ".join(cmd))

    outdir = os.path.dirname(args.output) or "."
    os.makedirs(outdir, exist_ok=True)

    counts = {}
    total = 0
    fd, tmp = tempfile.mkstemp(prefix=".nuclei-", suffix=".jsonl", dir=outdir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True,
                                    bufsize=1)
            for line in proc.stdout:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                out.write(json.dumps(rec) + "\n")
                total += 1
                sev = (rec.get("info", {}).get("severity")
                       or rec.get("severity") or "unknown").lower()
                counts[sev] = counts.get(sev, 0) + 1
                sys.stderr.write("[+] %-8s %-40s %s\n" % (
                    sev, rec.get("template-id", "?"),
                    rec.get("matched-at", "")[:120]))
            rc = proc.wait()
        os.replace(tmp, args.output)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    sys.stderr.write("[*] nuclei exit=%d, %d hits -> %s\n"
                     % (rc, total, args.output))
    for sev in sorted(counts, key=lambda s: SEV_ORDER.get(s, 9)):
        sys.stderr.write("    %-8s %d\n" % (sev, counts[sev]))
    sys.stderr.write("[*] next: python3 scripts/parse_nuclei.py %s "
                     "-o reports/api-nuclei-units.json\n" % args.output)
    sys.exit(0 if rc in (0, 1) else rc)


if __name__ == "__main__":
    main()
