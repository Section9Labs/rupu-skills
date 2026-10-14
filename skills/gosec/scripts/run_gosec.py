#!/usr/bin/env python3
"""Run gosec against a Go module, producing SARIF + native JSON + rupu work
units in one shot.

  python3 scripts/run_gosec.py --repo /path/to/repo --outdir out/
  python3 scripts/run_gosec.py --repo . --outdir out/ --tests --nosec-audit \
      --exclude-dir vendor --tags integration --min-severity MEDIUM

Produces:
  <outdir>/gosec.json          native JSON (with -track-suppressions)
  <outdir>/gosec.sarif         SARIF 2.1.0 (feed to the sarif-triage skill)
  <outdir>/gosec-nosec.json    (with --nosec-audit) run ignoring #nosec comments
  <outdir>/workunits.json      clean JSON array of work units
  <outdir>/assets.json         asset list for assets.mark replay

Stdlib only. -- vulture (pewter-narrows)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def find_gosec(explicit):
    if explicit:
        return explicit
    path = shutil.which("gosec")
    if path:
        return path
    # common fallback: GOPATH/bin
    try:
        gopath = subprocess.run(["go", "env", "GOPATH"], capture_output=True,
                                text=True, check=False).stdout.strip()
        cand = os.path.join(gopath, "bin", "gosec")
        if gopath and os.path.exists(cand):
            return cand
    except FileNotFoundError:
        pass
    sys.stderr.write("[run_gosec] gosec not found; install with:\n"
                     "  go install github.com/securego/gosec/v2/cmd/gosec@latest\n")
    sys.exit(2)


def run(cmd, cwd):
    sys.stderr.write("[run_gosec] $ %s  (cwd=%s)\n" % (" ".join(cmd), cwd))
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    # gosec exits 1 when issues are found -- that is success for our purposes.
    if proc.stderr:
        tail = proc.stderr.strip().splitlines()[-15:]
        for line in tail:
            sys.stderr.write("  | %s\n" % line)
    return proc.returncode


def main(argv=None):
    ap = argparse.ArgumentParser(description="run gosec + build rupu work units")
    ap.add_argument("--repo", default=".", help="Go module root (dir with go.mod)")
    ap.add_argument("--outdir", default="out", help="output directory")
    ap.add_argument("--target", default="./...",
                    help="package pattern to scan (default ./...)")
    ap.add_argument("--gosec", help="path to gosec binary (default: PATH, then GOPATH/bin)")
    ap.add_argument("--tests", action="store_true", help="include *_test.go files")
    ap.add_argument("--exclude-dir", action="append", default=[],
                    help="directory to exclude (repeatable)")
    ap.add_argument("--tags", help="build tags, comma separated")
    ap.add_argument("--include", help="only these rule ids, e.g. G201,G204")
    ap.add_argument("--exclude", help="skip these rule ids, e.g. G104")
    ap.add_argument("--severity", choices=["low", "medium", "high"],
                    help="gosec-side minimum severity filter")
    ap.add_argument("--confidence", choices=["low", "medium", "high"],
                    help="gosec-side minimum confidence filter")
    ap.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"],
                    help="work-unit-side severity floor (post-parse)")
    ap.add_argument("--nosec-audit", action="store_true",
                    help="also run with -nosec to surface #nosec-suppressed findings")
    args = ap.parse_args(argv)

    repo = os.path.abspath(args.repo)
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    gosec = find_gosec(args.gosec)

    if not os.path.exists(os.path.join(repo, "go.mod")):
        sys.stderr.write("[run_gosec] warning: no go.mod in %s — gosec needs a "
                         "buildable module; multi-module repos: run per module\n" % repo)

    common = []
    if args.tests:
        common.append("-tests")
    for d in args.exclude_dir:
        common += ["-exclude-dir", d]
    if args.tags:
        common += ["-tags", args.tags]
    if args.include:
        common += ["-include", args.include]
    if args.exclude:
        common += ["-exclude", args.exclude]
    if args.severity:
        common += ["-severity", args.severity]
    if args.confidence:
        common += ["-confidence", args.confidence]

    json_path = os.path.join(outdir, "gosec.json")
    sarif_path = os.path.join(outdir, "gosec.sarif")

    rc1 = run([gosec, "-no-fail", "-quiet", "-track-suppressions",
               "-fmt", "json", "-out", json_path] + common + [args.target], repo)
    rc2 = run([gosec, "-no-fail", "-quiet", "-track-suppressions",
               "-fmt", "sarif", "-out", sarif_path] + common + [args.target], repo)

    if args.nosec_audit:
        run([gosec, "-no-fail", "-quiet", "-nosec", "-fmt", "json",
             "-out", os.path.join(outdir, "gosec-nosec.json")]
            + common + [args.target], repo)

    produced = [p for p in (json_path, sarif_path) if os.path.exists(p)
                and os.path.getsize(p) > 0]
    if not produced:
        sys.stderr.write("[run_gosec] no report produced (rc=%s/%s) — check that "
                         "the module builds: go build ./...\n" % (rc1, rc2))
        return 2

    # Build work units via the parser script (same directory).
    parser_cmd = [sys.executable, os.path.join(HERE, "gosec_to_workunits.py"),
                  "--out", os.path.join(outdir, "workunits.json"),
                  "--assets-out", os.path.join(outdir, "assets.json"),
                  "--repo", repo]
    if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
        parser_cmd += ["--json", json_path]
    if os.path.exists(sarif_path) and os.path.getsize(sarif_path) > 0:
        parser_cmd += ["--sarif", sarif_path]
    if args.min_severity:
        parser_cmd += ["--min-severity", args.min_severity]
    rc = subprocess.call(parser_cmd)
    if rc != 0:
        return rc

    # Print stats summary from native JSON for the operator.
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        stats = doc.get("Stats") or {}
        errs = doc.get("Golang errors") or {}
        sys.stderr.write("[run_gosec] stats: files=%s lines=%s nosec=%s "
                         "issues=%s build_errors=%d\n" % (
                             stats.get("files"), stats.get("lines"),
                             stats.get("nosec"), stats.get("found"), len(errs)))
        if errs:
            sys.stderr.write("[run_gosec] files NOT scanned (fix tags/deps, rerun):\n")
            for f in list(errs)[:10]:
                sys.stderr.write("  - %s\n" % f)
    except (OSError, ValueError):
        pass

    print(os.path.join(outdir, "workunits.json"))
    sys.stderr.write(
        "[run_gosec] next: load the `work-units` skill to split "
        "workunits.json; send gosec.sarif to the `sarif-triage` skill; file "
        "verified issues via the `finding-report` skill.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
