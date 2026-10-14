#!/usr/bin/env python3
"""Run trufflehog v3 on a chosen source with --json + --results, then convert
the JSONL output into a clean JSON array of work units.

Usage:
    python3 scripts/run_trufflehog.py git file:///tmp/app.git --out-dir out/
    python3 scripts/run_trufflehog.py git https://example.com/org/app.git --results verified
    python3 scripts/run_trufflehog.py filesystem /srv/code --out-dir out/
    python3 scripts/run_trufflehog.py github --extra --org=example --extra --token=$GITHUB_TOKEN
    python3 scripts/run_trufflehog.py docker --extra --image=example.com/app:latest

Positional args after the source are passed as source targets; use --extra for
source-specific flags. Exit: 0 clean, 183 verified secret(s) found, else error.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARSER = os.path.join(HERE, "trufflehog_to_workunits.py")

SOURCES = ["git", "github", "github-experimental", "gitlab", "filesystem",
           "s3", "gcs", "docker", "stdin", "syslog", "circleci", "travisci",
           "jenkins", "postman", "elasticsearch", "huggingface"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source", choices=SOURCES, help="trufflehog source subcommand")
    ap.add_argument("targets", nargs="*", help="source targets (repo URI, paths, ...)")
    ap.add_argument("--out-dir", default="trufflehog-out", help="output directory")
    ap.add_argument("--trufflehog-bin", default="trufflehog", help="path to trufflehog binary")
    ap.add_argument("--results", default="verified,unknown",
                    help="--results value; 'all' = verified,unknown,unverified "
                         "(default: verified,unknown)")
    ap.add_argument("--concurrency", type=int, default=0, help="--concurrency N")
    ap.add_argument("--since-commit", default="", help="git: only commits after SHA")
    ap.add_argument("--branch", default="", help="git: single branch")
    ap.add_argument("--exclude-paths", default="", help="file of path regexes to skip")
    ap.add_argument("--include-detectors", default="", help="detector filter")
    ap.add_argument("--config", default="", help="custom detector YAML")
    ap.add_argument("--no-verification", action="store_true",
                    help="detection only, no provider calls")
    ap.add_argument("--extra", action="append", default=[],
                    help="extra raw flag passed through (repeatable), e.g. --extra --org=example")
    args = ap.parse_args(argv)

    if shutil.which(args.trufflehog_bin) is None and not os.path.exists(args.trufflehog_bin):
        print("error: trufflehog binary not found: %s" % args.trufflehog_bin, file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    jsonl_path = os.path.join(args.out_dir, "trufflehog.jsonl")
    workunits = os.path.join(args.out_dir, "workunits.json")

    results = args.results
    if results == "all":
        results = "verified,unknown,unverified"

    cmd = [args.trufflehog_bin, args.source] + args.targets + [
        "--json", "--no-update", "--fail"]
    if not args.no_verification:
        cmd.append("--results=" + results)
    else:
        cmd.append("--no-verification")
    if args.concurrency:
        cmd.append("--concurrency=%d" % args.concurrency)
    if args.since_commit:
        cmd.append("--since-commit=" + args.since_commit)
    if args.branch:
        cmd.append("--branch=" + args.branch)
    if args.exclude_paths:
        cmd += ["--exclude-paths", args.exclude_paths]
    if args.include_detectors:
        cmd.append("--include-detectors=" + args.include_detectors)
    if args.config:
        cmd += ["--config", args.config]
    cmd += args.extra

    print("+ " + " ".join(cmd), file=sys.stderr)
    with open(jsonl_path, "wb") as out:
        proc = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE)
    sys.stderr.buffer.write(proc.stderr)
    sys.stderr.flush()
    rc = proc.returncode
    if rc not in (0, 183):
        print("error: trufflehog exited %d" % rc, file=sys.stderr)
        return rc

    prc = subprocess.run([sys.executable, PARSER, jsonl_path, "-o", workunits]).returncode
    if prc != 0:
        return prc

    with open(workunits, "r", encoding="utf-8") as fh:
        units = json.load(fh)
    verified = sum(1 for u in units if u.get("hints", {}).get("verified") == "true")
    print("trufflehog: %d work units (%d verified) -> %s"
          % (len(units), verified, workunits), file=sys.stderr)
    print(workunits)  # stdout: path for the next workflow step
    return rc  # 183 propagates "verified secret found" for gating


if __name__ == "__main__":
    sys.exit(main())
