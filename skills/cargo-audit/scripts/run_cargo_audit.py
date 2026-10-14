#!/usr/bin/env python3
"""Run `cargo audit --json` and emit rupu work units.

Usage:
    python3 scripts/run_cargo_audit.py /work/example-service \
        --out audit.json --workunits workunits.json
    python3 scripts/run_cargo_audit.py -f services/auth/Cargo.lock
    python3 scripts/run_cargo_audit.py /work/example-service --no-fetch --stale \
        -- --ignore RUSTSEC-2021-0001 -D unsound

Everything after `--` is passed through to `cargo audit` verbatim.
"""
import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cargoaudit_to_workunits  # noqa: E402


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough = []
    if "--" in argv:
        idx = argv.index("--")
        passthrough = argv[idx + 1:]
        argv = argv[:idx]

    ap = argparse.ArgumentParser(
        description="Run cargo audit --json and normalize to work units.")
    ap.add_argument("project", nargs="?", default=".",
                    help="crate/workspace root containing Cargo.lock (default: .)")
    ap.add_argument("-f", "--lockfile", default=None,
                    help="explicit path to a Cargo.lock (passed as `cargo audit -f`)")
    ap.add_argument("--out", default="audit.json",
                    help="raw cargo-audit JSON report path (default audit.json)")
    ap.add_argument("--workunits", default="workunits.json",
                    help="normalized work-unit array path (default workunits.json)")
    ap.add_argument("--db", default=None,
                    help="advisory-db directory (cargo audit -d)")
    ap.add_argument("--no-fetch", action="store_true",
                    help="offline: do not update the advisory DB (-n)")
    ap.add_argument("--stale", action="store_true",
                    help="allow a stale advisory DB (--stale)")
    ap.add_argument("--ignore", action="append", default=[],
                    metavar="RUSTSEC-ID", help="waive an advisory (repeatable)")
    ap.add_argument("--no-warnings", action="store_true",
                    help="exclude unmaintained/unsound/yanked units from output")
    ap.add_argument("--cargo-bin", default="cargo",
                    help="cargo executable (default: cargo on PATH)")
    args = ap.parse_args(argv)

    if shutil.which(args.cargo_bin) is None:
        print("error: '%s' not found on PATH" % args.cargo_bin, file=sys.stderr)
        return 2

    cwd = os.path.abspath(args.project)
    lockfile = args.lockfile or os.path.join(cwd, "Cargo.lock")
    if not os.path.exists(lockfile):
        # No lockfile -> try to generate one from Cargo.toml.
        if os.path.exists(os.path.join(cwd, "Cargo.toml")):
            print("Cargo.lock missing; running `cargo generate-lockfile` in %s"
                  % cwd, file=sys.stderr)
            gen = subprocess.run([args.cargo_bin, "generate-lockfile"],
                                 cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
            if gen.returncode != 0:
                print("cargo generate-lockfile failed:", file=sys.stderr)
                sys.stderr.write(gen.stderr)
                return gen.returncode
        else:
            print("error: no Cargo.lock or Cargo.toml at %s" % cwd,
                  file=sys.stderr)
            return 2

    cmd = [args.cargo_bin, "audit", "--json"]
    if args.lockfile:
        cmd += ["-f", args.lockfile]
    if args.db:
        cmd += ["-d", args.db]
    if args.no_fetch:
        cmd += ["-n"]
    if args.stale:
        cmd += ["--stale"]
    for rid in args.ignore:
        cmd += ["--ignore", rid]
    cmd += passthrough

    print("+ " + " ".join(cmd) + "  (cwd=%s)" % cwd, file=sys.stderr)
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)

    stdout = (proc.stdout or "").strip()
    # cargo audit exits 1 when advisories are found; the JSON is still valid.
    if not stdout.startswith("{"):
        print("cargo audit produced no JSON (exit %d):" % proc.returncode,
              file=sys.stderr)
        sys.stderr.write(proc.stderr or stdout or "")
        return proc.returncode or 2

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(stdout + "\n")

    parser_args = [args.out, "-o", args.workunits]
    if args.no_warnings:
        parser_args.append("--no-warnings")
    rc = cargoaudit_to_workunits.main(parser_args)
    if rc != 0:
        return rc

    if proc.returncode != 0:
        print("cargo audit exit %d: advisories found (see %s / %s)"
              % (proc.returncode, args.out, args.workunits))
    else:
        print("cargo audit exit 0: no vulnerabilities (warnings may still "
              "be present in %s)" % args.workunits)
    return 0


if __name__ == "__main__":
    sys.exit(main())
