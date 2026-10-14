#!/usr/bin/env python3
"""Orchestrate CodeQL: database create -> analyze -> SARIF -> work-unit JSON.

Runs the `codeql` CLI (must be on PATH or given via --codeql), then parses the
resulting SARIF into a clean top-level JSON array of work units
(see codeql_sarif_to_workunits.py) suitable for rupu `read_file` + `for_each:`.

Examples:
    # interpreted language, no build
    python3 scripts/run_codeql.py --language python --source-root /src/example.com-app \
        --db /tmp/db-example --suite security-extended \
        --sarif results.sarif --output workunits.json

    # compiled language, traced build
    python3 scripts/run_codeql.py --language java --source-root /src/app \
        --db /tmp/db-java --command 'mvn clean package -DskipTests -B' \
        --suite security-extended --sarif java.sarif --output workunits.json

    # custom pack instead of a shipped suite
    python3 scripts/run_codeql.py --language python --source-root /src/app \
        --db /tmp/db --queries ./audit-queries --sarif custom.sarif

    # reuse an existing database
    python3 scripts/run_codeql.py --language go --db /tmp/db-go --skip-create \
        --suite security-extended --sarif go.sarif
"""

import argparse
import json
import os
import shlex
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from codeql_sarif_to_workunits import sarif_to_workunits  # noqa: E402

SUITES = {
    "code-scanning": None,  # pack default suite: just name the pack
    "security-extended": "codeql-suites/{lang}-security-extended.qls",
    "security-and-quality": "codeql-suites/{lang}-security-and-quality.qls",
}

INTERPRETED = {"python", "javascript", "ruby", "actions"}


def run(cmd, **kw):
    print("+ " + " ".join(shlex.quote(c) for c in cmd), file=sys.stderr)
    return subprocess.run(cmd, check=True, **kw)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:", 1)[1] if "Examples:" in __doc__ else None,
    )
    ap.add_argument("--codeql", default="codeql", help="codeql binary (default: codeql on PATH)")
    ap.add_argument("--language", required=True,
                    help="cpp|csharp|go|java|javascript|python|ruby|swift|actions")
    ap.add_argument("--source-root", help="checkout root (required unless --skip-create)")
    ap.add_argument("--db", required=True, help="database directory to create/use")
    ap.add_argument("--command", action="append", default=[],
                    help="build command to trace (compiled languages); repeatable")
    ap.add_argument("--suite", default="security-extended",
                    choices=sorted(SUITES), help="shipped suite (default: security-extended)")
    ap.add_argument("--queries", action="append", default=[],
                    help="extra/alternative query targets: .ql file, local pack dir, "
                         "or pack spec; repeatable. If given, replaces --suite.")
    ap.add_argument("--sarif", default="results.sarif", help="SARIF output path")
    ap.add_argument("--output", default="workunits.json", help="work-unit JSON array path")
    ap.add_argument("--sarif-category", help="run category (defaults to language)")
    ap.add_argument("--threads", default="0", help="threads for create+analyze (default 0=all)")
    ap.add_argument("--ram", help="RAM MB for the analyzer, e.g. 8192")
    ap.add_argument("--skip-create", action="store_true", help="reuse existing DB, skip create")
    ap.add_argument("--no-overwrite", action="store_true",
                    help="do not pass --overwrite to database create")
    ap.add_argument("--min-severity", type=float, default=None,
                    help="drop work units below this security-severity")
    args = ap.parse_args(argv)

    lang = args.language

    # ---- 1. database create -------------------------------------------------
    if not args.skip_create:
        if not args.source_root:
            ap.error("--source-root is required unless --skip-create")
        cmd = [args.codeql, "database", "create", args.db,
               "--language=" + lang,
               "--source-root=" + args.source_root,
               "--threads=" + args.threads]
        if not args.no_overwrite:
            cmd.append("--overwrite")
        for build in args.command:
            cmd.append("--command=" + build)
        if lang not in INTERPRETED and not args.command:
            print("note: compiled language %r with no --command -> autobuild; "
                  "if it fails, pass --command '<build cmd>'" % lang, file=sys.stderr)
        run(cmd)

    # ---- 2. database analyze ------------------------------------------------
    if args.queries:
        query_targets = list(args.queries)
    else:
        pack = "codeql/%s-queries" % lang
        suite_rel = SUITES[args.suite]
        query_targets = [pack if suite_rel is None
                         else "%s:%s" % (pack, suite_rel.format(lang=lang))]

    cmd = [args.codeql, "database", "analyze", args.db] + query_targets + [
        "--format=sarif-latest",
        "--output=" + args.sarif,
        "--sarif-category=" + (args.sarif_category or lang),
        "--threads=" + args.threads,
        "--download",
        "--sarif-add-snippets",
    ]
    if args.ram:
        cmd.append("--ram=" + args.ram)
    run(cmd)

    # ---- 3. SARIF -> work units ----------------------------------------------
    with open(args.sarif, "r", encoding="utf-8") as fh:
        sarif = json.load(fh)
    units = sarif_to_workunits(sarif)

    if args.min_severity is not None:
        def keep(u):
            try:
                return float(u["hints"].get("severity")) >= args.min_severity
            except (TypeError, ValueError):
                return True
        units = [u for u in units if keep(u)]

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")

    with_flows = sum(1 for u in units if u["hints"].get("codeflow_steps"))
    files = sorted({t.rsplit(":", 1)[0] for u in units for t in u["targets"]})
    print("db=%s sarif=%s" % (args.db, args.sarif), file=sys.stderr)
    print("wrote %d work units (%d with code flows) across %d files -> %s"
          % (len(units), with_flows, len(files), args.output), file=sys.stderr)
    print("next: assets.mark the repo + %d files; load `work-units` to split; "
          "route %s to `sarif-triage`; file verified issues via `finding-report`."
          % (len(files), args.sarif), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as e:
        print("codeql failed with exit code %d — check <db>/log/ for "
              "database-create logs if the create step failed" % e.returncode,
              file=sys.stderr)
        sys.exit(e.returncode)
