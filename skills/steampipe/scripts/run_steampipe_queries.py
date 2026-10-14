#!/usr/bin/env python3
"""Run bundled attack-surface .sql queries through `steampipe query --output json`
and save one JSON rows file per query.

Query files live in scripts/queries/ and are named <provider>_<name>.sql
(provider = aws | azure | gcp). Rows for each query go to <out-dir>/<query_name>.json.

Examples:
  python3 scripts/run_steampipe_queries.py
  python3 scripts/run_steampipe_queries.py --provider aws --out-dir out/queries
  python3 scripts/run_steampipe_queries.py --query aws_public_s3 --query aws_open_sgs
  python3 scripts/run_steampipe_queries.py --search-path-prefix aws_all
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys


def discover(queries_dir, providers, names):
    files = sorted(glob.glob(os.path.join(queries_dir, "*.sql")))
    picked = []
    for path in files:
        qname = os.path.splitext(os.path.basename(path))[0]
        provider = qname.split("_", 1)[0]
        if providers and provider not in providers:
            continue
        if names and qname not in names:
            continue
        picked.append((qname, provider, path))
    return picked


def run_query(steampipe, sql_file, search_path_prefix, timeout):
    cmd = [steampipe, "query", sql_file, "--output", "json"]
    if search_path_prefix:
        cmd += ["--search-path-prefix", search_path_prefix]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout).strip()
    out = proc.stdout.strip()
    if not out:
        return [], None
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return None, f"bad JSON from steampipe: {exc}"
    # steampipe >=0.21 wraps rows as {"rows": [...], ...}; older emits a bare array
    if isinstance(data, dict):
        data = data.get("rows", [])
    return data, None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--queries-dir",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "queries"),
                    help="directory of .sql files (default: scripts/queries next to this script)")
    ap.add_argument("--out-dir", default="out/queries",
                    help="directory for per-query JSON rows (default out/queries)")
    ap.add_argument("--provider", nargs="*", choices=["aws", "azure", "gcp"],
                    help="only run queries for these providers (default: all)")
    ap.add_argument("--query", action="append",
                    help="run only this query name (repeatable), e.g. aws_public_s3")
    ap.add_argument("--search-path-prefix",
                    help="steampipe --search-path-prefix, e.g. an aggregator like aws_all")
    ap.add_argument("--steampipe", default="steampipe", help="steampipe binary path")
    ap.add_argument("--timeout", type=int, default=600, help="per-query timeout seconds")
    args = ap.parse_args()

    steampipe = shutil.which(args.steampipe)
    if not steampipe:
        sys.exit(f"[-] steampipe binary not found: {args.steampipe}")

    queries = discover(args.queries_dir, set(args.provider or []), set(args.query or []))
    if not queries:
        sys.exit(f"[-] no matching .sql files in {args.queries_dir}")
    os.makedirs(args.out_dir, exist_ok=True)

    total_rows, failures = 0, []
    for qname, provider, path in queries:
        print(f"[*] {qname} ({provider}) ...", end=" ", flush=True)
        try:
            rows, err = run_query(steampipe, path, args.search_path_prefix, args.timeout)
        except subprocess.TimeoutExpired:
            rows, err = None, f"timeout after {args.timeout}s"
        if rows is None:
            print("ERROR")
            print(f"    {err}", file=sys.stderr)
            failures.append(qname)
            continue
        out_path = os.path.join(args.out_dir, f"{qname}.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump({"query_name": qname, "provider": provider,
                       "sql_file": path, "rows": rows}, fh, indent=2, default=str)
        total_rows += len(rows)
        print(f"{len(rows)} rows -> {out_path}")

    print(f"[+] done: {len(queries) - len(failures)}/{len(queries)} queries, "
          f"{total_rows} total rows in {args.out_dir}")
    if failures:
        print(f"[!] failed: {', '.join(failures)} "
              "(check plugin install, creds, and connection names)", file=sys.stderr)
    print(f"[+] next: python3 scripts/parse_steampipe.py {args.out_dir} "
          "--out out/work-units.json --assets out/assets.json")


if __name__ == "__main__":
    main()
