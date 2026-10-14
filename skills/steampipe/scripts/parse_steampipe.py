#!/usr/bin/env python3
"""Turn Steampipe query rows (from run_steampipe_queries.py, or any
`steampipe query --output json` output) into rupu work units and an asset list.

Writes:
  * work units: a BARE JSON array of {"id","title","targets","hints"} —
    targets are resource identifiers extracted from the rows (arn/id/name/endpoint
    columns); hints = {query_name, provider, columns, rows}
  * assets: every distinct target with its source query and provider

Examples:
  python3 scripts/parse_steampipe.py out/queries --out out/work-units.json --assets out/assets.json
  python3 scripts/parse_steampipe.py out/queries/aws_public_s3.json --max-targets 25
"""
import argparse
import glob
import json
import os
import re
import sys

# column names tried, in priority order, when picking a target identifier per row
TARGET_COLUMNS = [
    "arn", "resource", "instance_id", "group_id", "snapshot_id",
    "db_instance_identifier", "access_key_id", "name", "endpoint",
    "endpoint_address", "public_ip_address", "dns_name", "user_name",
    "account_name", "id", "title",
]


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "unit"


def load_inputs(path):
    """Yield (query_name, provider, rows) from a dir of files or a single file."""
    files = sorted(glob.glob(os.path.join(path, "*.json"))) if os.path.isdir(path) else [path]
    if not files:
        sys.exit(f"[-] no JSON files under {path}")
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] skipping {fp}: {exc}", file=sys.stderr)
            continue
        qname = os.path.splitext(os.path.basename(fp))[0]
        provider = qname.split("_", 1)[0]
        if isinstance(data, dict):  # run_steampipe_queries.py wrapper
            qname = data.get("query_name", qname)
            provider = data.get("provider", provider)
            rows = data.get("rows", [])
        elif isinstance(data, list):  # raw steampipe --output json array
            rows = data
        else:
            continue
        yield qname, provider, [r for r in rows if isinstance(r, dict)]


def pick_target(row):
    for col in TARGET_COLUMNS:
        val = row.get(col)
        if val not in (None, "", "null"):
            return str(val)
    for val in row.values():  # fallback: first scalar value
        if isinstance(val, (str, int)) and str(val):
            return str(val)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="directory of per-query JSON files, or one JSON file")
    ap.add_argument("--out", default="out/work-units.json",
                    help="work-units JSON array output (default out/work-units.json)")
    ap.add_argument("--assets", default="out/assets.json",
                    help="assets JSON output (default out/assets.json)")
    ap.add_argument("--max-targets", type=int, default=50,
                    help="split units with more than N targets into chunks (default 50)")
    ap.add_argument("--max-rows-in-hints", type=int, default=50,
                    help="cap raw rows embedded per unit's hints (default 50)")
    args = ap.parse_args()

    units, assets = [], {}
    for qname, provider, rows in load_inputs(args.input):
        if not rows:
            continue
        targets, by_target = [], {}
        for row in rows:
            tgt = pick_target(row)
            if not tgt:
                continue
            if tgt not in by_target:
                targets.append(tgt)
                by_target[tgt] = row
            assets.setdefault(tgt, {
                "resource": tgt,
                "provider": provider,
                "query_name": qname,
                "region": str(row.get("region") or row.get("location")
                              or row.get("resource_group") or "global"),
                "account": str(row.get("account_id") or row.get("subscription_id")
                               or row.get("project") or ""),
            })
        columns = sorted({k for r in rows for k in r})
        for i in range(0, len(targets), args.max_targets):
            chunk = targets[i:i + args.max_targets]
            suffix = f"-{i // args.max_targets + 1}" if len(targets) > args.max_targets else ""
            units.append({
                "id": f"steampipe-{slug(qname)}{suffix}",
                "title": f"{qname.replace('_', ' ')} "
                         f"({len(chunk)} resource{'s' if len(chunk) != 1 else ''})",
                "targets": chunk,
                "hints": {
                    "query_name": qname,
                    "provider": provider,
                    "columns": columns,
                    "rows": [by_target[t] for t in chunk[:args.max_rows_in_hints]],
                },
            })

    for path, payload in ((args.out, units),
                          (args.assets, sorted(assets.values(), key=lambda a: a["resource"]))):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    print(f"[+] {len(units)} work units -> {args.out}")
    print(f"[+] {len(assets)} assets -> {args.assets}")
    print("[+] feed into rupu per references/rupu.md; "
          "query follow-ups in references/queries.md")


if __name__ == "__main__":
    main()
