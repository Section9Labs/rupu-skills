#!/usr/bin/env python3
"""Split CloudSploit JSON results into rupu work units and an asset list.

Reads the --json output of index.js, keeps FAIL (and optionally WARN) results,
groups them by plugin, and writes:
  * work units: a BARE JSON array of {"id","title","targets","hints"} objects
    (targets = failing resource ARNs/IDs; hints = plugin/category/region/status/message)
  * assets: every distinct resource seen across ALL results, for coverage marking

Examples:
  python3 scripts/parse_cloudsploit.py out/cloudsploit.json \
      --out out/work-units.json --assets out/assets.json
  python3 scripts/parse_cloudsploit.py out/cloudsploit.json --include-warn --max-targets 25
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

FAIL_STATUSES = {"FAIL", "2", 2}
WARN_STATUSES = {"WARN", "1", 1}


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "unit"


def load_results(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        sys.exit(f"[-] {path} is not a JSON array of CloudSploit results")
    return data


def resource_of(result):
    res = result.get("resource")
    if not res or res in ("N/A", "unknown", "null"):
        return None
    return str(res)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", help="CloudSploit --json results file")
    ap.add_argument("--out", default="out/work-units.json",
                    help="work-units JSON array output (default out/work-units.json)")
    ap.add_argument("--assets", default="out/assets.json",
                    help="assets JSON output (default out/assets.json)")
    ap.add_argument("--include-warn", action="store_true",
                    help="also turn WARN results into work units")
    ap.add_argument("--category", action="append",
                    help="only include these categories (repeatable, e.g. --category S3)")
    ap.add_argument("--max-targets", type=int, default=50,
                    help="split units with more than N targets into chunks (default 50)")
    args = ap.parse_args()

    results = load_results(args.results)
    wanted = set(FAIL_STATUSES) | (set(WARN_STATUSES) if args.include_warn else set())
    cats = {c.lower() for c in args.category} if args.category else None

    # group failing results by plugin
    groups = defaultdict(list)
    assets = {}
    for r in results:
        res = resource_of(r)
        if res:
            assets.setdefault(res, {
                "resource": res,
                "category": r.get("category", ""),
                "region": r.get("region", "global") or "global",
                "worst_status": str(r.get("status", "")),
            })
            if str(r.get("status")) in ("FAIL", "2"):
                assets[res]["worst_status"] = "FAIL"
        status = r.get("status")
        if status not in wanted and str(status) not in {str(s) for s in wanted}:
            continue
        if cats and str(r.get("category", "")).lower() not in cats:
            continue
        groups[r.get("plugin", "unknown")].append(r)

    units = []
    for plugin, rows in sorted(groups.items()):
        first = rows[0]
        # dedupe targets, keep per-target messages in hints
        targets, messages, regions = [], {}, set()
        for r in rows:
            res = resource_of(r) or f"region:{r.get('region', 'global')}"
            if res not in targets:
                targets.append(res)
            messages.setdefault(res, r.get("message", ""))
            regions.add(r.get("region", "global") or "global")
        for i in range(0, len(targets), args.max_targets):
            chunk = targets[i:i + args.max_targets]
            suffix = f"-{i // args.max_targets + 1}" if len(targets) > args.max_targets else ""
            units.append({
                "id": f"cloudsploit-{slug(plugin)}{suffix}",
                "title": f"{first.get('title', plugin)} "
                         f"({len(chunk)} resource{'s' if len(chunk) != 1 else ''})",
                "targets": chunk,
                "hints": {
                    "plugin": plugin,
                    "category": first.get("category", ""),
                    "region": ",".join(sorted(regions)),
                    "status": "FAIL" if any(str(r.get("status")) in ("FAIL", "2")
                                            for r in rows) else "WARN",
                    "message": first.get("message", ""),
                    "description": first.get("description", ""),
                    "per_target_messages": {t: messages.get(t, "") for t in chunk},
                },
            })

    for path, payload in ((args.out, units), (args.assets, sorted(assets.values(),
                                                                  key=lambda a: a["resource"]))):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    print(f"[+] {len(units)} work units -> {args.out}")
    print(f"[+] {len(assets)} assets -> {args.assets}")
    print("[+] feed into rupu per references/rupu.md; triage per references/plugins-triage.md")


if __name__ == "__main__":
    main()
