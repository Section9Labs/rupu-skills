#!/usr/bin/env python3
"""Merge several sub-skills' work-units.json arrays into one deduplicated array.

Each input file must be a JSON array of work units:
    {"id": "...", "title": "...", "targets": [...], "hints": {...}}

Deduplication key: (title, sorted targets). When duplicates collide, their
hints dicts are merged (first writer wins per key, extras noted) and ids are
preserved from the first occurrence. Output is a bare JSON array (starts with
'['), suitable for rupu's `for_each:` file ingestion.

Usage:
    python3 scripts/merge_work_units.py out/prowler/work-units.json \
        out/cloudfox/work-units.json -o out/work-units.json
"""

import argparse
import json
import sys


def load_units(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[!] missing: {path} (skipped)", file=sys.stderr)
        return []
    except json.JSONDecodeError as exc:
        print(f"[!] bad JSON in {path}: {exc} (skipped)", file=sys.stderr)
        return []
    if not isinstance(data, list):
        print(f"[!] {path} is not a JSON array (skipped)", file=sys.stderr)
        return []
    units = []
    for i, u in enumerate(data):
        if not isinstance(u, dict):
            continue
        units.append({
            "id": str(u.get("id", f"{path}:{i}")),
            "title": str(u.get("title", "")).strip(),
            "targets": [str(t) for t in (u.get("targets") or [])],
            "hints": u.get("hints") if isinstance(u.get("hints"), dict) else {},
        })
    return units


def dedup_key(unit):
    return (unit["title"], tuple(sorted(unit["targets"])))


def main():
    ap = argparse.ArgumentParser(
        description="Merge and dedup work-units.json arrays from multiple "
                    "cloud-security sub-skills into one clean JSON array."
    )
    ap.add_argument("inputs", nargs="+",
                    help="input work-units.json files (JSON arrays)")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="output file (default: out/work-units.json); "
                         "use '-' for stdout")
    ap.add_argument("--prefix-ids", action="store_true",
                    help="prefix each unit id with its source file basename "
                         "to avoid id collisions")
    args = ap.parse_args()

    merged = {}
    order = []
    for path in args.inputs:
        for unit in load_units(path):
            if args.prefix_ids:
                base = path.rsplit("/", 1)[-1].replace(".json", "")
                unit["id"] = f"{base}:{unit['id']}"
            key = dedup_key(unit)
            if key in merged:
                existing = merged[key]
                for k, v in unit["hints"].items():
                    existing["hints"].setdefault(k, v)
                sources = existing["hints"].setdefault("merged_from", [])
                if isinstance(sources, list) and unit["id"] not in sources:
                    sources.append(unit["id"])
            else:
                merged[key] = unit
                order.append(key)

    out_units = [merged[k] for k in order]
    text = json.dumps(out_units, indent=2)

    if args.output == "-":
        print(text)
    else:
        import os
        d = os.path.dirname(args.output)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"[+] wrote {len(out_units)} units "
              f"(from {len(args.inputs)} files) -> {args.output}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
