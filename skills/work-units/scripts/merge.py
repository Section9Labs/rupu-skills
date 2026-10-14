#!/usr/bin/env python3
"""merge.py -- merge two or more work-unit array files into one clean array.

Usage:
    python3 scripts/merge.py FILE [FILE ...] [-o OUT]

De-duplicates by unit id. Because split.py derives ids from the unit's
tool-agnostic identity (e.g. service|host|port|proto), the same service seen
by naabu, httpx, and nmap collapses into ONE unit here. Merge rules:

  * the first file to mention an id owns the unit's position and title
  * later units contribute any targets the earlier unit lacks (exact-object
    de-dup, nothing is duplicated)
  * later hints fill in missing keys; list-valued hints are unioned;
    conflicting scalar hints keep the earlier value

Output is exactly one JSON array (stdout or -o OUT); diagnostics go to stderr.
Stdlib only.
"""

import argparse
import json
import sys


def note(msg):
    sys.stderr.write("merge: %s\n" % msg)


def load_units(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        note("skipping %s: %s" % (path, exc))
        return []
    if not isinstance(data, list):
        note("skipping %s: not a JSON array" % path)
        return []
    units = []
    for i, u in enumerate(data):
        if isinstance(u, dict) and "id" in u:
            u.setdefault("title", u["id"])
            u.setdefault("targets", [])
            u.setdefault("hints", {})
            units.append(u)
        else:
            note("%s[%d]: not a work unit, skipped" % (path, i))
    return units


def merge_hints(base, extra):
    for k, v in extra.items():
        if k not in base:
            base[k] = v
        elif isinstance(base[k], list) and isinstance(v, list):
            for item in v:
                if item not in base[k]:
                    base[k].append(item)
        # conflicting scalars: earlier value wins
    return base


def merge_unit(kept, new):
    for t in new.get("targets", []):
        if t not in kept["targets"]:
            kept["targets"].append(t)
    merge_hints(kept["hints"], new.get("hints", {}))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="merge.py",
        description="Merge work-unit arrays, de-duplicating by id.")
    parser.add_argument("files", nargs="+", help="work-unit JSON array files")
    parser.add_argument("-o", "--out", default="-",
                        help="output file (default: stdout)")
    args = parser.parse_args(argv)

    by_id, order = {}, []
    total = 0
    for path in args.files:
        units = load_units(path)
        total += len(units)
        for u in units:
            uid = u["id"]
            if uid in by_id:
                merge_unit(by_id[uid], u)
            else:
                by_id[uid] = u
                order.append(uid)

    merged = [by_id[uid] for uid in order]
    text = json.dumps(merged, indent=2) + "\n"
    if args.out in (None, "-"):
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    note("merged %d units from %d files into %d unique units"
         % (total, len(args.files), len(merged)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
