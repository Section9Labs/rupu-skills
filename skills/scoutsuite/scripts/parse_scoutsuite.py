#!/usr/bin/env python3
"""Parse ScoutSuite results into a rupu-ingestible work-units array.

Reads a scoutsuite_results_*.js file (or a report dir containing one), strips the
leading `scoutsuite_results =` JS assignment, walks every finding with
level == danger plus keyword-matched high-value warnings, truncates each flagged
item path to resource depth, and writes:

  - work units: bare JSON array of {"id","title","targets","hints"} (default
    out/work-units.json) — targets are flagged item paths / resource ids; hints
    carry service, finding_id, level, description, rationale, counts.
  - assets: bare JSON array of flagged resources (default out/assets.json).

Examples:
  python3 scripts/parse_scoutsuite.py --input out/scout
  python3 scripts/parse_scoutsuite.py \
      --input out/scout/scoutsuite-results/scoutsuite_results_aws-target.js \
      --all-warnings
"""
import argparse
import glob
import json
import os
import sys

# Warnings whose id or description matches these are kept by default: they tend to
# be directly exploitable even though the ruleset only rates them "warning".
HIGH_VALUE_KEYWORDS = [
    "public", "internet", "0.0.0.0", "::/0", "world", "anonymous", "all users",
    "allusers", "all_users", "wildcard", "star", "*:*", "privilege", "admin",
    "cross-account", "cross_account", "unencrypted", "secret", "metadata",
    "unauthenticated", "default service account", "open to all",
]

LEVEL_RANK = {"danger": 2, "warning": 1}


def find_results(path):
    if os.path.isfile(path):
        return path
    pats = [
        os.path.join(path, "scoutsuite-results", "scoutsuite_results_*.js"),
        os.path.join(path, "**", "scoutsuite_results_*.js"),
    ]
    candidates = []
    for pat in pats:
        candidates += glob.glob(pat, recursive=True)
    if not candidates:
        return None
    return max(set(candidates), key=os.path.getmtime)


def load_results(js_path):
    with open(js_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    # File is `scoutsuite_results =\n{...}` — strip through the first '='.
    eq = raw.find("=")
    payload = raw[eq + 1:].strip() if eq != -1 else raw.strip()
    return json.loads(payload)


def is_high_value(finding_id, finding):
    blob = " ".join([
        finding_id,
        str(finding.get("description") or ""),
        str(finding.get("rationale") or ""),
    ]).lower()
    return any(kw in blob for kw in HIGH_VALUE_KEYWORDS)


def trim_to_resource(item_path, pattern):
    """Truncate a flagged item path to the depth of the finding's resource-level
    path pattern (display_path/path, e.g. 's3.buckets.id')."""
    if not isinstance(item_path, str):
        return str(item_path)
    if not pattern:
        return item_path
    depth = len(pattern.split("."))
    return ".".join(item_path.split(".")[:depth])


def main():
    p = argparse.ArgumentParser(
        description="Split ScoutSuite results into rupu work units.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--input", required=True,
                   help="scoutsuite_results_*.js file or report dir containing one")
    p.add_argument("--out", default="out/work-units.json", help="work-units array output")
    p.add_argument("--assets-out", default="out/assets.json", help="assets array output")
    p.add_argument("--all-warnings", action="store_true",
                   help="keep every warning, not only keyword-matched high-value ones")
    p.add_argument("--dangers-only", action="store_true",
                   help="keep only level==danger findings")
    p.add_argument("--max-targets", type=int, default=200,
                   help="cap targets per work unit (total kept in hints.flagged_items)")
    args = p.parse_args()

    js_path = find_results(args.input)
    if not js_path:
        print("[!] no scoutsuite_results_*.js found under %s" % args.input, file=sys.stderr)
        sys.exit(1)
    print("[*] parsing %s" % js_path, file=sys.stderr)
    data = load_results(js_path)

    provider = data.get("provider_code") or data.get("provider_name") or ""
    account = str(data.get("account_id") or data.get("aws_account_id") or "")
    summary = (data.get("last_run") or {}).get("summary") or {}

    units = []
    assets = {}
    counts = {"findings": 0, "kept": 0}

    for svc, sdata in (data.get("services") or {}).items():
        if not isinstance(sdata, dict):
            continue
        for fid, f in (sdata.get("findings") or {}).items():
            if not isinstance(f, dict):
                continue
            flagged = f.get("flagged_items") or 0
            items = f.get("items") or []
            if flagged == 0 or not items:
                continue
            counts["findings"] += 1

            level = (f.get("level") or "warning").lower()
            if level != "danger":
                if args.dangers_only:
                    continue
                if not args.all_warnings and not is_high_value(fid, f):
                    continue
            counts["kept"] += 1

            pattern = f.get("display_path") or f.get("path") or ""
            targets = []
            for item in items:
                res = trim_to_resource(item, pattern)
                if res not in targets and len(targets) < args.max_targets:
                    targets.append(res)
                assets.setdefault(res, {
                    "id": res,
                    "service": svc,
                    "provider": provider,
                    "account": account,
                    "findings": [],
                })
                key = "%s.%s" % (svc, fid)
                if key not in assets[res]["findings"]:
                    assets[res]["findings"].append(key)

            units.append({
                "id": "scoutsuite:%s.%s" % (svc, fid),
                "title": (f.get("description") or fid).strip(),
                "targets": targets,
                "hints": {
                    "service": svc,
                    "finding_id": fid,
                    "level": level,
                    "description": (f.get("description") or "")[:300],
                    "rationale": (f.get("rationale") or "")[:500],
                    "remediation": (f.get("remediation") or "")[:300],
                    "flagged_items": flagged,
                    "checked_items": f.get("checked_items") or 0,
                    "resource_path": pattern,
                    "provider": provider,
                    "account": account,
                    "sample_item_paths": [i for i in items[:5] if isinstance(i, str)],
                },
            })

    units.sort(key=lambda u: (-LEVEL_RANK.get(u["hints"]["level"], 0),
                              -u["hints"]["flagged_items"], u["id"]))

    for path, payload in ((args.out, units), (args.assets_out, list(assets.values()))):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)   # bare array — rupu for_each ingests this

    print("[+] account=%s provider=%s" % (account, provider), file=sys.stderr)
    if summary:
        tot = sum((v or {}).get("flagged_items", 0) for v in summary.values()
                  if isinstance(v, dict))
        print("[+] last_run summary: %d flagged items across %d services"
              % (tot, len(summary)), file=sys.stderr)
    print("[+] findings with flags=%(findings)d kept=%(kept)d" % counts, file=sys.stderr)
    print("[+] %d work units -> %s" % (len(units), args.out), file=sys.stderr)
    print("[+] %d assets     -> %s" % (len(assets), args.assets_out), file=sys.stderr)
    for u in units[:15]:
        print("    [%s] %s (%d targets)" % (u["hints"]["level"], u["id"],
                                            len(u["targets"])), file=sys.stderr)


if __name__ == "__main__":
    main()
