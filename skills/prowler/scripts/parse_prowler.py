#!/usr/bin/env python3
"""Parse Prowler OCSF JSON into a rupu-ingestible work-units array.

Reads one or more *.ocsf.json files (or a directory of them), filters FAIL records,
keeps the exploitable ones (public exposure / privesc / pivot patterns, plus every
critical & high FAIL), groups them per check id, and writes:

  - work units: bare JSON array of {"id","title","targets","hints"}  (default
    out/work-units.json) — targets are resource UIDs/ARNs; hints carry severity,
    check_id, regions, provider, status, risk, exploit routing flag.
  - assets: bare JSON array of every failing resource (default out/assets.json).

Examples:
  python3 scripts/parse_prowler.py --input out/prowler/target-aws.ocsf.json
  python3 scripts/parse_prowler.py --input out/prowler --all-fails --min-severity low
"""
import argparse
import glob
import json
import os
import sys

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

# Check-id substrings that indicate a directly exploitable FAIL regardless of the
# severity prowler assigns. See references/checks-triage.md for the routing table.
EXPLOITABLE_PATTERNS = [
    "public", "internet", "anonymous", "allusers", "all_users", "world",
    "privilege_escalation", "administrative_privileges", "admin",
    "cross_account", "cross_service", "confused_deputy", "trust",
    "imdsv2", "metadata", "function_url", "unauthenticated", "unrestricted",
    "wildcard", "0_0_0_0", "exposed", "secrets", "default_service_account",
    "snapshot", "ami_public", "firewall", "ingress", "no_authentication",
]


def is_exploitable(check_id):
    cid = (check_id or "").lower()
    return any(pat in cid for pat in EXPLOITABLE_PATTERNS)


def load_records(path):
    files = []
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "*.ocsf.json"), recursive=True))
    else:
        files = [path]
    records = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = [data]
        records.extend(data)
        print("[*] %s: %d records" % (f, len(data)), file=sys.stderr)
    return records


def main():
    p = argparse.ArgumentParser(
        description="Split Prowler OCSF output into rupu work units.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--input", required=True, help="*.ocsf.json file or directory of them")
    p.add_argument("--out", default="out/work-units.json", help="work-units array output")
    p.add_argument("--assets-out", default="out/assets.json", help="assets array output")
    p.add_argument("--min-severity", default="low",
                   choices=["critical", "high", "medium", "low", "informational"],
                   help="drop FAILs below this severity (exploitable-pattern FAILs are "
                        "always kept)")
    p.add_argument("--all-fails", action="store_true",
                   help="keep every FAIL >= --min-severity, not only exploitable/crit/high")
    p.add_argument("--max-targets", type=int, default=200,
                   help="cap targets per work unit (total count kept in hints)")
    args = p.parse_args()

    records = load_records(args.input)
    min_rank = SEV_RANK[args.min_severity]

    units = {}          # check_id -> unit under construction
    assets = {}         # resource uid -> asset dict
    counts = {"total": len(records), "fail": 0, "kept": 0}

    for r in records:
        status = (r.get("status_code") or r.get("status") or "").upper()
        if status != "FAIL":
            continue
        counts["fail"] += 1

        sev = (r.get("severity") or "informational").lower()
        check_id = (r.get("metadata") or {}).get("event_code") or "unknown_check"
        finfo = r.get("finding_info") or {}
        cloud = r.get("cloud") or {}
        provider = (cloud.get("provider") or "").lower()
        account = (cloud.get("account") or {}).get("uid") or ""
        exploitable = is_exploitable(check_id)

        resources = r.get("resources") or []
        for res in resources:
            uid = res.get("uid") or res.get("name")
            if not uid:
                continue
            assets.setdefault(uid, {
                "uid": uid,
                "name": res.get("name") or "",
                "type": res.get("type") or "",
                "region": res.get("region") or "",
                "provider": provider,
                "account": account,
                "failed_checks": [],
            })
            if check_id not in assets[uid]["failed_checks"]:
                assets[uid]["failed_checks"].append(check_id)

        keep = exploitable or SEV_RANK.get(sev, 0) >= SEV_RANK["high"]
        if args.all_fails:
            keep = True
        if SEV_RANK.get(sev, 0) < min_rank and not exploitable:
            keep = False
        if not keep:
            continue
        counts["kept"] += 1

        u = units.setdefault(check_id, {
            "id": "prowler:%s" % check_id,
            "title": finfo.get("title") or check_id,
            "targets": [],
            "hints": {
                "severity": sev,
                "check_id": check_id,
                "provider": provider,
                "account": account,
                "status": "FAIL",
                "regions": [],
                "risk": (r.get("risk_details") or "")[:500],
                "remediation": ((r.get("remediation") or {}).get("desc") or "")[:300],
                "exploitable": exploitable,
                "status_detail_sample": (r.get("status_detail") or "")[:300],
                "finding_uids": [],
                "count": 0,
            },
        })
        # escalate severity if a later record of the same check is worse
        if SEV_RANK.get(sev, 0) > SEV_RANK.get(u["hints"]["severity"], 0):
            u["hints"]["severity"] = sev
        u["hints"]["count"] += 1
        if finfo.get("uid") and len(u["hints"]["finding_uids"]) < 20:
            u["hints"]["finding_uids"].append(finfo["uid"])
        for res in resources:
            uid = res.get("uid") or res.get("name")
            if uid and uid not in u["targets"] and len(u["targets"]) < args.max_targets:
                u["targets"].append(uid)
            region = res.get("region")
            if region and region not in u["hints"]["regions"]:
                u["hints"]["regions"].append(region)

    unit_list = sorted(
        units.values(),
        key=lambda x: (-SEV_RANK.get(x["hints"]["severity"], 0),
                       not x["hints"]["exploitable"],
                       x["id"]))

    for path, payload in ((args.out, unit_list), (args.assets_out, list(assets.values()))):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)   # bare array — rupu for_each ingests this

    print("[+] records=%(total)d fail=%(fail)d kept=%(kept)d" % counts, file=sys.stderr)
    print("[+] %d work units -> %s" % (len(unit_list), args.out), file=sys.stderr)
    print("[+] %d assets     -> %s" % (len(assets), args.assets_out), file=sys.stderr)
    for u in unit_list[:15]:
        print("    [%s/%s] %s (%d targets)" % (
            u["hints"]["severity"], "EXPLOITABLE" if u["hints"]["exploitable"] else "review",
            u["id"], len(u["targets"])), file=sys.stderr)


if __name__ == "__main__":
    main()
