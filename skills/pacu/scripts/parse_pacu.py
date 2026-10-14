#!/usr/bin/env python3
"""parse_pacu.py - turn a Pacu session (sqlite DB) and/or an iam__privesc_scan
log into rupu work units.

Reads:
  * --db        Pacu's sqlite DB (default ~/.local/share/pacu/sqlite.db),
                table pacu_session: per-service JSON columns (IAM, EC2, Lambda,
                S3, SecretsManager/Secrets, SSM, ...)
  * --privesc-log  captured stdout of `run iam__privesc_scan [--scan-only]`

Writes:
  * --output    bare JSON array of work units {"id","title","targets","hints"}
                (one per CONFIRMED/POTENTIAL privesc method, one per loot target)
  * --assets    JSON list of assets for coverage-assets / assets.mark

Examples:
  python3 scripts/parse_pacu.py --session s1
  python3 scripts/parse_pacu.py --privesc-log out/privesc_scan.txt -o out/work-units.json
"""
import argparse
import json
import os
import re
import sqlite3
import sys

DEFAULT_DB = os.path.expanduser("~/.local/share/pacu/sqlite.db")

PRIVESC_LINE_RE = re.compile(r"(CONFIRMED|POTENTIAL)", re.IGNORECASE)
METHOD_TOKEN_RE = re.compile(r"\b([A-Z][A-Za-z0-9]{3,}(?:[A-Z][a-z0-9]+)+)\b")
USER_CTX_RE = re.compile(r"(arn:aws:iam::\d{12}:(?:user|role)/[\w+=,.@/-]+)")

# service-column key -> (item list key(s), id field candidates, unit kind)
LOOT_MAP = {
    "EC2": [("Instances", ["InstanceId"], "EC2 instance (user-data/metadata creds)",
             "run ec2__download_userdata")],
    "Lambda": [("Functions", ["FunctionArn", "FunctionName"], "Lambda function (env vars/code)",
                "run lambda__enum  # inspect Environment + download code")],
    "S3": [("Buckets", ["Name"], "S3 bucket", "run s3__download_bucket --names <name>")],
    "SecretsManager": [("Secrets", ["ARN", "Name"], "Secrets Manager secret", "run secrets__enum")],
    "Secrets": [("Secrets", ["ARN", "Name"], "Secrets Manager secret", "run secrets__enum")],
    "SSM": [("Parameters", ["Name"], "SSM parameter", "run systemsmanager__download_parameters")],
    "IAM": [("Users", ["Arn", "UserName"], "IAM user", "run iam__enum_permissions --all-users"),
            ("Roles", ["Arn", "RoleName"], "IAM role", "run iam__enum_permissions --role-name <name>")],
}


def pick(d, fields):
    for f in fields:
        v = d.get(f)
        if v:
            return str(v)
    return None


def walk_items(obj, list_key):
    """Find all dicts under any occurrence of list_key, at any nesting depth
    (Pacu sometimes nests per-region)."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == list_key and isinstance(v, list):
                out.extend(x for x in v if isinstance(x, dict))
            else:
                out.extend(walk_items(v, list_key))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(walk_items(v, list_key))
    return out


def parse_db(db_path, session_name):
    """Return (loot_units_raw, assets) from the pacu_session table."""
    units, assets = [], []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM pacu_session")
    except sqlite3.OperationalError as e:
        sys.exit("[!] cannot read pacu_session table: %s" % e)
    rows = cur.fetchall()
    if not rows:
        sys.exit("[!] no sessions in %s" % db_path)
    row = None
    if session_name:
        for r in rows:
            if r["name"] == session_name:
                row = r
                break
        if row is None:
            sys.exit("[!] session %r not found; have: %s"
                     % (session_name, ", ".join(r["name"] for r in rows)))
    else:
        row = rows[-1]  # most recent
    for col in row.keys():
        val = row[col]
        if not isinstance(val, str) or not val.strip().startswith(("{", "[")):
            continue
        try:
            data = json.loads(val)
        except (json.JSONDecodeError, ValueError):
            continue
        for list_key, id_fields, kind, exploit in LOOT_MAP.get(col, []):
            for item in walk_items(data, list_key):
                ident = pick(item, id_fields)
                if not ident:
                    continue
                region = str(item.get("Region", item.get("region", "")))
                units.append({"kind": "loot", "service": col, "target": ident,
                              "desc": kind, "exploit": exploit, "region": region})
                assets.append({"asset": ident, "kind": _asset_kind(col),
                               "attrs": {"service": col, "region": region,
                                         "source": "pacu:%s" % row["name"]}})
    conn.close()
    return units, assets


def _asset_kind(service):
    return {"EC2": "compute", "Lambda": "compute", "S3": "storage",
            "SSM": "secret", "SecretsManager": "secret", "Secrets": "secret",
            "IAM": "principal"}.get(service, "asset")


def parse_privesc_log(path):
    """Return [(confidence, method, context_arn)] from iam__privesc_scan output."""
    results, seen = [], set()
    current_ctx = ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = USER_CTX_RE.search(line)
            if m:
                current_ctx = m.group(1)
            cm = PRIVESC_LINE_RE.search(line)
            if not cm:
                continue
            confidence = cm.group(1).lower()
            tail = line[cm.end():]
            for method in METHOD_TOKEN_RE.findall(tail):
                key = (confidence, method, current_ctx)
                if key not in seen:
                    seen.add(key)
                    results.append(key)
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB,
                    help="Pacu sqlite DB (default: %(default)s)")
    ap.add_argument("--session", help="session name (default: most recent)")
    ap.add_argument("--no-db", action="store_true", help="skip the DB, log only")
    ap.add_argument("--privesc-log", help="captured iam__privesc_scan stdout")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units array (default: %(default)s)")
    ap.add_argument("--assets", default="out/assets.json",
                    help="assets list (default: %(default)s)")
    args = ap.parse_args()

    units, assets, n = [], [], 0

    if args.privesc_log:
        for confidence, method, ctx in parse_privesc_log(args.privesc_log):
            n += 1
            units.append({
                "id": "pacu-%04d" % n,
                "title": "%s privesc: %s" % (confidence.upper(), method),
                "targets": [ctx] if ctx else [],
                "hints": {"kind": "privesc", "method": method,
                          "confidence": confidence,
                          "exploit": "run iam__privesc_scan --method %s" % method,
                          "source": "pacu iam__privesc_scan"},
            })

    if not args.no_db:
        if os.path.exists(args.db):
            loot, assets = parse_db(args.db, args.session)
            for l in loot:
                n += 1
                units.append({
                    "id": "pacu-%04d" % n,
                    "title": "loot: %s %s" % (l["desc"], l["target"]),
                    "targets": [l["target"]],
                    "hints": {"kind": "loot", "service": l["service"],
                              "region": l["region"], "exploit": l["exploit"],
                              "source": "pacu session db"},
                })
        elif not args.privesc_log:
            sys.exit("[!] DB not found at %s and no --privesc-log given" % args.db)

    # confirmed privesc first, then potential, then loot
    order = {"confirmed": 0, "potential": 1}
    units.sort(key=lambda u: order.get(u["hints"].get("confidence", ""), 2))

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
    os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
    with open(args.assets, "w", encoding="utf-8") as fh:
        json.dump(assets, fh, indent=2)
    sys.stderr.write("[+] %d work units -> %s | %d assets -> %s\n"
                     % (len(units), args.output, len(assets), args.assets))


if __name__ == "__main__":
    main()
