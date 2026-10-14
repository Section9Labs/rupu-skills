#!/usr/bin/env python3
"""az_enum.py - Azure resource-plane sweep via the az CLI.

Runs `az ... -o json` across all (or selected) subscriptions and services and
writes a single normalized inventory JSON. Python 3 stdlib only.

Examples:
  python3 scripts/az_enum.py --all-subscriptions -o out/az-inventory.json
  python3 scripts/az_enum.py --subscription 00000000-0000-0000-0000-000000000001 \
      --services vm,storage,keyvault -o out/az-inventory.json
  python3 scripts/az_enum.py --all-subscriptions --deep -o out/az-inventory.json
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

ALL_SERVICES = [
    "resources", "roles", "vm", "storage", "keyvault", "webapp",
    "functionapp", "sql", "cosmosdb", "aks", "acr", "network",
    "automation", "identity", "deployments",
]


def run_az(args, timeout=180):
    """Run an az command, return parsed JSON (or None on failure)."""
    cmd = ["az"] + args + ["-o", "json", "--only-show-errors"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] {' '.join(cmd)}: {e}", file=sys.stderr)
        return None
    if p.returncode != 0:
        err = (p.stderr or "").strip().splitlines()
        print(f"[!] az {' '.join(args[:4])}... -> {err[0] if err else 'error'}",
              file=sys.stderr)
        return None
    out = p.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out}


def get_subscriptions(explicit):
    if explicit:
        return [{"id": s, "name": s} for s in explicit]
    subs = run_az(["account", "list", "--all"]) or []
    return [{"id": s["id"], "name": s.get("name", ""),
             "tenantId": s.get("tenantId", ""), "state": s.get("state", "")}
            for s in subs]


def enum_subscription(sub_id, services, deep):
    """Enumerate one subscription. Returns dict of service -> data."""
    S = ["--subscription", sub_id]
    inv = {}

    def grab(key, args):
        print(f"    [*] {key}", file=sys.stderr)
        data = run_az(args + S)
        if data is not None:
            inv[key] = data

    if "resources" in services:
        grab("resources", ["resource", "list"])
        grab("resource_groups", ["group", "list"])
    if "roles" in services:
        grab("role_assignments", ["role", "assignment", "list", "--all"])
        grab("custom_roles", ["role", "definition", "list",
                              "--custom-role-only", "true"])
    if "vm" in services:
        grab("vms", ["vm", "list", "-d"])
        grab("vmss", ["vmss", "list"])
        grab("disks", ["disk", "list"])
    if "storage" in services:
        grab("storage_accounts", ["storage", "account", "list"])
        if deep:
            for acct in inv.get("storage_accounts") or []:
                keys = run_az(["storage", "account", "keys", "list",
                               "-n", acct["name"], "-g", acct["resourceGroup"]] + S)
                if keys:
                    acct["_keys"] = keys
    if "keyvault" in services:
        grab("keyvaults", ["keyvault", "list"])
        if deep:
            for kv in inv.get("keyvaults") or []:
                secrets = run_az(["keyvault", "secret", "list",
                                  "--vault-name", kv["name"]])
                if secrets is not None:
                    kv["_secrets"] = secrets
    if "webapp" in services:
        grab("webapps", ["webapp", "list"])
        if deep:
            for app in inv.get("webapps") or []:
                st = run_az(["webapp", "config", "appsettings", "list",
                             "-n", app["name"], "-g", app["resourceGroup"]] + S)
                if st is not None:
                    app["_appsettings"] = st
    if "functionapp" in services:
        grab("functionapps", ["functionapp", "list"])
        if deep:
            for fn in inv.get("functionapps") or []:
                st = run_az(["functionapp", "config", "appsettings", "list",
                             "-n", fn["name"], "-g", fn["resourceGroup"]] + S)
                if st is not None:
                    fn["_appsettings"] = st
    if "sql" in services:
        grab("sql_servers", ["sql", "server", "list"])
    if "cosmosdb" in services:
        grab("cosmosdb", ["cosmosdb", "list"])
    if "aks" in services:
        grab("aks", ["aks", "list"])
    if "acr" in services:
        grab("acr", ["acr", "list"])
    if "network" in services:
        grab("public_ips", ["network", "public-ip", "list"])
        grab("nsgs", ["network", "nsg", "list"])
        grab("load_balancers", ["network", "lb", "list"])
    if "automation" in services:
        grab("automation_accounts", ["automation", "account", "list"])
    if "identity" in services:
        grab("managed_identities", ["identity", "list"])
    if "deployments" in services and deep:
        for rg in inv.get("resource_groups") or []:
            deps = run_az(["deployment", "group", "list", "-g", rg["name"]] + S)
            if deps:
                inv.setdefault("deployments", []).extend(deps)
    return inv


def main():
    ap = argparse.ArgumentParser(
        description="Azure resource-plane sweep via az CLI -> inventory JSON")
    ap.add_argument("--all-subscriptions", action="store_true",
                    help="enumerate every subscription from `az account list --all`")
    ap.add_argument("--subscription", action="append", default=[],
                    help="subscription id (repeatable)")
    ap.add_argument("--services", default=",".join(ALL_SERVICES),
                    help=f"comma list of services (default: all = {','.join(ALL_SERVICES)})")
    ap.add_argument("--deep", action="store_true",
                    help="also pull storage keys, KV secret lists, app settings, deployments")
    ap.add_argument("-o", "--output", default="out/az-inventory.json",
                    help="inventory output path (default out/az-inventory.json)")
    args = ap.parse_args()

    if not shutil.which("az"):
        sys.exit("[!] az CLI not found in PATH")
    if not args.all_subscriptions and not args.subscription:
        sys.exit("[!] pass --all-subscriptions or --subscription <id>")

    services = [s.strip() for s in args.services.split(",") if s.strip()]
    account = run_az(["account", "show"])
    subs = get_subscriptions(args.subscription if not args.all_subscriptions else None)
    print(f"[*] identity: {json.dumps((account or {}).get('user', {}))}", file=sys.stderr)
    print(f"[*] {len(subs)} subscription(s)", file=sys.stderr)

    inventory = {"identity": account, "subscriptions": []}
    for sub in subs:
        print(f"[*] subscription {sub['id']} ({sub.get('name','')})", file=sys.stderr)
        data = enum_subscription(sub["id"], services, args.deep)
        inventory["subscriptions"].append({"subscription": sub, "inventory": data})

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(inventory, f, indent=2, default=str)
    total = sum(len(v) if isinstance(v, list) else 1
                for s in inventory["subscriptions"]
                for v in s["inventory"].values())
    print(f"[+] wrote {args.output} ({total} inventory entries across "
          f"{len(subs)} subscription(s))")
    print("[+] next: python3 scripts/az_to_work_units.py "
          f"{args.output} -o out/work-units.json --assets out/assets.json")


if __name__ == "__main__":
    main()
