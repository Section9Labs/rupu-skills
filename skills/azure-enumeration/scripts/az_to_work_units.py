#!/usr/bin/env python3
"""az_to_work_units.py - convert az_enum.py inventory into rupu work units.

Reads the inventory JSON from scripts/az_enum.py and writes:
  - a BARE JSON ARRAY of work units {"id","title","targets","hints"} (rupu
    for_each-compatible: file content starts with '['), and
  - optionally an assets list {"kind","id","attrs"} for coverage-assets.

Unit kinds: public_endpoint, storage, keyvault, vm_runcommand, webapp,
functionapp, role_assignment, aks, acr, cosmosdb, sql, automation.

Example:
  python3 scripts/az_to_work_units.py out/az-inventory.json \
      -o out/work-units.json --assets out/assets.json
"""
import argparse
import json
import os
import sys

PRIV_ROLES = {
    "Owner", "Contributor", "User Access Administrator",
    "Virtual Machine Contributor", "Key Vault Administrator",
    "Storage Account Contributor", "Automation Contributor",
    "Azure Kubernetes Service Cluster Admin Role",
}


def unit(uid, title, targets, hints):
    return {"id": uid, "title": title,
            "targets": sorted(set(t for t in targets if t)), "hints": hints}


def main():
    ap = argparse.ArgumentParser(
        description="az inventory -> rupu work-units JSON array + assets")
    ap.add_argument("inventory", help="output of scripts/az_enum.py")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units array path (default out/work-units.json)")
    ap.add_argument("--assets", help="also write assets list JSON here")
    args = ap.parse_args()

    with open(args.inventory) as f:
        inv = json.load(f)

    units, assets, n = [], [], 0

    def nid(prefix):
        nonlocal n
        n += 1
        return f"az-{prefix}-{n:04d}"

    for entry in inv.get("subscriptions", []):
        sub = entry["subscription"]["id"]
        data = entry.get("inventory", {})
        assets.append({"kind": "cloud-account", "id": f"azure:sub:{sub}",
                       "attrs": {"name": entry["subscription"].get("name", "")}})

        # Public IPs -> public_endpoint units
        for pip in data.get("public_ips") or []:
            ip = pip.get("ipAddress")
            if not ip:
                continue
            assets.append({"kind": "public-endpoint", "id": f"ip:{ip}",
                           "attrs": {"subscription": sub, "name": pip.get("name", "")}})
            units.append(unit(nid("pub"), f"Public IP {ip} ({pip.get('name','')})",
                              [ip],
                              {"kind": "public_endpoint", "subscription": sub,
                               "resource_id": pip.get("id", ""),
                               "handoff": "network attack surface / metadata-ssrf-pivot"}))

        # Storage accounts
        for sa in data.get("storage_accounts") or []:
            name = sa.get("name", "")
            blob_ep = (sa.get("primaryEndpoints") or {}).get("blob", "")
            assets.append({"kind": "storage-account", "id": f"azure:storage:{name}",
                           "attrs": {"subscription": sub,
                                     "publicBlobAccess": str(sa.get("allowBlobPublicAccess"))}})
            units.append(unit(nid("sa"), f"Storage account {name}",
                              [name, blob_ep],
                              {"kind": "storage", "subscription": sub,
                               "resource_group": sa.get("resourceGroup", ""),
                               "allow_blob_public_access": bool(sa.get("allowBlobPublicAccess")),
                               "keys_retrieved": bool(sa.get("_keys")),
                               "handoff": "cloud-storage-exposure"}))

        # Key Vaults
        for kv in data.get("keyvaults") or []:
            name = kv.get("name", "")
            uri = f"https://{name}.vault.azure.net/"
            assets.append({"kind": "secret-store", "id": f"azure:kv:{name}",
                           "attrs": {"subscription": sub}})
            units.append(unit(nid("kv"), f"Key Vault {name}",
                              [name, uri],
                              {"kind": "keyvault", "subscription": sub,
                               "secrets_listed": len(kv.get("_secrets") or []),
                               "handoff": "az keyvault secret show -> trufflehog"}))

        # VMs -> run-command units
        for vm in data.get("vms") or []:
            name, rg = vm.get("name", ""), vm.get("resourceGroup", "")
            pubs = vm.get("publicIps") or ""
            ident = vm.get("identity") or {}
            assets.append({"kind": "compute-instance", "id": vm.get("id", f"azure:vm:{name}"),
                           "attrs": {"subscription": sub, "power": vm.get("powerState", "")}})
            units.append(unit(nid("vm"), f"VM {name} (run-command surface)",
                              [t.strip() for t in ([name] + pubs.split(",")) if t.strip()],
                              {"kind": "vm_runcommand", "subscription": sub,
                               "resource_group": rg,
                               "os": (vm.get("storageProfile") or {}).get("osDisk", {}).get("osType", ""),
                               "managed_identity": ident.get("type", "none"),
                               "handoff": "az vm run-command invoke -> IMDS token -> metadata-ssrf-pivot"}))

        # Web / Function apps
        for key, kind in (("webapps", "webapp"), ("functionapps", "functionapp")):
            for app in data.get(key) or []:
                host = app.get("defaultHostName", "")
                settings = app.get("_appsettings") or []
                assets.append({"kind": "public-endpoint", "id": f"url:https://{host}",
                               "attrs": {"subscription": sub, "type": kind}})
                units.append(unit(nid(kind[:2]), f"{kind} {app.get('name','')}",
                                  [host and f"https://{host}", app.get("name", "")],
                                  {"kind": kind, "subscription": sub,
                                   "resource_group": app.get("resourceGroup", ""),
                                   "appsettings_count": len(settings),
                                   "setting_names": [s.get("name") for s in settings][:50],
                                   "handoff": "appsettings/publish-profile dump -> trufflehog"}))

        # Privileged role assignments
        for ra in data.get("role_assignments") or []:
            role = ra.get("roleDefinitionName", "")
            if role not in PRIV_ROLES:
                continue
            principal = ra.get("principalName") or ra.get("principalId", "")
            assets.append({"kind": "principal", "id": f"azure:principal:{ra.get('principalId','')}",
                           "attrs": {"role": role, "scope": ra.get("scope", "")}})
            units.append(unit(nid("ra"), f"{role} -> {principal}",
                              [principal, ra.get("scope", "")],
                              {"kind": "role_assignment", "subscription": sub,
                               "role": role, "principal_type": ra.get("principalType", ""),
                               "handoff": "cloud-privilege-escalation"}))

        # AKS / ACR / data stores / automation
        for key, kind, handoff in (
                ("aks", "aks", "az aks get-credentials --admin -> k8s attack flow"),
                ("acr", "acr", "az acr credential show -> image loot"),
                ("cosmosdb", "cosmosdb", "az cosmosdb keys list -> data exfil"),
                ("sql_servers", "sql", "firewall rules + AAD auth -> data access"),
                ("automation_accounts", "automation",
                 "runbook content + variables -> cloud-privilege-escalation")):
            for r in data.get(key) or []:
                units.append(unit(nid(kind), f"{kind} {r.get('name','')}",
                                  [r.get("name", ""),
                                   r.get("fullyQualifiedDomainName", "") or
                                   r.get("loginServer", "") or
                                   r.get("documentEndpoint", "") or
                                   r.get("fqdn", "")],
                                  {"kind": kind, "subscription": sub,
                                   "resource_group": r.get("resourceGroup", ""),
                                   "handoff": handoff}))

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(units, f, indent=2)   # bare array -> rupu for_each
    print(f"[+] wrote {len(units)} work units -> {args.output}")

    if args.assets:
        seen, dedup = set(), []
        for a in assets:
            if a["id"] not in seen:
                seen.add(a["id"])
                dedup.append(a)
        os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
        with open(args.assets, "w") as f:
            json.dump(dedup, f, indent=2)
        print(f"[+] wrote {len(dedup)} assets -> {args.assets} "
              "(loop through rupu assets.mark; see references/rupu.md)")


if __name__ == "__main__":
    main()
