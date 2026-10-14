#!/usr/bin/env python3
"""parse_azurehound.py — split AzureHound JSON into rupu work units + assets.

Reads one or more AzureHound output files (format:
{"meta": {...}, "data": [{"kind": "AZUser", "data": {...}}, ...]} — a bare list
of kind/data entries also works) and writes:

  * a bare JSON ARRAY of work units ({"id","title","targets","hints"}) — one
    per privesc edge / high-value principal:
      - holders of high-privilege directory roles (GA, PRA, App Admin, ...)
      - app / service-principal / group ownership edges
      - role-assignable groups and dynamic-membership groups
      - service principals holding dangerous MS Graph app roles
  * an assets inventory (users, groups, service principals, apps, roles,
    devices, tenants, subscriptions) for coverage-assets / assets.mark.

Examples:
  python3 scripts/parse_azurehound.py azurehound.json
  python3 scripts/parse_azurehound.py a.json b.json -o out/work-units.json --assets out/assets.json
"""

import argparse
import json
import os
import sys

HIGH_PRIV_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": "Partner Tier2 Support",
}

DANGEROUS_APP_ROLES = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
}


def pick(d, *keys):
    """First non-empty value among keys (case-tolerant)."""
    if not isinstance(d, dict):
        return None
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
    return None


def iter_entries(paths):
    for path in paths:
        with open(path) as fh:
            doc = json.load(fh)
        data = doc.get("data", doc) if isinstance(doc, dict) else doc
        if not isinstance(data, list):
            print("[!] %s: unrecognized layout, skipping" % path, file=sys.stderr)
            continue
        for entry in data:
            if isinstance(entry, dict) and "kind" in entry:
                yield entry.get("kind", ""), entry.get("data", {}) or {}


def extract_owners(data):
    """Yield owner principal dicts from an *Owner entry's data blob."""
    owners = pick(data, "owners") or []
    for o in owners:
        if isinstance(o, dict):
            inner = o.get("owner", o)
            if isinstance(inner, dict):
                yield inner


def extract_role_assignments(kind, data):
    """Yield (role_definition_id, principal_id, scope) from assorted shapes."""
    rdid = pick(data, "roleDefinitionId", "roleTemplateId")
    assignees = pick(data, "assignees") or []
    if assignees:
        for a in assignees:
            inner = a.get("assignee", a) if isinstance(a, dict) else {}
            pid = pick(inner, "principalId", "id")
            if pid:
                yield (pick(inner, "roleDefinitionId") or rdid,
                       pid, pick(inner, "directoryScopeId") or "/")
    elif rdid and pick(data, "principalId"):
        yield rdid, pick(data, "principalId"), pick(data, "directoryScopeId") or "/"


def main():
    ap = argparse.ArgumentParser(
        description="AzureHound JSON -> rupu work units + asset inventory.")
    ap.add_argument("inputs", nargs="+", help="AzureHound output JSON file(s)")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units bare JSON array (default: %(default)s)")
    ap.add_argument("--assets", default="out/assets.json",
                    help="assets inventory JSON (default: %(default)s)")
    args = ap.parse_args()

    assets = {k: [] for k in ("tenants", "users", "groups", "service_principals",
                              "apps", "roles", "devices", "subscriptions", "other")}
    names = {}          # objectId -> display label
    groups = {}         # objectId -> group data
    role_names = dict(HIGH_PRIV_ROLES)
    deferred = []       # (kind, data) for edge entries, processed after names known

    for kind, data in iter_entries(args.inputs):
        oid = pick(data, "id", "objectId")
        name = pick(data, "displayName", "userPrincipalName", "name") or oid
        if oid:
            names[oid] = name
        if kind == "AZUser":
            assets["users"].append({"id": oid,
                                    "upn": pick(data, "userPrincipalName"),
                                    "name": name,
                                    "synced": bool(pick(data, "onPremisesSyncEnabled"))})
            upn = pick(data, "userPrincipalName")
            if upn:
                names[oid] = upn
        elif kind == "AZGroup":
            groups[oid] = data
            assets["groups"].append({"id": oid, "name": name,
                                     "role_assignable": bool(pick(data, "isAssignableToRole")),
                                     "membership_rule": pick(data, "membershipRule")})
        elif kind == "AZServicePrincipal":
            assets["service_principals"].append({"id": oid, "name": name,
                                                 "app_id": pick(data, "appId"),
                                                 "type": pick(data, "servicePrincipalType")})
        elif kind == "AZApp":
            assets["apps"].append({"id": oid, "name": name, "app_id": pick(data, "appId")})
        elif kind == "AZRole":
            tmpl = pick(data, "roleTemplateId", "templateId")
            if tmpl and name:
                role_names.setdefault(tmpl, name)
            if oid:
                role_names.setdefault(oid, name)
            assets["roles"].append({"id": oid, "name": name, "template_id": tmpl})
        elif kind == "AZDevice":
            assets["devices"].append({"id": oid, "name": name,
                                      "os": pick(data, "operatingSystem")})
        elif kind == "AZTenant":
            assets["tenants"].append({"id": pick(data, "tenantId", "id"), "name": name})
        elif kind == "AZSubscription":
            assets["subscriptions"].append({"id": pick(data, "subscriptionId", "id"),
                                            "name": name})
        elif kind in ("AZRoleAssignment", "AZAppOwner", "AZServicePrincipalOwner",
                      "AZGroupOwner", "AZAppRoleAssignment"):
            deferred.append((kind, data))
        else:
            assets["other"].append({"kind": kind, "id": oid, "name": name})

    def label(oid):
        return names.get(oid, oid)

    units, seen = [], set()

    def add_unit(uid, title, targets, hints):
        if uid in seen:
            return
        seen.add(uid)
        units.append({"id": uid, "title": title,
                      "targets": [t for t in targets if t], "hints": hints})

    for kind, data in deferred:
        if kind == "AZRoleAssignment":
            for rdid, pid, scope in extract_role_assignments(kind, data):
                role = role_names.get(rdid, rdid)
                if rdid in HIGH_PRIV_ROLES:
                    add_unit("role-%s-%s" % (rdid, pid),
                             "%s held by %s" % (role, label(pid)),
                             [label(pid), pid],
                             {"edge": "AZHasRole", "role": role,
                              "reason": "high-privilege directory role; takeover of "
                                        "this principal yields the role",
                              "scope": scope, "role_template_id": rdid})
        elif kind in ("AZAppOwner", "AZServicePrincipalOwner", "AZGroupOwner"):
            obj = pick(data, "appId", "appObjectId", "servicePrincipalId",
                       "groupId", "id", "objectId")
            kindmap = {"AZAppOwner": ("AZApp", "owner can addPassword/addKey on the app "
                                               "and authenticate as its service principal"),
                       "AZServicePrincipalOwner": ("AZServicePrincipal",
                                                   "owner can add credentials to the SP and act as it"),
                       "AZGroupOwner": ("AZGroup", "owner controls group membership")}
            target_kind, reason = kindmap[kind]
            if kind == "AZGroupOwner":
                g = groups.get(obj, {})
                if pick(g, "isAssignableToRole"):
                    reason = ("owner of a ROLE-ASSIGNABLE group: add self as member "
                              "to inherit its directory role")
                elif pick(g, "membershipRule"):
                    reason = "owner of a dynamic group (rule: %s)" % pick(g, "membershipRule")
            for owner in extract_owners(data):
                oid = pick(owner, "id", "objectId")
                add_unit("own-%s-%s" % (oid, obj),
                         "%s owns %s %s" % (label(oid), target_kind, label(obj)),
                         [label(oid), oid, obj],
                         {"edge": "AZOwns", "role": target_kind, "reason": reason,
                          "owner": oid or "", "owned_object": obj or ""})
        elif kind == "AZAppRoleAssignment":
            arid = pick(data, "appRoleId")
            pid = pick(data, "principalId")
            if arid in DANGEROUS_APP_ROLES and pid:
                perm = DANGEROUS_APP_ROLES[arid]
                add_unit("approle-%s-%s" % (arid, pid),
                         "SP %s holds Graph app role %s"
                         % (pick(data, "principalDisplayName") or label(pid), perm),
                         [label(pid), pid],
                         {"edge": "AZMGGrantAppRoles", "role": perm,
                          "reason": "dangerous MS Graph application permission; "
                                    "a credential on this SP escalates to directory control",
                          "app_role_id": arid,
                          "resource": pick(data, "resourceDisplayName") or ""})

    # Standalone high-value objects (no edge entry required)
    for gid, g in groups.items():
        if pick(g, "isAssignableToRole"):
            add_unit("rag-%s" % gid,
                     "Role-assignable group %s" % label(gid),
                     [label(gid), gid],
                     {"edge": "role-assignable-group", "role": "AZGroup",
                      "reason": "membership grants a directory role; hunt owners and "
                                "AZAddMembers paths into it"})
        rule = pick(g, "membershipRule")
        if rule:
            add_unit("dyn-%s" % gid,
                     "Dynamic group %s" % label(gid),
                     [label(gid), gid],
                     {"edge": "dynamic-membership", "role": "AZGroup",
                      "reason": "membership rule may be attacker-satisfiable",
                      "rule": rule})

    for path in (args.output, args.assets):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(units, fh, indent=2)
    with open(args.assets, "w") as fh:
        json.dump(assets, fh, indent=2)

    counts = {k: len(v) for k, v in assets.items() if v}
    print("[+] %d work units -> %s" % (len(units), args.output), file=sys.stderr)
    print("[+] assets -> %s %s" % (args.assets, json.dumps(counts)), file=sys.stderr)


if __name__ == "__main__":
    main()
