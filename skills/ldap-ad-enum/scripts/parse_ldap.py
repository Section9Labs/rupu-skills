#!/usr/bin/env python3
"""parse_ldap.py - normalize ldapsearch LDIF output into inventory + work units.

Consumes raw LDIF files (ldapsearch -LLL recommended; wrapped lines and
base64 values handled). Classifies entries into users / computers / groups /
trusts and derives kerberoastable, AS-REP-roastable and delegation sets from
userAccountControl bits and delegation attributes.

Emits into the output directory:
  inventory.json    {users:[{sam,description,spn,uac_flags}], computers, groups,
                     kerberoastable, asrep, delegation, trusts, cred_descriptions}
  users.txt         enabled sAMAccountNames (spray input)
  spn-targets.txt   kerberoastable accounts
  work_units.json   clean JSON ARRAY [{id,title,targets,hints}]

Standalone, stdlib only.

Usage:
  python3 scripts/parse_ldap.py --dc 192.0.2.10 --domain example.com \
      --users users.ldif --computers computers.ldif --groups groups.ldif \
      --extra spn.ldif asrep.ldif deleg.ldif trusts.ldif \
      -o ldap_example.com

-- vulture (silver-pinnacle)
"""

import argparse
import base64
import json
import os
import re
import sys

UAC_FLAGS = {
    0x2: "ACCOUNTDISABLE",
    0x10: "LOCKOUT",
    0x20: "PASSWD_NOTREQD",
    0x80: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x200: "NORMAL_ACCOUNT",
    0x800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}

CRED_RE = re.compile(r"pass|pwd|pw[: =]|cred|secret|login|initial|temp", re.I)


def parse_ldif(path):
    """Yield entries as dicts attr(lower) -> [values]. Handles folding and ::b64."""
    entries = []
    cur = {}
    # unfold continuation lines first
    lines = []
    for raw in open(path, "r", errors="replace"):
        raw = raw.rstrip("\n")
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    for line in lines:
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        if line.startswith("#") or line.startswith("version:"):
            continue
        if line.startswith("search:") or line.startswith("result:") or line.startswith("ref:"):
            continue
        m = re.match(r"^([A-Za-z0-9;.-]+)(::?)\s*(.*)$", line)
        if not m:
            continue
        attr, sep, val = m.group(1).lower(), m.group(2), m.group(3)
        if sep == "::":
            try:
                val = base64.b64decode(val).decode("utf-8", errors="replace")
            except Exception:
                pass
        cur.setdefault(attr, []).append(val)
    if cur:
        entries.append(cur)
    return entries


def first(e, attr, default=None):
    v = e.get(attr.lower())
    return v[0] if v else default


def classify(entries, inv):
    for e in entries:
        oc = {v.lower() for v in e.get("objectclass", [])}
        sam = first(e, "samaccountname")

        if "trusteddomain" in oc or e.get("trustpartner"):
            inv["trusts"].append({
                "partner": first(e, "trustpartner") or first(e, "cn"),
                "direction": first(e, "trustdirection"),
                "attributes": first(e, "trustattributes"),
            })
            continue

        if "group" in oc and "person" not in oc:
            inv["groups"].append({
                "name": sam or first(e, "cn"),
                "description": first(e, "description"),
                "member_count": len(e.get("member", [])),
                "admincount": first(e, "admincount"),
            })
            continue

        uac = int(first(e, "useraccountcontrol", "0") or 0)
        flags = [n for b, n in UAC_FLAGS.items() if uac & b]
        spns = e.get("serviceprincipalname", [])
        delegate_to = e.get("msds-allowedtodelegateto", [])
        rbcd = bool(e.get("msds-allowedtoactonbehalfofotheridentity"))

        if "computer" in oc or (uac & 0x1000) or (uac & 0x2000):
            comp = {
                "sam": sam,
                "dns": first(e, "dnshostname"),
                "os": first(e, "operatingsystem"),
                "os_version": first(e, "operatingsystemversion"),
                "uac_flags": flags,
                "laps": first(e, "ms-mcs-admpwd"),
            }
            inv["computers"].append(comp)
            if comp["laps"]:
                inv["laps_readable"].append(sam)
        elif "user" in oc or "person" in oc or sam:
            user = {
                "sam": sam,
                "description": first(e, "description"),
                "spn": spns,
                "uac": uac,
                "uac_flags": flags,
                "memberof": e.get("memberof", []),
                "admincount": first(e, "admincount"),
                "enabled": not (uac & 0x2),
            }
            inv["users"].append(user)
            if user["description"] and CRED_RE.search(user["description"]):
                inv["cred_descriptions"].append(
                    {"sam": sam, "description": user["description"]})
        else:
            continue

        name = sam or first(e, "cn") or "?"
        if spns and (sam or "").lower() != "krbtgt" and not (uac & 0x2) and not (uac & 0x1000):
            inv["kerberoastable"].append({"sam": name, "spns": spns})
        if uac & 0x400000 and not (uac & 0x2):
            inv["asrep"].append(name)
        if uac & 0x80000:
            inv["delegation"].append(
                {"principal": name, "type": "unconstrained",
                 "is_dc": bool(uac & 0x2000)})
        if delegate_to:
            inv["delegation"].append(
                {"principal": name, "type": "constrained",
                 "protocol_transition": bool(uac & 0x1000000),
                 "targets": delegate_to})
        if rbcd:
            inv["delegation"].append({"principal": name, "type": "rbcd"})
        if e.get("msds-managedpassword"):
            inv["gmsa_readable"].append(name)


def build_work_units(inv, dc, domain):
    wu = []
    if inv["kerberoastable"]:
        wu.append({
            "id": "kerberoast-%s" % domain,
            "title": "Kerberoast %d SPN accounts" % len(inv["kerberoastable"]),
            "targets": [dc],
            "hints": {"skill": "netexec", "mode": "--kerberoasting",
                      "targets_file": "spn-targets.txt",
                      "alt": "GetUserSPNs.py %s/user:pass -dc-ip %s -request" % (domain, dc)},
        })
    if inv["asrep"]:
        wu.append({
            "id": "asrep-%s" % domain,
            "title": "AS-REP roast %d preauth-less accounts" % len(inv["asrep"]),
            "targets": [dc],
            "hints": {"skill": "netexec", "mode": "--asreproast",
                      "accounts": inv["asrep"]},
        })
    enabled = [u["sam"] for u in inv["users"] if u.get("enabled") and u.get("sam")]
    if enabled:
        wu.append({
            "id": "spray-%s" % domain,
            "title": "Password spray %d enabled users" % len(enabled),
            "targets": [dc],
            "hints": {"skill": "netexec", "userfile": "users.txt",
                      "note": "pull lockout policy from smb-enum pass_pol first"},
        })
    for i, d in enumerate(inv["delegation"]):
        if d.get("is_dc"):
            continue  # DCs are unconstrained by design
        wu.append({
            "id": "deleg-%s-%d" % (domain, i),
            "title": "Delegation abuse: %s (%s)" % (d["principal"], d["type"]),
            "targets": [dc],
            "hints": d,
        })
    for c in inv["cred_descriptions"]:
        wu.append({
            "id": "cred-desc-%s" % (c["sam"] or "unknown").lower(),
            "title": "Possible credential in description of %s - validate" % c["sam"],
            "targets": [dc],
            "hints": {"skill": "netexec", "account": c["sam"],
                      "description": c["description"]},
        })
    for t in inv["trusts"]:
        if t.get("partner"):
            wu.append({
                "id": "trust-pivot-%s" % t["partner"].lower(),
                "title": "Trusted domain %s - enumerate" % t["partner"],
                "targets": [t["partner"]],
                "hints": {"skill": "ldap-ad-enum", "domain": t["partner"],
                          "direction": t.get("direction")},
            })
    if inv["laps_readable"] or inv["gmsa_readable"]:
        wu.append({
            "id": "laps-gmsa-%s" % domain,
            "title": "Readable LAPS/gMSA secrets - dump and report",
            "targets": [dc],
            "hints": {"skill": "netexec", "laps": inv["laps_readable"],
                      "gmsa": inv["gmsa_readable"]},
        })
    wu.append({
        "id": "bloodhound-%s" % domain,
        "title": "BloodHound CE collection for %s" % domain,
        "targets": [dc],
        "hints": {"collector": "bloodhound-ce-python",
                  "cmd": "bloodhound-ce-python -u <user> -p <pass> -d %s -ns %s -c All --zip" % (domain, dc)},
    })
    return wu


def main():
    ap = argparse.ArgumentParser(description="Normalize ldapsearch LDIF output")
    ap.add_argument("--dc", required=True, help="DC IP, e.g. 192.0.2.10")
    ap.add_argument("--domain", required=True, help="domain, e.g. example.com")
    ap.add_argument("--users", help="users query LDIF")
    ap.add_argument("--computers", help="computers query LDIF")
    ap.add_argument("--groups", help="groups query LDIF")
    ap.add_argument("--extra", nargs="*", default=[],
                    help="additional LDIF files (spn/asrep/deleg/trusts/...)")
    ap.add_argument("-o", "--outdir", default="ldap_out", help="output directory")
    args = ap.parse_args()

    inv = {"dc": args.dc, "domain": args.domain,
           "users": [], "computers": [], "groups": [],
           "kerberoastable": [], "asrep": [], "delegation": [],
           "trusts": [], "cred_descriptions": [],
           "laps_readable": [], "gmsa_readable": []}

    files = [f for f in [args.users, args.computers, args.groups] + args.extra if f]
    if not files:
        ap.error("provide at least one LDIF file")
    for path in files:
        if not os.path.exists(path):
            print("[!] missing: %s (skipped)" % path, file=sys.stderr)
            continue
        classify(parse_ldif(path), inv)

    # dedupe users/computers by sam
    for key in ("users", "computers"):
        seen, out = set(), []
        for item in inv[key]:
            k = (item.get("sam") or "").lower()
            if k and k in seen:
                continue
            seen.add(k)
            out.append(item)
        inv[key] = out
    inv["asrep"] = sorted(set(inv["asrep"]), key=str.lower)

    os.makedirs(args.outdir, exist_ok=True)

    with open(os.path.join(args.outdir, "inventory.json"), "w") as f:
        json.dump(inv, f, indent=2)

    enabled = sorted({u["sam"] for u in inv["users"]
                      if u.get("enabled") and u.get("sam")}, key=str.lower)
    with open(os.path.join(args.outdir, "users.txt"), "w") as f:
        f.write("\n".join(enabled) + ("\n" if enabled else ""))

    spns = sorted({k["sam"] for k in inv["kerberoastable"] if k.get("sam")}, key=str.lower)
    with open(os.path.join(args.outdir, "spn-targets.txt"), "w") as f:
        f.write("\n".join(spns) + ("\n" if spns else ""))

    wu = build_work_units(inv, args.dc, args.domain)
    with open(os.path.join(args.outdir, "work_units.json"), "w") as f:
        json.dump(wu, f, indent=2)

    print("[*] %s @ %s: users=%d computers=%d groups=%d" %
          (args.domain, args.dc, len(inv["users"]), len(inv["computers"]), len(inv["groups"])))
    print("[*] kerberoastable=%d asrep=%d delegation=%d trusts=%d cred-desc=%d laps=%d gmsa=%d" %
          (len(inv["kerberoastable"]), len(inv["asrep"]), len(inv["delegation"]),
           len(inv["trusts"]), len(inv["cred_descriptions"]),
           len(inv["laps_readable"]), len(inv["gmsa_readable"])))
    print("[*] wrote %s/{inventory.json,users.txt,spn-targets.txt,work_units.json} (%d work units)" %
          (args.outdir, len(wu)))


if __name__ == "__main__":
    sys.exit(main())
