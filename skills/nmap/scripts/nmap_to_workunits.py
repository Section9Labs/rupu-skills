#!/usr/bin/env python3
"""nmap_to_workunits.py - turn inventory.json into a rupu-ingestible JSON ARRAY
of per-service enumeration work units.

Input : inventory.json produced by parse_nmap_xml.py
Output: a JSON array (first byte '[') of
        {"id": ..., "title": ..., "targets": [...], "hints": [...]}
groupable by rupu `for_each:` or a lead's `dispatch`.

Service-to-sub-skill routing:
    445/tcp (and 139)      -> smb-enum
    389,636,3268,3269/tcp  -> ldap-ad-enum
    161/udp                -> snmp-enum
    2049 (and 111)         -> nfs-enum
    53/tcp+udp             -> dns-recon
    500,4500/udp           -> ike-scan
Other open services get a generic work unit carrying the -sV strings as hints.

Usage:
    python3 nmap_to_workunits.py inventory.json -o workunits.json
    python3 nmap_to_workunits.py inventory.json            # stdout
Signed-off: vulture (plum-quarter)
"""

import argparse
import json
import sys

# (match_fn) -> (unit_key, skill, title)
ROUTES = [
    (lambda p: p["proto"] == "tcp" and p["port"] in (445, 139),
     ("smb", "smb-enum", "SMB enumeration")),
    (lambda p: p["proto"] == "tcp" and p["port"] in (389, 636, 3268, 3269),
     ("ldap", "ldap-ad-enum", "LDAP / Active Directory enumeration")),
    (lambda p: p["proto"] == "udp" and p["port"] in (161, 162),
     ("snmp", "snmp-enum", "SNMP enumeration")),
    (lambda p: p["port"] in (2049, 111),
     ("nfs", "nfs-enum", "NFS / RPC enumeration")),
    (lambda p: p["port"] == 53,
     ("dns", "dns-recon", "DNS reconnaissance")),
    (lambda p: p["proto"] == "udp" and p["port"] in (500, 4500),
     ("ike", "ike-scan", "IKE / VPN gateway enumeration")),
]

# generic buckets for common services without a dedicated route above
GENERIC = {
    "http": "HTTP service enumeration",
    "https": "HTTPS service enumeration",
    "http-proxy": "HTTP proxy enumeration",
    "ssh": "SSH service review",
    "ftp": "FTP service enumeration",
    "ms-sql-s": "MS-SQL enumeration",
    "ms-wbt-server": "RDP enumeration",
    "mysql": "MySQL enumeration",
    "postgresql": "PostgreSQL enumeration",
    "vnc": "VNC enumeration",
    "telnet": "Telnet service review",
    "smtp": "SMTP enumeration",
    "redis": "Redis enumeration",
    "mongodb": "MongoDB enumeration",
    "winrm": "WinRM enumeration",
    "kerberos-sec": "Kerberos enumeration",
    "msrpc": "MSRPC enumeration",
}

OPEN_STATES = ("open", "open|filtered")


def svc_desc(p):
    bits = [p.get("service") or "unknown"]
    ver = " ".join(x for x in (p.get("product"), p.get("version"),
                               p.get("extrainfo")) if x)
    if ver:
        bits.append(ver)
    return " ".join(bits)


def main():
    ap = argparse.ArgumentParser(
        description="inventory.json -> rupu work-units JSON array")
    ap.add_argument("inventory", help="inventory.json from parse_nmap_xml.py")
    ap.add_argument("-o", "--output", default=None,
                    help="output path (default: stdout)")
    ap.add_argument("--no-generic", action="store_true",
                    help="emit only routed (sub-skill) units")
    args = ap.parse_args()

    with open(args.inventory) as f:
        inv = json.load(f)

    # key -> {"title","skill","targets":set,"hints":set}
    units = {}

    def add(key, title, skill, target, extra_hints):
        u = units.setdefault(key, {"title": title, "skill": skill,
                                   "targets": [], "hints": []})
        if target not in u["targets"]:
            u["targets"].append(target)
        for h in extra_hints:
            if h and h not in u["hints"]:
                u["hints"].append(h)

    for addr, host in sorted(inv.items()):
        if host.get("status") != "up":
            continue
        names = host.get("hostnames") or []
        for p in host.get("ports", []):
            if p.get("state") not in OPEN_STATES or p.get("port", 0) == 0:
                continue
            target = "%s:%d/%s" % (addr, p["port"], p["proto"])
            base_hints = ["service: " + svc_desc(p)]
            if names:
                base_hints.append("hostnames: " + ",".join(names))
            if host.get("os", {}).get("name"):
                base_hints.append("os: %s (%s%%)" % (
                    host["os"]["name"], host["os"].get("accuracy", "?")))
            for sid, out in (p.get("scripts") or {}).items():
                first = out.splitlines()[0].strip() if out else ""
                base_hints.append("nse %s: %s" % (sid, first[:160]))

            routed = False
            for match, (ukey, skill, title) in ROUTES:
                if match(p):
                    add(ukey, title, skill, target, base_hints)
                    routed = True
                    break
            if routed or args.no_generic:
                continue

            svc = p.get("service") or ""
            if svc in GENERIC:
                add("svc-" + svc, GENERIC[svc], None, target, base_hints)
            else:
                add("svc-other", "Unrouted open services - manual triage",
                    None, target, base_hints)

    out = []
    for key in sorted(units):
        u = units[key]
        hints = []
        if u["skill"]:
            hints.append("load skill: %s" % u["skill"])
        hints.extend(u["hints"])
        out.append({
            "id": "nmap-%s" % key,
            "title": u["title"],
            "targets": u["targets"],
            "hints": hints,
        })

    text = json.dumps(out, indent=2)
    assert text and text[0] == "[", "output must be a JSON array"
    if args.output:
        with open(args.output, "w") as f:
            f.write(text + "\n")
        sys.stderr.write("[+] %d work units (%d targets) -> %s\n" % (
            len(out), sum(len(u["targets"]) for u in out), args.output))
    else:
        print(text)


if __name__ == "__main__":
    main()
