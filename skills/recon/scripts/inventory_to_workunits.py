#!/usr/bin/env python3
"""inventory_to_workunits.py — cut inventory.json into rupu work units.

Reads the inventory produced by normalize_inventory.py and writes a clean
JSON ARRAY of work units:

    [{"id": "...", "title": "...", "targets": [...], "hints": "..."}, ...]

Contract: the output file's FIRST BYTE is '[' so a rupu workflow `for_each:`
step can JSON-parse the result of `read_file` directly, and a lead agent can
`dispatch` one subagent per element.

One unit is emitted per (service-family, host) pair for every enumerable
family, one aggregate netexec multi-protocol sweep unit, and one generic
nmap deep-dive unit per host that exposes services no dedicated enumerator
covers. Each unit's hints name the sub-skill to load.

Usage:
  python3 scripts/inventory_to_workunits.py inventory.json -o work-units.json
"""

import argparse
import json
import sys

# family -> (skill, title verb, matcher)
# matcher: (proto, port set, service-name substrings)
FAMILIES = [
    ("smb", "smb-enum", "Enumerate SMB/MSRPC",
     {"tcp": {135, 139, 445}},
     ("microsoft-ds", "netbios-ssn", "msrpc", "smb")),
    ("ldap", "ldap-ad-enum", "Enumerate LDAP/AD",
     {"tcp": {389, 636, 3268, 3269}},
     ("ldap",)),
    ("dns", "dns-recon", "Enumerate DNS",
     {"tcp": {53}, "udp": {53}},
     ("domain",)),
    ("nfs", "nfs-enum", "Enumerate NFS/portmap",
     {"tcp": {111, 2049}, "udp": {111, 2049}},
     ("nfs", "rpcbind", "mountd")),
    ("snmp", "snmp-enum", "Enumerate SNMP",
     {"udp": {161}},
     ("snmp",)),
    ("ike", "ike-scan", "Fingerprint IKE/IPsec VPN",
     {"udp": {500, 4500}},
     ("isakmp", "ike")),
]

FAMILY_NOTES = {
    "smb": ("Null/guest sessions, share listing and spidering, RID cycling, "
            "MSRPC endpoints, signing and dialect checks; feed any creds to "
            "netexec."),
    "ldap": ("rootDSE and naming contexts, anonymous bind test, users, groups, "
             "SPNs (kerberoast targets), delegation, domain/forest mapping."),
    "dns": ("Zone transfer attempts, SRV records (_ldap._tcp, _kerberos._tcp), "
            "PTR sweeps, subdomain enumeration."),
    "nfs": ("showmount exports, mount and loot, root/UID squashing checks."),
    "snmp": ("Community brute force, full MIB walks, interfaces/routes/ARP, "
             "processes and installed software, credential leakage in config "
             "MIBs."),
    "ike": ("Transform enumeration, vendor-ID fingerprinting, aggressive-mode "
            "handshake and PSK hash capture for offline cracking."),
}

# netexec aggregate sweep: protocol -> (proto, ports)
NETEXEC_PROTOS = {
    "smb": ("tcp", {139, 445}),
    "ldap": ("tcp", {389, 636, 3268, 3269}),
    "winrm": ("tcp", {5985, 5986}),
    "mssql": ("tcp", {1433}),
    "ssh": ("tcp", {22}),
    "rdp": ("tcp", {3389}),
    "wmi": ("tcp", {135}),
}

# ports covered by some dedicated unit; anything else open and interesting
# falls into a generic nmap deep-dive unit.
HANDLED_PORTS = {
    ("tcp", p) for fam in FAMILIES for p in fam[3].get("tcp", set())
} | {
    ("udp", p) for fam in FAMILIES for p in fam[3].get("udp", set())
} | {
    (proto, p) for proto, ports in NETEXEC_PROTOS.values() for p in ports
}
# web ports are out of this pack's scope but still get flagged in the generic
# unit so the web pack can pick them up.


def open_ports(host):
    return [p for p in host.get("ports", [])
            if p.get("state", "open") in ("open", "open|filtered")]


def port_desc(p):
    bits = [f"{p['port']}/{p['proto']}"]
    svc = p.get("service")
    prod = " ".join(filter(None, [p.get("product"), p.get("version")]))
    if svc:
        bits.append(svc)
    if prod:
        bits.append(f"({prod})")
    return " ".join(bits)


def matches(p, matcher, names):
    if p["port"] in matcher.get(p["proto"], set()):
        return True
    svc = (p.get("service") or "").lower()
    return any(n in svc for n in names) if svc else False


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Emit a JSON array of rupu work units from inventory.json.")
    ap.add_argument("inventory", help="inventory.json from normalize_inventory.py")
    ap.add_argument("-o", "--output", default="work-units.json",
                    help="output path (default: work-units.json)")
    args = ap.parse_args(argv)

    with open(args.inventory, "r", encoding="utf-8") as fh:
        inv = json.load(fh)

    units = []
    seq = 0

    def unit_id(tag):
        nonlocal seq
        seq += 1
        return f"wu-{seq:03d}-{tag}"

    # per-(family, host) units
    for addr in sorted(inv, key=lambda a: tuple(
            int(x) if x.isdigit() else x for x in a.replace(":", ".").split("."))):
        host = inv[addr]
        ports = open_ports(host)
        for fam, skill, verb, matcher, names in FAMILIES:
            hit = [p for p in ports if matches(p, matcher, names)]
            if not hit:
                continue
            detail = ", ".join(port_desc(p) for p in hit)
            extra = ""
            if host.get("os"):
                extra = f" Host OS: {host['os']}."
            if host.get("hostnames"):
                extra += f" Hostnames: {', '.join(host['hostnames'])}."
            units.append({
                "id": unit_id(f"{fam}-{addr.replace('.', '-').replace(':', '-')}"),
                "title": f"{verb} on {addr}",
                "targets": [addr],
                "hints": (f"Load the `{skill}` skill. Ports open: {detail}."
                          f"{extra} {FAMILY_NOTES[fam]}"),
            })

    # aggregate netexec sweep over every host exposing a netexec protocol
    nxc_hosts = {}
    for addr, host in inv.items():
        protos = sorted(
            name for name, (proto, portset) in NETEXEC_PROTOS.items()
            if any(p["proto"] == proto and p["port"] in portset
                   for p in open_ports(host)))
        if protos:
            nxc_hosts[addr] = protos
    if nxc_hosts:
        all_protos = sorted({pr for prs in nxc_hosts.values() for pr in prs})
        units.append({
            "id": unit_id("netexec-sweep"),
            "title": f"netexec multi-protocol sweep ({len(nxc_hosts)} hosts)",
            "targets": sorted(nxc_hosts),
            "hints": (f"Load the `netexec` skill. Protocols present: "
                      f"{', '.join(all_protos)}. Run uncredentialed triage "
                      "(signing, null/guest sessions, OS/domain banners) now; "
                      "re-run across every protocol each time the credential "
                      "set grows, and spray per that skill's lockout-aware "
                      "guidance."),
        })

    # generic deep-dive for open ports no dedicated enumerator covers
    for addr in sorted(inv):
        host = inv[addr]
        leftover = [p for p in open_ports(host)
                    if (p["proto"], p["port"]) not in HANDLED_PORTS]
        if not leftover:
            continue
        detail = ", ".join(port_desc(p) for p in leftover)
        units.append({
            "id": unit_id(f"misc-{addr.replace('.', '-').replace(':', '-')}"),
            "title": f"Deep-dive uncovered services on {addr}",
            "targets": [addr],
            "hints": (f"Load the `nmap` skill. Open ports without a dedicated "
                      f"enumerator: {detail}. Run targeted -sV "
                      "--version-intensity 9 and per-service NSE scripts; "
                      "route HTTP(S) ports to the web pack."),
        })

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)   # first byte of the file is '['
        fh.write("\n")

    print(f"[+] wrote {args.output}: {len(units)} work units "
          f"from {len(inv)} hosts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
