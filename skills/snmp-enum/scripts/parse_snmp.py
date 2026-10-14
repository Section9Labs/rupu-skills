#!/usr/bin/env python3
"""parse_snmp.py — snmp-enum handoff parser (Section9Labs / vulture, crew lapis-bough)

Parses:
  * onesixtyone output (community hits)          --hits FILE            (repeatable)
  * snmpwalk/snmpbulkwalk output                 --walk HOST=FILE       (repeatable)
  * snmp-check output                            --check HOST=FILE      (repeatable)
  * known write communities                      --write-community HOST=COMMUNITY

Emits into --out-dir (default snmp_out/):
  snmp_enum.json   per-host records:
                   {host, community, version, sysdescr, users:[], processes:[],
                    routes:[], write_community:bool}
  subnets.txt      discovered subnets (one per line) -> re-feed host-discovery
  work_units.json  clean JSON array [{id,title,targets,hints}]

Standalone, python3 stdlib only.

Examples:
  python3 scripts/parse_snmp.py --hits hits.txt \
      --walk 192.0.2.10=walk_192.0.2.10_public.txt \
      --check 192.0.2.10=snmpcheck_192.0.2.10.txt \
      --write-community 192.0.2.10=private --out-dir snmp_out
"""
import argparse
import ipaddress
import json
import os
import re
import sys

# ---------------------------------------------------------------- OID handling

# Prefixes snmpwalk may print depending on loaded MIBs; normalize all to numeric.
PREFIX_MAP = [
    ("SNMPv2-SMI::enterprises", "1.3.6.1.4.1"),
    ("SNMPv2-SMI::mib-2", "1.3.6.1.2.1"),
    ("iso.3.6.1", "1.3.6.1"),
    ("SNMPv2-MIB::sysDescr", "1.3.6.1.2.1.1.1"),
    ("SNMPv2-MIB::sysName", "1.3.6.1.2.1.1.5"),
    ("SNMPv2-MIB::sysContact", "1.3.6.1.2.1.1.4"),
    ("HOST-RESOURCES-MIB::hrSWRunName", "1.3.6.1.2.1.25.4.2.1.2"),
    ("HOST-RESOURCES-MIB::hrSWRunParameters", "1.3.6.1.2.1.25.4.2.1.5"),
    ("HOST-RESOURCES-MIB::hrSWInstalledName", "1.3.6.1.2.1.25.6.3.1.2"),
    ("IP-MIB::ipAdEntAddr", "1.3.6.1.2.1.4.20.1.1"),
    ("IP-MIB::ipAdEntNetMask", "1.3.6.1.2.1.4.20.1.3"),
    ("RFC1213-MIB::ipRouteDest", "1.3.6.1.2.1.4.21.1.1"),
    ("RFC1213-MIB::ipRouteNextHop", "1.3.6.1.2.1.4.21.1.7"),
    ("RFC1213-MIB::ipRouteMask", "1.3.6.1.2.1.4.21.1.11"),
]

OID_SYSDESCR = "1.3.6.1.2.1.1.1"
OID_PROC_NAME = "1.3.6.1.2.1.25.4.2.1.2"
OID_PROC_ARGS = "1.3.6.1.2.1.25.4.2.1.5"
OID_WIN_USERS = "1.3.6.1.4.1.77.1.2.25"
OID_IPADDR = "1.3.6.1.2.1.4.20.1.1"
OID_IPMASK = "1.3.6.1.2.1.4.20.1.3"
OID_ROUTE_DEST = "1.3.6.1.2.1.4.21.1.1"
OID_ROUTE_NEXT = "1.3.6.1.2.1.4.21.1.7"
OID_ROUTE_MASK = "1.3.6.1.2.1.4.21.1.11"

SECRET_RE = re.compile(
    r"(pass(word|wd)?|pwd|secret|token|apikey|api[-_]key|connectionstring|"
    r"-p\s*\S|jdbc:|mysql://|postgres(ql)?://|mongodb://|amqp://)", re.I)

WALK_LINE_RE = re.compile(r"^(?P<oid>\S+?)\s*=\s*(?:(?P<type>[A-Za-z0-9\-]+):\s*)?(?P<val>.*)$")


def norm_oid(oid):
    for pfx, num in PREFIX_MAP:
        if oid.startswith(pfx):
            oid = num + oid[len(pfx):]
            break
    return oid.lstrip(".")


def clean_val(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
    return val.strip()


# ---------------------------------------------------------------- parsers

def parse_onesixtyone(path):
    """Lines: '192.0.2.10 [public] Linux core-sw1 ...' -> list of dicts."""
    hits = []
    rx = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\[([^\]]+)\]\s*(.*)$")
    with open(path, errors="replace") as f:
        for line in f:
            m = rx.match(line.strip())
            if m:
                hits.append({"host": m.group(1), "community": m.group(2),
                             "sysdescr": m.group(3).strip()})
    return hits


def parse_walk(path):
    """snmpwalk output -> dict of extracted fields."""
    out = {"sysdescr": None, "users": [], "processes": {}, "proc_args": {},
           "routes": [], "ipaddrs": {}, "ipmasks": {}, "route_rows": {},
           "secrets": []}
    with open(path, errors="replace") as f:
        for raw in f:
            m = WALK_LINE_RE.match(raw.rstrip("\n"))
            if not m:
                continue
            oid = norm_oid(m.group("oid"))
            val = clean_val(m.group("val"))
            if not val or val in ("No Such Object available on this agent at this OID",):
                continue
            if oid.startswith(OID_SYSDESCR) and out["sysdescr"] is None:
                out["sysdescr"] = val
            elif oid.startswith(OID_WIN_USERS):
                if val and val not in out["users"]:
                    out["users"].append(val)
            elif oid.startswith(OID_PROC_NAME):
                out["processes"][oid[len(OID_PROC_NAME) + 1:]] = val
            elif oid.startswith(OID_PROC_ARGS):
                out["proc_args"][oid[len(OID_PROC_ARGS) + 1:]] = val
                if SECRET_RE.search(val):
                    out["secrets"].append(val)
            elif oid.startswith(OID_IPADDR):
                out["ipaddrs"][oid[len(OID_IPADDR) + 1:]] = val
            elif oid.startswith(OID_IPMASK):
                out["ipmasks"][oid[len(OID_IPMASK) + 1:]] = val
            elif oid.startswith(OID_ROUTE_DEST):
                out["route_rows"].setdefault(oid[len(OID_ROUTE_DEST) + 1:], {})["dest"] = val
            elif oid.startswith(OID_ROUTE_NEXT):
                out["route_rows"].setdefault(oid[len(OID_ROUTE_NEXT) + 1:], {})["next_hop"] = val
            elif oid.startswith(OID_ROUTE_MASK):
                out["route_rows"].setdefault(oid[len(OID_ROUTE_MASK) + 1:], {})["mask"] = val
    for idx, row in sorted(out["route_rows"].items()):
        out["routes"].append({"dest": row.get("dest", idx),
                              "mask": row.get("mask", ""),
                              "next_hop": row.get("next_hop", "")})
    return out


def parse_snmpcheck(path):
    """snmp-check output -> dict (sysdescr, users, processes, routes, write hint)."""
    out = {"host": None, "sysdescr": None, "users": [], "processes": [],
           "routes": [], "write_community": False}
    section = None
    with open(path, errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            s = line.strip()
            m = re.match(r"^\[\*\]\s*(.+?):?\s*$", s)
            if m:
                section = m.group(1).lower()
                continue
            if re.search(r"write access.*(enabled|permitted)|snmp.*writ(e|able)", s, re.I):
                out["write_community"] = True
            if not s or s.startswith("-"):
                continue
            if section is None:
                continue
            if "system information" in section:
                kv = re.match(r"^(.+?)\s*:\s*(.*)$", s)
                if kv:
                    key, val = kv.group(1).strip().lower(), kv.group(2).strip()
                    if key.startswith("host ip"):
                        out["host"] = val
                    elif key == "description":
                        out["sysdescr"] = val
            elif "user accounts" in section:
                for u in s.split():
                    if u not in out["users"]:
                        out["users"].append(u)
            elif section.startswith("processes"):
                cols = re.split(r"\s{2,}", s)
                if cols and cols[0].lower() in ("id", "pid"):
                    continue
                if len(cols) >= 3:
                    name = cols[2]
                    args = cols[4] if len(cols) > 4 else ""
                    out["processes"].append((name + " " + args).strip())
            elif "routing information" in section:
                cols = s.split()
                if cols and cols[0].lower() == "destination":
                    continue
                if len(cols) >= 3 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cols[0]):
                    out["routes"].append({"dest": cols[0], "next_hop": cols[1],
                                          "mask": cols[2]})
    return out


# ---------------------------------------------------------------- aggregation

def subnet_of(addr, mask):
    try:
        net = ipaddress.ip_network("%s/%s" % (addr, mask), strict=False)
        if net.prefixlen == 32 or net.is_loopback or net.is_multicast:
            return None
        if str(net.network_address) == "0.0.0.0":
            return None
        return str(net)
    except ValueError:
        return None


def kv_pairs(values):
    out = {}
    for v in values or []:
        if "=" not in v:
            sys.exit("expected HOST=FILE (or HOST=VALUE), got: %r" % v)
        k, _, val = v.partition("=")
        out.setdefault(k, []).append(val)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hits", action="append", default=[],
                    help="onesixtyone -o output file (repeatable)")
    ap.add_argument("--walk", action="append", default=[], metavar="HOST=FILE",
                    help="snmpwalk/snmpbulkwalk output for HOST (repeatable)")
    ap.add_argument("--check", action="append", default=[], metavar="HOST=FILE",
                    help="snmp-check output for HOST (repeatable)")
    ap.add_argument("--write-community", action="append", default=[],
                    metavar="HOST=COMMUNITY", help="confirmed write community (repeatable)")
    ap.add_argument("--version", default="2c", help="SNMP version used (default 2c)")
    ap.add_argument("--out-dir", default="snmp_out")
    args = ap.parse_args()

    hosts = {}  # host -> record

    def rec(h):
        return hosts.setdefault(h, {
            "host": h, "community": None, "version": args.version,
            "sysdescr": None, "users": [], "processes": [], "routes": [],
            "write_community": False, "secrets": [], "walked": False})

    for path in args.hits:
        for hit in parse_onesixtyone(path):
            r = rec(hit["host"])
            if r["community"] is None:
                r["community"] = hit["community"]
            if not r["sysdescr"]:
                r["sysdescr"] = hit["sysdescr"] or None

    for host, files in kv_pairs(args.walk).items():
        r = rec(host)
        r["walked"] = True
        for path in files:
            w = parse_walk(path)
            r["sysdescr"] = r["sysdescr"] or w["sysdescr"]
            r["users"] = sorted(set(r["users"]) | set(w["users"]))
            procs = []
            for idx, name in sorted(w["processes"].items()):
                procs.append((name + " " + w["proc_args"].get(idx, "")).strip())
            r["processes"] = sorted(set(r["processes"]) | set(procs))
            r["routes"].extend(x for x in w["routes"] if x not in r["routes"])
            r["secrets"].extend(s for s in w["secrets"] if s not in r["secrets"])
            r.setdefault("_ipaddrs", {}).update(w["ipaddrs"])
            r.setdefault("_ipmasks", {}).update(w["ipmasks"])

    for host, files in kv_pairs(args.check).items():
        r = rec(host)
        for path in files:
            c = parse_snmpcheck(path)
            r["sysdescr"] = r["sysdescr"] or c["sysdescr"]
            r["users"] = sorted(set(r["users"]) | set(c["users"]))
            r["processes"] = sorted(set(r["processes"]) | set(c["processes"]))
            r["routes"].extend(x for x in c["routes"] if x not in r["routes"])
            r["write_community"] = r["write_community"] or c["write_community"]
            r["secrets"].extend(p for p in c["processes"]
                                if SECRET_RE.search(p) and p not in r["secrets"])

    for host, comms in kv_pairs(args.write_community).items():
        r = rec(host)
        r["write_community"] = True
        r["community"] = r["community"] or comms[0]

    # ---- discovered subnets
    subnets = set()
    for r in hosts.values():
        for idx, addr in (r.pop("_ipaddrs", {}) or {}).items():
            mask = r.get("_ipmasks", {}).get(idx) if "_ipmasks" in r else None
            mask = mask or "255.255.255.0"
            n = subnet_of(addr, mask)
            if n:
                subnets.add(n)
        r.pop("_ipmasks", None)
        for rt in r["routes"]:
            if rt.get("dest") and rt.get("mask"):
                n = subnet_of(rt["dest"], rt["mask"])
                if n:
                    subnets.add(n)

    # ---- work units
    units = []
    for h, r in sorted(hosts.items()):
        comm = r["community"] or "public"
        if r["community"] and not r["walked"]:
            units.append({
                "id": "snmp-fullwalk-%s-%s" % (h, comm),
                "title": "Full SNMP walk of %s with community '%s' (v%s)" % (h, comm, r["version"]),
                "targets": [h],
                "hints": [
                    "snmpbulkwalk -v2c -c %s %s .1 > walk_%s_%s.txt" % (comm, h, h, comm),
                    "then re-run parse_snmp.py with --walk %s=walk_%s_%s.txt" % (h, h, comm),
                    "grep walks for creds: grep -iE 'pass|secret|key' walk_%s_%s.txt" % (h, comm)]})
        if r["community"] and not r["write_community"]:
            units.append({
                "id": "snmp-write-test-%s" % h,
                "title": "Test SNMP write access on %s" % h,
                "targets": [h],
                "hints": [
                    "snmpget -v2c -c %s %s 1.3.6.1.2.1.1.4.0  # save sysContact" % (comm, h),
                    "snmpset -v2c -c %s %s 1.3.6.1.2.1.1.4.0 s probe-rw && restore original" % (comm, h),
                    "try classic rw strings too: private, write, admin"]})
        if r["write_community"] and r["sysdescr"] and "cisco" in r["sysdescr"].lower():
            units.append({
                "id": "snmp-cisco-confexfil-%s" % h,
                "title": "Exfiltrate Cisco running-config from %s via CISCO-CONFIG-COPY (rw community)" % h,
                "targets": [h],
                "hints": [
                    "stand up tftp, then ccCopyTable snmpset sequence (snmp-enum SKILL.md section 6)",
                    "poll 1.3.6.1.4.1.9.9.96.1.1.1.1.10.$R for copyState=3",
                    "crack type-7/secret hashes from the config; harvest snmp/vpn/tacacs keys"]})
        if r["secrets"]:
            units.append({
                "id": "cred-followup-%s" % h,
                "title": "Chase credential material found in SNMP process cmdlines on %s" % h,
                "targets": [h],
                "hints": ["candidates: " + " | ".join(r["secrets"][:5]),
                          "test creds against services from tcpConnTable and the wider scope"]})
        if r["users"]:
            units.append({
                "id": "spray-users-%s" % h,
                "title": "Password-spray %d usernames enumerated via SNMP from %s" % (len(r["users"]), h),
                "targets": [h],
                "hints": ["users: " + ",".join(r["users"][:20]),
                          "targets: smb/winrm/ssh on %s and its subnet" % h]})
    for n in sorted(subnets):
        units.append({
            "id": "host-discovery-%s" % n.replace("/", "_"),
            "title": "Host discovery on subnet %s learned from SNMP routes/interfaces" % n,
            "targets": [n],
            "hints": ["feed to the recon/host-discovery flow",
                      "nmap -sn %s ; then full port scan on responders" % n]})

    # ---- write outputs
    os.makedirs(args.out_dir, exist_ok=True)
    records = []
    for h, r in sorted(hosts.items()):
        records.append({k: r[k] for k in
                        ("host", "community", "version", "sysdescr", "users",
                         "processes", "routes", "write_community")})
    with open(os.path.join(args.out_dir, "snmp_enum.json"), "w") as f:
        json.dump(records, f, indent=2)
    with open(os.path.join(args.out_dir, "subnets.txt"), "w") as f:
        f.write("\n".join(sorted(subnets)) + ("\n" if subnets else ""))
    with open(os.path.join(args.out_dir, "work_units.json"), "w") as f:
        json.dump(units, f, indent=2)

    print("[parse_snmp] hosts=%d subnets=%d work_units=%d -> %s/"
          % (len(records), len(subnets), len(units), args.out_dir))


if __name__ == "__main__":
    main()
