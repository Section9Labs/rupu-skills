#!/usr/bin/env python3
"""parse_nmap_xml.py - merge one or more Nmap -oX XML files into inventory.json.

Output: a JSON object keyed by host address:

    {
      "192.0.2.10": {
        "address": "192.0.2.10",
        "hostnames": ["host.example.com"],
        "status": "up",
        "os": {"name": "Linux 5.4", "accuracy": 96},
        "ports": [
          {"port": 445, "proto": "tcp", "state": "open",
           "service": "microsoft-ds", "product": "Windows Server 2019",
           "version": "10.0", "extrainfo": "workgroup: EXAMPLE",
           "scripts": {"smb2-security-mode": "..."},
           "source": "nmap"}
        ]
      }
    }

Robust to missing fields; multiple XMLs are merged (later files refine
earlier results: port entries are merged per (port, proto), scripts and
version fields are unioned, OS kept at highest accuracy).

Usage:
    python3 parse_nmap_xml.py scans/*.xml -o inventory.json
    python3 parse_nmap_xml.py scans/03-tcp-full.xml scans/05-deep.xml   # stdout
Signed-off: vulture (plum-quarter)
"""

import argparse
import glob
import json
import sys
import xml.etree.ElementTree as ET


def host_address(host_el):
    """Prefer IPv4, then IPv6, then MAC."""
    addrs = {}
    for a in host_el.findall("address"):
        addrs[a.get("addrtype", "ipv4")] = a.get("addr")
    return addrs.get("ipv4") or addrs.get("ipv6") or addrs.get("mac")


def parse_host(host_el):
    addr = host_address(host_el)
    if not addr:
        return None

    status_el = host_el.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"

    hostnames = []
    hn_el = host_el.find("hostnames")
    if hn_el is not None:
        for hn in hn_el.findall("hostname"):
            name = hn.get("name")
            if name and name not in hostnames:
                hostnames.append(name)

    os_info = {}
    os_el = host_el.find("os")
    if os_el is not None:
        best, best_acc = None, -1
        for match in os_el.findall("osmatch"):
            try:
                acc = int(match.get("accuracy", "0"))
            except ValueError:
                acc = 0
            if acc > best_acc:
                best, best_acc = match.get("name"), acc
        if best:
            os_info = {"name": best, "accuracy": best_acc}

    ports = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for p in ports_el.findall("port"):
            try:
                portid = int(p.get("portid", "0"))
            except ValueError:
                continue
            state_el = p.find("state")
            svc_el = p.find("service")
            scripts = {}
            for s in p.findall("script"):
                sid = s.get("id")
                if sid:
                    scripts[sid] = (s.get("output") or "").strip()
            ports.append({
                "port": portid,
                "proto": p.get("protocol", "tcp"),
                "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
                "service": svc_el.get("name", "") if svc_el is not None else "",
                "product": svc_el.get("product", "") if svc_el is not None else "",
                "version": svc_el.get("version", "") if svc_el is not None else "",
                "extrainfo": svc_el.get("extrainfo", "") if svc_el is not None else "",
                "scripts": scripts,
                "source": "nmap",
            })

    # host scripts (smb-os-discovery etc.) recorded as pseudo-port 0
    hostscripts = {}
    hs_el = host_el.find("hostscript")
    if hs_el is not None:
        for s in hs_el.findall("script"):
            sid = s.get("id")
            if sid:
                hostscripts[sid] = (s.get("output") or "").strip()
    if hostscripts:
        ports.append({
            "port": 0, "proto": "host", "state": "n/a",
            "service": "hostscript", "product": "", "version": "",
            "extrainfo": "", "scripts": hostscripts, "source": "nmap",
        })

    return {
        "address": addr,
        "hostnames": hostnames,
        "status": status,
        "os": os_info,
        "ports": ports,
    }


STATE_RANK = {"open": 3, "open|filtered": 2, "unfiltered": 1,
              "closed|filtered": 1, "filtered": 0, "closed": 0}


def merge_port(existing, new):
    """Merge a new port record into an existing one (same port/proto)."""
    # prefer the more definite state
    if STATE_RANK.get(new["state"], 0) >= STATE_RANK.get(existing["state"], 0):
        existing["state"] = new["state"]
    for field in ("service", "product", "version", "extrainfo"):
        if new.get(field):
            existing[field] = new[field]
    existing["scripts"].update(new.get("scripts", {}))


def merge_host(inv, host):
    addr = host["address"]
    if addr not in inv:
        inv[addr] = host
        return
    cur = inv[addr]
    if host["status"] == "up":
        cur["status"] = "up"
    for hn in host["hostnames"]:
        if hn not in cur["hostnames"]:
            cur["hostnames"].append(hn)
    if host["os"] and host["os"].get("accuracy", 0) >= cur.get("os", {}).get("accuracy", -1):
        cur["os"] = host["os"]
    index = {(p["port"], p["proto"]): p for p in cur["ports"]}
    for p in host["ports"]:
        key = (p["port"], p["proto"])
        if key in index:
            merge_port(index[key], p)
        else:
            cur["ports"].append(p)


def parse_file(path, inv):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        # salvage truncated XML from interrupted scans
        sys.stderr.write("[!] %s: XML parse error (%s); attempting salvage\n" % (path, e))
        try:
            with open(path, "r", errors="replace") as f:
                data = f.read()
            data += "</nmaprun>"
            root = ET.fromstring(data)
        except ET.ParseError:
            sys.stderr.write("[!] %s: unrecoverable, skipped\n" % path)
            return 0
    n = 0
    for host_el in root.findall("host"):
        host = parse_host(host_el)
        if host:
            merge_host(inv, host)
            n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description="Merge Nmap -oX XML into inventory.json")
    ap.add_argument("xml", nargs="+", help="Nmap XML file(s) or globs")
    ap.add_argument("-o", "--output", default=None,
                    help="output path (default: stdout)")
    ap.add_argument("--up-only", action="store_true",
                    help="include only hosts whose status is up")
    args = ap.parse_args()

    paths = []
    for pattern in args.xml:
        matched = glob.glob(pattern)
        paths.extend(matched if matched else [pattern])

    inv = {}
    total = 0
    for path in paths:
        total += parse_file(path, inv)

    if args.up_only:
        inv = {a: h for a, h in inv.items() if h["status"] == "up"}

    out = json.dumps(inv, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out + "\n")
        up = sum(1 for h in inv.values() if h["status"] == "up")
        open_ports = sum(1 for h in inv.values() for p in h["ports"]
                         if p["state"].startswith("open"))
        sys.stderr.write("[+] %d host records parsed, %d unique hosts (%d up), "
                         "%d open ports -> %s\n"
                         % (total, len(inv), up, open_ports, args.output))
    else:
        print(out)


if __name__ == "__main__":
    main()
