#!/usr/bin/env python3
"""parse_rustscan.py — parse RustScan greppable (-g) output.

Accepts:
  * greppable lines:   192.0.2.10 -> [22,80,443]
  * normal-mode lines: Open 192.0.2.10:22

Produces:
  * inventory.json  — merged host/port inventory (source: "rustscan")
  * targets.tsv     — ip<TAB>comma-separated-ports (nmap deep-pass input)
  * work_units.json — optional rupu for_each fan-out: clean JSON ARRAY of
                      {id,title,targets,hints} deep-scan units (first byte '[')

Usage:
  python3 scripts/parse_rustscan.py rs.gnmap [more files...] \
      [--inventory inventory.json] [--targets targets.tsv] [--units work_units.json]

Stdlib only. vulture / lavender-bastion
"""
import argparse
import ipaddress
import json
import os
import re
import sys

GREP_RE = re.compile(r"^(\S+)\s*->\s*\[([\d,\s]*)\]\s*$")
OPEN_RE = re.compile(r"^Open\s+(\S+):(\d+)\s*$")


def parse_file(path):
    """Yield (ip, port) tuples from a rustscan output file."""
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = GREP_RE.match(line)
            if m:
                ip, ports = m.groups()
                for p in ports.split(","):
                    p = p.strip()
                    if p.isdigit():
                        yield ip, int(p)
                continue
            m = OPEN_RE.match(line)
            if m:
                yield m.group(1), int(m.group(2))


def load_inventory(path):
    if os.path.exists(path):
        try:
            with open(path) as fh:
                inv = json.load(fh)
            if isinstance(inv, dict) and isinstance(inv.get("hosts"), dict):
                return inv
        except ValueError:
            pass
    return {"hosts": {}}


def merge(inv, pairs, source):
    added = 0
    for ip, port in pairs:
        host = inv["hosts"].setdefault(ip, {"ports": []})
        if any(p["port"] == port and p.get("proto", "tcp") == "tcp"
               for p in host["ports"]):
            continue
        host["ports"].append({"port": port, "proto": "tcp",
                              "state": "open", "source": source})
        added += 1
    return added


def ip_sort_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def write_targets(inv, path):
    rows = []
    for ip in sorted(inv["hosts"], key=ip_sort_key):
        ports = sorted({p["port"] for p in inv["hosts"][ip]["ports"]
                        if p.get("proto", "tcp") == "tcp" and p.get("state") == "open"})
        if ports:
            rows.append((ip, ",".join(str(p) for p in ports)))
    with open(path, "w") as fh:
        for ip, ports in rows:
            fh.write("%s\t%s\n" % (ip, ports))
    return rows


def write_units(rows, path, source):
    units = []
    for ip, ports in rows:
        units.append({
            "id": "deep-scan-%s" % ip.replace(":", "_"),
            "title": "deep-scan %s:%s" % (ip, ports),
            "targets": [ip],
            "hints": [
                "ports discovered by %s: %s" % (source, ports),
                "nmap -sS -sV -sC -Pn -p%s -oA scans/deep_%s %s" % (ports, ip, ip),
                "load the nmap skill for flag selection and output parsing",
            ],
        })
    with open(path, "w") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    return len(units)


def main():
    ap = argparse.ArgumentParser(description="Parse RustScan -g output.")
    ap.add_argument("files", nargs="+", help="rustscan output files (-g or normal)")
    ap.add_argument("--inventory", default="inventory.json")
    ap.add_argument("--targets", default="targets.tsv")
    ap.add_argument("--units", default=None,
                    help="also write rupu work-unit JSON array here")
    args = ap.parse_args()

    inv = load_inventory(args.inventory)
    total = 0
    for path in args.files:
        total += merge(inv, parse_file(path), "rustscan")

    with open(args.inventory, "w") as fh:
        json.dump(inv, fh, indent=2)
        fh.write("\n")

    rows = write_targets(inv, args.targets)
    if args.units:
        n = write_units(rows, args.units, "rustscan")
        print("[+] %d work units -> %s" % (n, args.units))

    print("[+] %d new port entries merged into %s (%d hosts)"
          % (total, args.inventory, len(inv["hosts"])))
    print("[+] %d target rows -> %s" % (len(rows), args.targets))


if __name__ == "__main__":
    sys.exit(main())
