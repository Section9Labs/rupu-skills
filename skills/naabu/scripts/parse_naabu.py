#!/usr/bin/env python3
"""parse_naabu.py — parse naabu -json (JSONL) output.

Accepts:
  * JSONL records: {"host":"example.com","ip":"192.0.2.10","port":443,...}
    (handles both integer ports and older nested {"Port":443,"Protocol":"tcp"})
  * plain -silent lines as fallback: host:port

Produces:
  * inventory.json  — merged host/port inventory (source: "naabu")
  * targets.tsv     — ip<TAB>comma-separated-ports (nmap deep-pass input)
  * work_units.json — optional rupu for_each fan-out: clean JSON ARRAY of
                      {id,title,targets,hints} deep-scan units (first byte '[')

Usage:
  python3 scripts/parse_naabu.py naabu.jsonl [more files...] \
      [--inventory inventory.json] [--targets targets.tsv] [--units work_units.json]

Stdlib only. vulture / lavender-bastion
"""
import argparse
import ipaddress
import json
import os
import re
import sys

PLAIN_RE = re.compile(r"^(\S+?):(\d+)\s*$")


def normalize(obj):
    """Normalize a naabu JSONL record to {ip, host, port, proto, timestamp}."""
    port = obj.get("port")
    proto = obj.get("protocol") or "tcp"
    if isinstance(port, dict):  # older naabu: {"Port":443,"Protocol":"tcp"}
        proto = (port.get("Protocol") or port.get("protocol") or proto)
        port = port.get("Port") or port.get("port")
    if port is None:
        return None
    ip = obj.get("ip") or obj.get("host")
    if not ip:
        return None
    rec = {"ip": ip, "port": int(port), "proto": str(proto).lower(),
           "state": "open"}
    host = obj.get("host")
    if host and host != ip:
        rec["hostname"] = host
    if obj.get("timestamp"):
        rec["timestamp"] = obj["timestamp"]
    if obj.get("cdn") or obj.get("cdn-name"):
        rec["cdn"] = obj.get("cdn-name") or True
    return rec


def parse_file(path):
    recs = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    rec = normalize(json.loads(line))
                except ValueError:
                    rec = None
                if rec:
                    recs.append(rec)
                continue
            m = PLAIN_RE.match(line)
            if m:
                host, port = m.groups()
                h = host.strip("[]")  # [IPv6]:port
                recs.append({"ip": h, "port": int(port), "proto": "tcp",
                             "state": "open"})
    return recs


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


def merge(inv, recs, source):
    added = 0
    for rec in recs:
        host = inv["hosts"].setdefault(rec["ip"], {"ports": []})
        if rec.get("hostname"):
            names = host.setdefault("hostnames", [])
            if rec["hostname"] not in names:
                names.append(rec["hostname"])
        key = (rec["port"], rec["proto"])
        if any((p["port"], p.get("proto", "tcp")) == key for p in host["ports"]):
            continue
        entry = {"port": rec["port"], "proto": rec["proto"], "state": "open",
                 "source": source}
        for k in ("timestamp", "cdn", "hostname"):
            if rec.get(k):
                entry[k] = rec[k]
        host["ports"].append(entry)
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
    ap = argparse.ArgumentParser(description="Parse naabu -json output.")
    ap.add_argument("files", nargs="+", help="naabu JSONL (or host:port) files")
    ap.add_argument("--inventory", default="inventory.json")
    ap.add_argument("--targets", default="targets.tsv")
    ap.add_argument("--units", default=None,
                    help="also write rupu work-unit JSON array here")
    args = ap.parse_args()

    inv = load_inventory(args.inventory)
    total = 0
    for path in args.files:
        total += merge(inv, parse_file(path), "naabu")

    with open(args.inventory, "w") as fh:
        json.dump(inv, fh, indent=2)
        fh.write("\n")

    rows = write_targets(inv, args.targets)
    if args.units:
        n = write_units(rows, args.units, "naabu")
        print("[+] %d work units -> %s" % (n, args.units))

    print("[+] %d new port entries merged into %s (%d hosts)"
          % (total, args.inventory, len(inv["hosts"])))
    print("[+] %d target rows -> %s" % (len(rows), args.targets))


if __name__ == "__main__":
    sys.exit(main())
