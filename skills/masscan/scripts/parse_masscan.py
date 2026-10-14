#!/usr/bin/env python3
"""parse_masscan.py — parse masscan -oL (list) and -oJ (JSON) output.

Produces:
  * inventory.json  — merged host/port inventory (source: "masscan")
  * targets.tsv     — ip<TAB>comma-separated-tcp-ports  (nmap deep-pass input)
  * targets-udp.tsv — same for UDP hits, if any
  * work_units.json — optional rupu for_each fan-out: clean JSON ARRAY of
                      {id,title,targets,hints} deep-scan units (first byte '[')

Usage:
  python3 scripts/parse_masscan.py sweep.lst [more files...] \
      [--inventory inventory.json] [--targets targets.tsv] [--units work_units.json]

Stdlib only. vulture / lavender-bastion
"""
import argparse
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict

LIST_RE = re.compile(
    r"^(open|closed|banner)\s+(tcp|udp|icmp|sctp)\s+(\d+)\s+(\S+)\s+(\d+)(?:\s+(.*))?$"
)


def parse_list(text):
    """Yield dicts from masscan -oL lines: state proto port ip ts [svc banner]."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LIST_RE.match(line)
        if not m:
            continue
        state, proto, port, ip, ts, extra = m.groups()
        rec = {"ip": ip, "port": int(port), "proto": proto,
               "state": "open", "timestamp": int(ts)}
        if state == "banner" and extra:
            parts = extra.split(None, 1)
            rec["service"] = parts[0]
            if len(parts) > 1:
                rec["banner"] = parts[1]
        elif state == "closed":
            continue
        yield rec


def parse_json(text):
    """Parse masscan -oJ. Tolerates trailing commas / 'finished' pseudo-records."""
    recs = []
    try:
        data = json.loads(text)
    except ValueError:
        data = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                data.append(json.loads(line))
            except ValueError:
                continue
    for obj in data:
        if not isinstance(obj, dict) or "ip" not in obj:
            continue
        ts = obj.get("timestamp")
        for p in obj.get("ports", []):
            if p.get("status") not in (None, "open"):
                continue
            rec = {"ip": obj["ip"], "port": int(p["port"]),
                   "proto": p.get("proto", "tcp"), "state": "open"}
            if ts is not None:
                try:
                    rec["timestamp"] = int(ts)
                except (TypeError, ValueError):
                    rec["timestamp"] = ts
            svc = p.get("service") or {}
            if isinstance(svc, dict):
                if svc.get("name"):
                    rec["service"] = svc["name"]
                if svc.get("banner"):
                    rec["banner"] = svc["banner"]
            recs.append(rec)
    return recs


def sniff_and_parse(path):
    with open(path, "r", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        return list(parse_json(text))
    return list(parse_list(text))


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
        existing = {(p["port"], p.get("proto", "tcp")) for p in host["ports"]}
        key = (rec["port"], rec["proto"])
        entry = dict(rec)
        entry.pop("ip", None)
        entry["source"] = source
        if key in existing:
            for p in host["ports"]:
                if (p["port"], p.get("proto", "tcp")) == key:
                    for k in ("service", "banner"):
                        if entry.get(k) and not p.get(k):
                            p[k] = entry[k]
                    break
        else:
            host["ports"].append(entry)
            added += 1
    return added


def ip_sort_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def write_targets(inv, path, proto):
    rows = []
    for ip in sorted(inv["hosts"], key=ip_sort_key):
        ports = sorted({p["port"] for p in inv["hosts"][ip]["ports"]
                        if p.get("proto", "tcp") == proto and p.get("state") == "open"})
        if ports:
            rows.append((ip, ",".join(str(p) for p in ports)))
    if rows:
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
    ap = argparse.ArgumentParser(description="Parse masscan -oL/-oJ output.")
    ap.add_argument("files", nargs="+", help="masscan output files (-oL or -oJ)")
    ap.add_argument("--inventory", default="inventory.json")
    ap.add_argument("--targets", default="targets.tsv")
    ap.add_argument("--units", default=None,
                    help="also write rupu work-unit JSON array here")
    args = ap.parse_args()

    inv = load_inventory(args.inventory)
    total = 0
    for path in args.files:
        recs = sniff_and_parse(path)
        total += merge(inv, recs, "masscan")

    with open(args.inventory, "w") as fh:
        json.dump(inv, fh, indent=2)
        fh.write("\n")

    tcp_rows = write_targets(inv, args.targets, "tcp")
    udp_base, udp_ext = os.path.splitext(args.targets)
    udp_rows = write_targets(inv, udp_base + "-udp" + (udp_ext or ".tsv"), "udp")

    if args.units:
        n = write_units(tcp_rows, args.units, "masscan")
        print("[+] %d work units -> %s" % (n, args.units))

    print("[+] %d new port entries merged into %s (%d hosts)"
          % (total, args.inventory, len(inv["hosts"])))
    print("[+] %d TCP target rows -> %s" % (len(tcp_rows), args.targets))
    if udp_rows:
        print("[+] %d UDP target rows -> %s"
              % (len(udp_rows), udp_base + "-udp" + (udp_ext or ".tsv")))


if __name__ == "__main__":
    sys.exit(main())
