#!/usr/bin/env python3
"""normalize_inventory.py — merge scanner outputs into one inventory.json.

Accepts any mix of:
  * nmap XML        (-oX / the .xml from -oA; also masscan -oX, same schema)
  * masscan JSON    (-oJ)
  * masscan list    (-oL:  "open tcp 445 192.0.2.10 1700000000")
  * masscan/nmap grepable (-oG: "Host: ... Ports: 445/open/tcp//...")
  * naabu           (JSON lines {"ip":...,"port":...} or plain host:port lines)
  * rustscan -g     ("192.0.2.10 -> [22,80,445]")

Format is detected per file by extension and content. Output is a JSON object
keyed by host address:

  {"192.0.2.10": {"address": "...", "hostnames": [...], "os": "...",
                  "ports": [{"port":445,"proto":"tcp","state":"open",
                             "service":"microsoft-ds","product":"...",
                             "version":"...","scripts":{...},"source":"nmap"}]}}

Usage:
  python3 scripts/normalize_inventory.py nmap-deep.xml masscan.json naabu.json \
      rustscan.txt -o inventory.json
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------- inventory --

def new_host(address):
    return {"address": address, "hostnames": [], "os": None, "ports": []}


def add_port(inv, address, port, proto, state="open", service=None,
             product=None, version=None, scripts=None, source=None):
    host = inv.setdefault(address, new_host(address))
    port = int(port)
    proto = (proto or "tcp").lower()
    for entry in host["ports"]:
        if entry["port"] == port and entry["proto"] == proto:
            # merge: prefer richer data, union sources
            if service and not entry.get("service"):
                entry["service"] = service
            if product and not entry.get("product"):
                entry["product"] = product
            if version and not entry.get("version"):
                entry["version"] = version
            if scripts:
                entry.setdefault("scripts", {}).update(scripts)
            if state == "open":
                entry["state"] = "open"
            if source and source not in entry["source"].split(","):
                entry["source"] += "," + source
            return
    host["ports"].append({
        "port": port, "proto": proto, "state": state,
        "service": service, "product": product, "version": version,
        "scripts": scripts or {}, "source": source or "unknown",
    })


def add_hostname(inv, address, name):
    if not name:
        return
    host = inv.setdefault(address, new_host(address))
    if name not in host["hostnames"]:
        host["hostnames"].append(name)


# ------------------------------------------------------------------ parsers --

def parse_nmap_xml(text, inv, source):
    root = ET.fromstring(text)
    # masscan -oX reuses the nmaprun schema; scanner attr tells us which.
    scanner = root.get("scanner") or source
    for h in root.iter("host"):
        addr = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if addr is None:
            continue
        status = h.find("status")
        if status is not None and status.get("state") == "down":
            continue
        inv.setdefault(addr, new_host(addr))
        hn = h.find("hostnames")
        if hn is not None:
            for n in hn.findall("hostname"):
                add_hostname(inv, addr, n.get("name"))
        # best OS match
        os_el = h.find("os")
        if os_el is not None:
            best, best_acc = None, -1
            for m in os_el.findall("osmatch"):
                try:
                    acc = int(m.get("accuracy", "0"))
                except ValueError:
                    acc = 0
                if acc > best_acc:
                    best, best_acc = m.get("name"), acc
            if best and not inv[addr]["os"]:
                inv[addr]["os"] = best
        ports_el = h.find("ports")
        if ports_el is None:
            continue
        for p in ports_el.findall("port"):
            state_el = p.find("state")
            state = state_el.get("state") if state_el is not None else "open"
            if state in ("closed",):
                continue
            svc = p.find("service")
            service = product = version = None
            if svc is not None:
                service = svc.get("name")
                product = svc.get("product")
                version = " ".join(filter(None, [svc.get("version"),
                                                 svc.get("extrainfo")])) or None
            scripts = {}
            for s in p.findall("script"):
                scripts[s.get("id")] = (s.get("output") or "").strip()
            add_port(inv, addr, p.get("portid"), p.get("protocol"), state,
                     service, product, version, scripts, scanner)
        # host-level scripts (e.g. smb-os-discovery) -> stash on host
        hs = h.find("hostscript")
        if hs is not None:
            hscripts = inv[addr].setdefault("hostscripts", {})
            for s in hs.findall("script"):
                hscripts[s.get("id")] = (s.get("output") or "").strip()


def parse_masscan_json(text, inv):
    # masscan -oJ: a JSON array, sometimes with a trailing comma / partial
    # final record if the scan was interrupted. Try strict, fall back to
    # per-object regex extraction.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for m in re.finditer(r"\{[^{}]*\"ip\"[^{}]*\"ports\"\s*:\s*\[[^\]]*\][^{}]*\}",
                             text, re.S):
            try:
                data.append(json.loads(m.group(0)))
            except json.JSONDecodeError:
                continue
    for rec in data:
        if not isinstance(rec, dict) or "ip" not in rec:
            continue
        for p in rec.get("ports", []):
            add_port(inv, rec["ip"], p.get("port"), p.get("proto", "tcp"),
                     "open" if p.get("status", "open") == "open" else p.get("status"),
                     service=(p.get("service") or {}).get("name")
                     if isinstance(p.get("service"), dict) else None,
                     source="masscan")


def parse_masscan_list(text, inv):
    # -oL: "open tcp 445 192.0.2.10 1700000000"
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] in ("open", "closed") \
                and parts[1] in ("tcp", "udp", "icmp", "sctp"):
            add_port(inv, parts[3], parts[2], parts[1], parts[0],
                     source="masscan")


def parse_grepable(text, inv, source):
    # -oG: "Host: 192.0.2.10 (name)  Ports: 445/open/tcp//microsoft-ds//, ..."
    for line in text.splitlines():
        m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not m:
            continue
        addr, name = m.group(1), m.group(2)
        inv.setdefault(addr, new_host(addr))
        add_hostname(inv, addr, name)
        pm = re.search(r"Ports:\s+(.*?)(?:\t|$)", line)
        if not pm:
            continue
        for spec in pm.group(1).split(","):
            fields = spec.strip().split("/")
            if len(fields) < 3:
                continue
            port, state, proto = fields[0], fields[1], fields[2]
            service = fields[4] if len(fields) > 4 and fields[4] else None
            product = fields[6] if len(fields) > 6 and fields[6] else None
            if state == "closed":
                continue
            add_port(inv, addr, port, proto, state, service, product,
                     source=source)


def parse_naabu(text, inv):
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            addr = rec.get("ip") or rec.get("host")
            if not addr:
                continue
            add_port(inv, addr, rec.get("port"),
                     rec.get("protocol", "tcp"), "open", source="naabu")
            host_field = rec.get("host")
            if host_field and host_field != addr:
                add_hostname(inv, addr, host_field)
        else:
            # host:port (IPv6 would be [addr]:port)
            m = re.match(r"\[?([0-9a-fA-F:.]+?)\]?:(\d+)$", line)
            if m:
                add_port(inv, m.group(1), m.group(2), "tcp", "open",
                         source="naabu")


def parse_rustscan(text, inv):
    # rustscan -g: "192.0.2.10 -> [22,80,445]"
    for line in text.splitlines():
        m = re.match(r"\s*(\S+)\s+->\s+\[([\d,\s]*)\]", line)
        if not m:
            continue
        for port in filter(None, re.split(r"[,\s]+", m.group(2))):
            add_port(inv, m.group(1), port, "tcp", "open", source="rustscan")


# ---------------------------------------------------------------- detection --

def detect_and_parse(path, inv):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip("\ufeff \t\r\n")
    if path.endswith(".xml") or stripped.startswith("<?xml") \
            or "<nmaprun" in stripped[:4096]:
        parse_nmap_xml(stripped, inv, "nmap")
        return "nmap-xml"
    if "Host:" in text and "Ports:" in text:
        parse_grepable(text, inv, "grepable")
        return "grepable"
    if stripped.startswith("[") or '"ports"' in stripped[:4096]:
        parse_masscan_json(stripped, inv)
        return "masscan-json"
    if re.search(r"^(open|closed)\s+(tcp|udp)\s+\d+\s+\S+", text, re.M):
        parse_masscan_list(text, inv)
        return "masscan-list"
    if re.search(r"->\s+\[", text):
        parse_rustscan(text, inv)
        return "rustscan"
    if re.search(r"^\S+:\d+\s*$", stripped, re.M) or stripped.startswith("{"):
        parse_naabu(text, inv)
        return "naabu"
    raise ValueError(f"could not detect format of {path}")


# --------------------------------------------------------------------- main --

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Merge nmap/masscan/naabu/rustscan outputs into one "
                    "inventory.json keyed by host.")
    ap.add_argument("inputs", nargs="+", help="scanner output files")
    ap.add_argument("-o", "--output", default="inventory.json",
                    help="output path (default: inventory.json)")
    args = ap.parse_args(argv)

    inv = {}
    for path in args.inputs:
        try:
            fmt = detect_and_parse(path, inv)
            print(f"[+] {path}: parsed as {fmt}", file=sys.stderr)
        except (OSError, ET.ParseError, ValueError) as exc:
            print(f"[!] {path}: {exc}", file=sys.stderr)

    for host in inv.values():
        host["ports"].sort(key=lambda e: (e["proto"], e["port"]))

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=2, sort_keys=True)
        fh.write("\n")

    nports = sum(len(h["ports"]) for h in inv.values())
    print(f"[+] wrote {args.output}: {len(inv)} hosts, {nports} port entries",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
