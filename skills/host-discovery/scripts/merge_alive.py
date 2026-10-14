#!/usr/bin/env python3
"""merge_alive.py - merge mixed host-discovery outputs into one alive.txt.

Accepts any mix of:
  * fping / zmap          : one bare IP per line
  * arp-scan              : "IP<TAB>MAC<TAB>Vendor"
  * netdiscover (-P)      : "IP  MAC  count  len  Vendor"
  * nmap grepable (-oG)   : "Host: IP (name)  Status: Up"
  * nbtscan               : "IP  NAME\\SHARE  server  user  MAC" (or -s : form)

Extracts IPv4 addresses of live hosts, dedupes, sorts numerically, writes
alive.txt, and optionally emits a JSON ARRAY (first byte '[') of
{id,title,targets,hints} port-scan work units for the next phase.

Usage:
  python3 scripts/merge_alive.py disc/*.txt disc/*.gnmap -o alive.txt --units units.json
  cat fping.txt | python3 scripts/merge_alive.py - -o alive.txt
"""
import argparse
import ipaddress
import json
import re
import sys

IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")


def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_multicast or ip.is_unspecified or s.endswith(".255"))
    except ValueError:
        return False


def classify(line):
    """Guess which tool produced this line (for the hints field)."""
    l = line.strip()
    if not l:
        return None
    if l.startswith("#") or l.lower().startswith(("interface:", "starting", "ending",
                                                  "currently scanning", "warning",
                                                  "doing nbt", "ip address", "---")):
        return None
    if l.startswith("Host:"):
        return "nmap"
    if "\t" in l and MAC_RE.search(l):
        return "arp-scan"
    if MAC_RE.search(l) and IP_RE.match(l):
        # netdiscover or nbtscan row (MAC later in line)
        return "netdiscover/nbtscan"
    if IP_RE.fullmatch(l):
        return "fping/zmap"
    if IP_RE.match(l):
        return "sweep"
    return "other" if IP_RE.search(l) else None


def parse_line(line, source_name):
    """Return (ip, hints:list[str]) or None."""
    kind = classify(line)
    if kind is None:
        return None
    l = line.strip()

    if kind == "nmap":
        # Host: 203.0.113.10 (name.example.com)   Status: Up
        if "Status: Up" not in l and "Ports:" not in l:
            return None
        m = IP_RE.search(l)
        if not m:
            return None
        ip = m.group(1)
        hints = []
        hm = re.search(r"\(([^)]+)\)", l)
        if hm and hm.group(1).strip():
            hints.append("hostname=" + hm.group(1).strip())
        return (ip, hints) if valid_ip(ip) else None

    m = IP_RE.search(l)
    if not m or not valid_ip(m.group(1)):
        return None
    ip = m.group(1)
    hints = []
    mm = MAC_RE.search(l)
    if mm:
        hints.append("mac=" + mm.group(1).lower())
        # vendor = text after the MAC (arp-scan / netdiscover tail)
        tail = l[mm.end():].strip()
        tail = re.sub(r"^\d+\s+\d+\s*", "", tail)  # netdiscover count/len cols
        if tail and not IP_RE.search(tail):
            hints.append("vendor=" + tail)
    # nbtscan: second column is NetBIOS name (contains letters, no dots-only)
    cols = l.split()
    if len(cols) >= 2 and not MAC_RE.match(cols[1]) and not IP_RE.match(cols[1]) \
            and re.search(r"[A-Za-z]", cols[1]) and "=" not in cols[1] \
            and "nbtscan" in source_name.lower():
        hints.append("netbios=" + cols[1])
    return ip, hints


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="discovery output files ('-' for stdin)")
    ap.add_argument("-o", "--output", default="alive.txt", help="merged host list")
    ap.add_argument("--units", help="write JSON work-units array here")
    args = ap.parse_args()

    hosts = {}  # ip -> {"sources": set, "hints": set}

    for path in args.files:
        name = "stdin" if path == "-" else path
        try:
            fh = sys.stdin if path == "-" else open(path, errors="replace")
        except OSError as e:
            print(f"[!] skip {path}: {e}", file=sys.stderr)
            continue
        with fh:
            for line in fh:
                parsed = parse_line(line, name)
                if not parsed:
                    continue
                ip, hints = parsed
                rec = hosts.setdefault(ip, {"sources": set(), "hints": set()})
                rec["sources"].add(name.rsplit("/", 1)[-1])
                rec["hints"].update(hints)

    ips = sorted(hosts, key=lambda s: tuple(int(o) for o in s.split(".")))

    with open(args.output, "w") as f:
        f.write("\n".join(ips) + ("\n" if ips else ""))
    print(f"[+] {len(ips)} unique live hosts -> {args.output}", file=sys.stderr)

    if args.units:
        units = []
        for ip in ips:
            rec = hosts[ip]
            hint_bits = ["seen via: " + ", ".join(sorted(rec["sources"]))]
            hint_bits.extend(sorted(rec["hints"]))
            units.append({
                "id": "portscan-" + ip.replace(".", "-"),
                "title": f"port-scan {ip}",
                "targets": [ip],
                "hints": "; ".join(hint_bits),
            })
        with open(args.units, "w") as f:
            json.dump(units, f, indent=2)
            f.write("\n")
        print(f"[+] {len(units)} work units -> {args.units}", file=sys.stderr)


if __name__ == "__main__":
    main()
