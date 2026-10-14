#!/usr/bin/env python3
"""parse_dns.py — consolidate DNS recon tool output into a port-scan handoff.

Ingests any mix of output files from:
  subfinder (plain names)          amass enum (plain names or v4 triples)
  massdns -o S / -o J              dnsx -resp (plain or -json)
  dnsrecon -c CSV / -j JSON        dnsenum / fierce / dig / host text logs
  plain host or IP lists           dnsx -ptr output

Auto-detects the format line by line. Emits into --out-dir:
  resolved_hosts.txt   hostname<TAB>ip[,ip...]  (validated pairs)
  scan-targets.txt     unique live IPs, one per line
  work-units.json      JSON ARRAY (first byte '[') of {id,title,targets,hints}
                       "port-scan <netblock>" work units, grouped by /24 (v4)
                       or /64 (v6), rupu-ingestible (see references/rupu.md)

The JSON array is also mirrored on stdout; a summary goes to stderr.

Usage:
  python3 scripts/parse_dns.py --out-dir out resolved.txt massdns.txt \
      subfinder.txt amass.txt dnsrecon.csv ptr.txt

vulture / violet-valley
"""
import argparse
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict

HOST_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,62})\.)+[a-z]{2,63}$", re.I
)
# tokens that look like hostnames inside arbitrary text
HOST_TOKEN_RE = re.compile(
    r"\b((?:[a-z0-9_](?:[a-z0-9_-]{0,62})\.)+[a-z]{2,63})\.?\b", re.I
)
IP_TOKEN_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b|\b([0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})\b", re.I
)
RECORD_TYPES = {"A", "AAAA", "CNAME", "PTR", "MX", "NS", "TXT", "SOA", "SRV"}


def norm_host(h):
    h = h.strip().strip('"').rstrip(".").lower()
    if h.startswith("*."):
        h = h[2:]
    return h if HOST_RE.match(h) else None


def norm_ip(s):
    try:
        return str(ipaddress.ip_address(s.strip()))
    except ValueError:
        return None


class Store:
    def __init__(self):
        self.hosts = set()                 # every hostname seen
        self.pairs = defaultdict(set)      # host -> {ip, ...}
        self.cnames = defaultdict(set)     # host -> {cname target, ...}
        self.loose_ips = set()             # ips seen without a host pairing

    def add_host(self, h):
        h = norm_host(h) if h else None
        if h:
            self.hosts.add(h)
        return h

    def add_pair(self, h, ip):
        h = self.add_host(h)
        ip = norm_ip(ip) if ip else None
        if ip:
            self.loose_ips.add(ip)
            if h:
                self.pairs[h].add(ip)

    def add_cname(self, h, tgt):
        h = self.add_host(h)
        tgt = norm_host(tgt) if tgt else None
        if h and tgt:
            self.cnames[h].add(tgt)
            self.hosts.add(tgt)


def parse_json_obj(obj, st):
    """dnsx -json / massdns -o J / dnsrecon -j objects."""
    if not isinstance(obj, dict):
        return
    host = obj.get("host") or obj.get("name") or obj.get("query_name") or obj.get("target")
    rtype = (obj.get("type") or "").upper()
    # dnsx -json
    for key in ("a", "aaaa"):
        for ip in obj.get(key) or []:
            st.add_pair(host, ip)
    for c in obj.get("cname") or []:
        st.add_cname(host, c)
    for p in obj.get("ptr") or []:
        st.add_host(p)
    # dnsrecon -j: {"type":"A","name":"www.example.com","address":"192.0.2.10"}
    addr = obj.get("address") or obj.get("data")
    name = obj.get("name") or host
    if addr and name:
        if rtype in ("A", "AAAA") or norm_ip(addr):
            st.add_pair(name, addr)
        elif rtype == "CNAME":
            st.add_cname(name, addr)
        elif rtype == "PTR":
            st.add_host(addr)
    # massdns -o J: {"name":"www.example.com.","data":{"answers":[{...}]}}
    data = obj.get("data")
    if isinstance(data, dict):
        for ans in data.get("answers") or []:
            parse_json_obj(ans, st)
    if host and not addr:
        st.add_host(host)


def parse_line(line, st):
    line = line.strip()
    if not line or line.startswith(("#", ";", "[-]")):
        return
    # dnsrecon text lines like "[*] 	 A www.example.com 192.0.2.10" still carry data
    if line.startswith(("[*]", "[+]")):
        line = line.lstrip("[*+] \t")
    if not line:
        return

    # JSON line? (dnsx -json, massdns -o J, dnsrecon -j fragments)
    if line[0] in "{[":
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if obj is not None:
            if isinstance(obj, list):
                for o in obj:
                    parse_json_obj(o, st)
            else:
                parse_json_obj(obj, st)
            return

    # dnsx -resp:  www.example.com [A] [192.0.2.10]   /  host [CNAME] [tgt]
    m = re.match(r"^(\S+)\s+\[(\w+)\]\s+\[([^\]]+)\]", line)
    if m:
        host, rtype, val = m.group(1), m.group(2).upper(), m.group(3)
        if rtype in ("A", "AAAA"):
            st.add_pair(host, val)
        elif rtype == "CNAME":
            st.add_cname(host, val)
        elif rtype == "PTR":
            st.add_host(val)
            st.loose_ips.update(i for i in [norm_ip(host)] if i)
        else:
            st.add_host(host)
        return

    # amass v4 triple: www.example.com (FQDN) --> a_record --> 192.0.2.10 (IPAddress)
    if "-->" in line:
        parts = [p.strip() for p in line.split("-->")]
        if len(parts) >= 3:
            src = parts[0].split(" ")[0]
            rel = parts[1].lower()
            dst = parts[2].split(" ")[0]
            if "a_record" in rel or "aaaa" in rel:
                st.add_pair(src, dst)
            elif "cname" in rel:
                st.add_cname(src, dst)
            elif "ptr" in rel:
                st.add_host(dst)
            else:
                st.add_host(src)
                st.add_host(dst)
            return

    # CSV (dnsrecon -c): Type,Name,Address[,...]  with possible header
    if "," in line and "\t" not in line:
        fields = [f.strip() for f in line.split(",")]
        if fields[0].upper() in RECORD_TYPES and len(fields) >= 3:
            rtype, name, addr = fields[0].upper(), fields[1], fields[2]
            if rtype in ("A", "AAAA"):
                st.add_pair(name, addr)
            elif rtype == "CNAME":
                st.add_cname(name, addr)
            elif rtype == "PTR":
                st.add_host(addr)
            else:
                st.add_host(name)
            return
        if fields[0].lower() in ("type", "domain"):  # header row
            return

    # whitespace-token records: massdns -o S, dig answers, host output
    toks = line.split()
    if len(toks) >= 3:
        # massdns -o S:  www.example.com. A 192.0.2.10
        if toks[1].upper() in RECORD_TYPES:
            rtype = toks[1].upper()
            if rtype in ("A", "AAAA"):
                st.add_pair(toks[0], toks[2])
            elif rtype == "CNAME":
                st.add_cname(toks[0], toks[2])
            elif rtype == "PTR":
                st.add_host(toks[2])
            else:
                st.add_host(toks[0])
            return
        # dig answer:  www.example.com. 300 IN A 192.0.2.10
        if "IN" in toks:
            i = toks.index("IN")
            if len(toks) > i + 2:
                rtype = toks[i + 1].upper()
                if rtype in ("A", "AAAA"):
                    st.add_pair(toks[0], toks[i + 2])
                elif rtype == "CNAME":
                    st.add_cname(toks[0], toks[i + 2])
                elif rtype == "PTR":
                    st.add_host(toks[i + 2])
                else:
                    st.add_host(toks[0])
                return
        # host(1):  www.example.com has address 192.0.2.10
        if "address" in toks or "alias" in line:
            h = norm_host(toks[0])
            ips = [norm_ip(t) for t in toks]
            ips = [i for i in ips if i]
            if h and ips:
                for ip in ips:
                    st.add_pair(h, ip)
                return

    # single-token lines: plain hostname (subfinder/amass -passive) or bare IP
    if len(toks) == 1:
        if norm_ip(toks[0]):
            st.loose_ips.add(norm_ip(toks[0]))
        else:
            st.add_host(toks[0])
        return

    # fallback: scrape host/ip tokens from free text (dnsenum/fierce logs)
    hosts = [norm_host(h) for h in HOST_TOKEN_RE.findall(line)]
    hosts = [h for h in hosts if h]
    ips = [norm_ip(a or b) for a, b in IP_TOKEN_RE.findall(line)]
    ips = [i for i in ips if i]
    if hosts and ips:
        for ip in ips:
            st.add_pair(hosts[0], ip)
    else:
        for h in hosts:
            st.add_host(h)
        st.loose_ips.update(ips)


def netblock(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", help="tool output files (any mix)")
    ap.add_argument("--out-dir", default="out", help="output directory (default: out)")
    ap.add_argument("--no-stdout", action="store_true",
                    help="do not mirror work-units JSON on stdout")
    args = ap.parse_args()

    st = Store()
    for path in args.files:
        try:
            with open(path, "r", errors="replace") as fh:
                blob = fh.read()
        except OSError as e:
            print(f"[!] skip {path}: {e}", file=sys.stderr)
            continue
        # whole-file JSON (dnsrecon -j writes one array)
        stripped = blob.lstrip()
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                items = obj if isinstance(obj, list) else [obj]
                for o in items:
                    parse_json_obj(o, st)
                continue
            except ValueError:
                pass
        for line in blob.splitlines():
            parse_line(line, st)

    # resolve CNAME chains onto IPs where the target resolved
    for h, tgts in st.cnames.items():
        for t in tgts:
            st.pairs[h].update(st.pairs.get(t, set()))

    os.makedirs(args.out_dir, exist_ok=True)

    resolved = {h: sorted(ips) for h, ips in st.pairs.items() if ips}
    with open(os.path.join(args.out_dir, "resolved_hosts.txt"), "w") as fh:
        for h in sorted(resolved):
            fh.write(f"{h}\t{','.join(resolved[h])}\n")

    all_ips = sorted(st.loose_ips | {ip for ips in resolved.values() for ip in ips},
                     key=lambda i: ipaddress.ip_address(i))
    with open(os.path.join(args.out_dir, "scan-targets.txt"), "w") as fh:
        fh.write("\n".join(all_ips) + ("\n" if all_ips else ""))

    # group by netblock -> work units
    blocks = defaultdict(set)
    hints = defaultdict(list)
    for ip in all_ips:
        blocks[netblock(ip)].add(ip)
    for h in sorted(resolved):
        for ip in resolved[h]:
            hints[netblock(ip)].append(f"{h} -> {ip}")

    units = []
    for blk in sorted(blocks, key=lambda b: ipaddress.ip_network(b).network_address):
        targets = sorted(blocks[blk], key=lambda i: ipaddress.ip_address(i))
        uid = "port-scan-" + re.sub(r"[^0-9a-z]+", "-", blk.lower()).strip("-")
        units.append({
            "id": uid,
            "title": f"port-scan {blk} ({len(targets)} host{'s' if len(targets) != 1 else ''})",
            "targets": targets,
            "hints": hints.get(blk, []),
        })

    out_json = os.path.join(args.out_dir, "work-units.json")
    payload = json.dumps(units, indent=2)
    with open(out_json, "w") as fh:
        fh.write(payload + "\n")
    if not args.no_stdout:
        print(payload)

    unresolved = len(st.hosts) - len(resolved)
    print(
        f"[dns-recon] hosts={len(st.hosts)} resolved={len(resolved)} "
        f"unresolved={max(unresolved, 0)} ips={len(all_ips)} "
        f"netblocks={len(blocks)} units={len(units)} -> {args.out_dir}/ "
        f"(resolved_hosts.txt, scan-targets.txt, work-units.json)",
        file=sys.stderr,
    )
    # takeover triage hint: CNAMEs whose chain never reached an IP
    dangling = sorted(h for h, t in st.cnames.items() if not st.pairs.get(h))
    if dangling:
        print(f"[dns-recon] {len(dangling)} CNAME(s) with no resolving target "
              f"(takeover triage): " + ", ".join(dangling[:10]) +
              (" ..." if len(dangling) > 10 else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
