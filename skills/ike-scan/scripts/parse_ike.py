#!/usr/bin/env python3
"""parse_ike.py - parse ike-scan output into per-gateway JSON records plus
follow-up work units.

Handles single-line and -M (multiline) output, main and aggressive mode,
Notify messages, SA transform decode, Vendor IDs, --showbackoff
"Implementation guess" lines, --ikev2 output, and -P / --pskcrack
"IKE PSK parameters" captures.

Usage:
  python3 scripts/parse_ike.py ike-*.txt -o gateways.json --units units.json
  sudo ike-scan -A -M -f hosts.txt | python3 scripts/parse_ike.py - --units units.json
"""
import argparse
import json
import re
import sys

IP_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3})\s+(.*)$")
VID_RE = re.compile(r"VID=([0-9a-fA-F]+)(?:\s*\(([^)]*)\))?")
SA_RE = re.compile(r"SA=\(([^)]*)\)")
ID_RE = re.compile(r"\bID\(([^)]*)\)")
GUESS_RE = re.compile(r"Implementation guess:\s*(.+)")
NOTIFY_RE = re.compile(r"Notify message \d+ \(([A-Z0-9_-]+)\)")
PSKPARAM_RE = re.compile(r"^[0-9a-fA-F]+(:[0-9a-fA-F]*){7,}$")

WEAK = {"Enc=DES", "Hash=MD5", "Group=1:modp768", "Group=2:modp1024"}


def new_gw(ip):
    return {
        "ip": ip,
        "handshake": False,
        "modes": [],            # "main", "aggressive", "ikev2"
        "notify": [],
        "transforms": [],       # decoded SA=() strings
        "weak_transforms": [],
        "vendor_ids": [],       # {"vid":..., "decode":...}
        "identities": [],       # ID() payloads from aggressive replies
        "implementation_guess": None,
        "psk_hash_captured": False,
    }


def parse_streams(streams):
    gws = {}
    cur = None          # gateway record continuation lines attach to
    pending_psk = False  # saw "IKE PSK parameters" header

    def feed(gw, text):
        for sa in SA_RE.findall(text):
            if sa not in gw["transforms"]:
                gw["transforms"].append(sa)
            for w in WEAK:
                if w in sa and sa not in gw["weak_transforms"]:
                    gw["weak_transforms"].append(sa)
        for vid, decode in VID_RE.findall(text):
            rec = {"vid": vid.lower(), "decode": decode or None}
            if rec not in gw["vendor_ids"]:
                gw["vendor_ids"].append(rec)
        for ident in ID_RE.findall(text):
            if ident not in gw["identities"]:
                gw["identities"].append(ident)
        m = GUESS_RE.search(text)
        if m:
            gw["implementation_guess"] = m.group(1).strip()
        m = NOTIFY_RE.search(text)
        if m and m.group(1) not in gw["notify"]:
            gw["notify"].append(m.group(1))
        if "Handshake returned" in text:
            gw["handshake"] = True
            mode = ("aggressive" if "Aggressive Mode" in text
                    else "ikev2" if "IKEv2" in text or "SA_INIT" in text
                    else "main")
            if mode not in gw["modes"]:
                gw["modes"].append(mode)
        if "IKE PSK parameters" in text:
            gw["psk_hash_captured"] = True

    for fh in streams:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if line.lower().startswith(("starting ike-scan", "ending ike-scan",
                                        "ike backoff patterns", "ip address")):
                cur = None
                continue
            m = IP_RE.match(line)
            if m:
                ip, rest = m.group(1), m.group(2)
                # backoff timing rows: "<ip> <no> <recvtime> <delta>" - keep
                # cur pointed at the gw so the final guess line attaches.
                cur = gws.setdefault(ip, new_gw(ip))
                feed(cur, rest)
                pending_psk = "IKE PSK parameters" in rest
            elif line[0] in " \t" and cur:
                # -M continuation payload line
                feed(cur, line.strip())
                if pending_psk and PSKPARAM_RE.match(line.strip()):
                    cur["psk_hash_captured"] = True
                    pending_psk = False
            elif cur and PSKPARAM_RE.match(line.strip()):
                cur["psk_hash_captured"] = True
                pending_psk = False
    return gws


def build_units(gws):
    units = []

    def add(uid, title, ip, hints):
        units.append({"id": uid, "title": title, "targets": [ip],
                      "hints": hints})

    for ip in sorted(gws, key=lambda s: tuple(int(o) for o in s.split("."))):
        gw = gws[ip]
        dash = ip.replace(".", "-")
        vids = ", ".join(v["decode"] or v["vid"][:16] for v in gw["vendor_ids"])
        base = f"ike v1 modes={','.join(gw['modes']) or 'none'}"
        if vids:
            base += f"; vids: {vids}"
        if gw["implementation_guess"]:
            base += f"; guess: {gw['implementation_guess']}"

        if gw["psk_hash_captured"]:
            add(f"ike-psk-crack-{dash}", f"crack captured PSK for {ip}", ip,
                f"psk-crack -d <wordlist> psk-{ip}.txt then -b brute; "
                f"hash auto MD5/SHA1; hashcat 5300/5400 for GPU; "
                f"ids seen: {', '.join(gw['identities']) or 'none'}; {base}")
        elif "aggressive" in gw["modes"]:
            add(f"ike-psk-capture-{dash}",
                f"capture aggressive-mode PSK hash from {ip}", ip,
                f"ike-scan -A --id=<group> -P psk-{ip}.txt {ip}; "
                f"ids seen: {', '.join(gw['identities']) or 'try vpn/group names'}; {base}")
        elif gw["handshake"]:
            add(f"ike-aggressive-{dash}", f"test aggressive mode on {ip}", ip,
                f"handshake returned in {'/'.join(gw['modes'])} mode; try "
                f"ike-scan -A --id=<group> -P; group-ID candidates: vpn, "
                f"company name, AD groups; {base}")
        elif gw["notify"]:
            add(f"ike-transforms-{dash}", f"brute-force transforms on {ip}", ip,
                f"gateway answered {','.join(gw['notify'])}: iterate "
                f"--trans=enc,hash,auth,group over 1/5/7-128..256 x 1,2 x "
                f"1,3,64221,65001 x 1,2,5,14 in main AND aggressive mode; {base}")

        if gw["handshake"] and not gw["vendor_ids"] and not gw["implementation_guess"]:
            add(f"ike-fingerprint-{dash}", f"backoff-fingerprint {ip}", ip,
                f"no VIDs returned; run ike-scan -M --showbackoff {ip} "
                f"(serially) and record Implementation guess; {base}")
        if gw["weak_transforms"]:
            add(f"ike-weak-crypto-{dash}", f"report weak IKE transforms on {ip}",
                ip, "accepted weak transforms: "
                + " | ".join(gw["weak_transforms"])
                + "; file finding per finding-report skill")
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="ike-scan output files ('-' for stdin)")
    ap.add_argument("-o", "--output", help="write gateway records JSON here")
    ap.add_argument("--units", help="write JSON work-units array here")
    args = ap.parse_args()

    streams = []
    for p in args.files:
        streams.append(sys.stdin if p == "-" else open(p, errors="replace"))
    gws = parse_streams(streams)
    for s in streams:
        if s is not sys.stdin:
            s.close()

    records = [gws[ip] for ip in sorted(
        gws, key=lambda s: tuple(int(o) for o in s.split(".")))]
    if args.output:
        with open(args.output, "w") as f:
            json.dump(records, f, indent=2)
            f.write("\n")
        print(f"[+] {len(records)} gateway records -> {args.output}",
              file=sys.stderr)
    else:
        json.dump(records, sys.stdout, indent=2)
        print()

    if args.units:
        units = build_units(gws)
        with open(args.units, "w") as f:
            json.dump(units, f, indent=2)
            f.write("\n")
        print(f"[+] {len(units)} work units -> {args.units}", file=sys.stderr)


if __name__ == "__main__":
    main()
