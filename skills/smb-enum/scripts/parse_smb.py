#!/usr/bin/env python3
"""parse_smb.py - normalize SMB enumeration output into inventory + work units.

Consumes:
  * enum4linux-ng output  (-oY YAML or -oJ JSON file)
  * smbmap stdout         (text capture)
  * rpcclient stdout      (text capture: enumdomusers/enumdomgroups/srvinfo/
                           getdompwinfo/netshareenumall ...)

Emits into the output directory:
  inventory.json      {host, domain, signing, smbv1, os, shares, users, groups, pass_pol}
  users.txt           one username per line (spray input)
  relay-targets.txt   hosts with SMB signing not required
  work_units.json     clean JSON ARRAY [{id,title,targets,hints}]

Standalone, stdlib only. The YAML reader is a minimal subset parser sufficient
for enum4linux-ng output (block mappings/sequences, plain scalars); JSON files
are detected automatically.

Usage:
  python3 scripts/parse_smb.py --host 192.0.2.10 \
      --e4l e4l_192.0.2.10.yaml --smbmap smbmap.txt --rpc rpcclient.txt \
      -o smb_192.0.2.10

-- vulture (silver-pinnacle)
"""

import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------- YAML subset


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _scalar(s):
    s = s.strip()
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return _unquote(s)


def load_yaml_subset(text):
    """Parse the block-style YAML emitted by enum4linux-ng (subset)."""
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw.strip() == "---":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    def parse(idx, indent):
        container = None
        while idx < len(lines):
            ind, line = lines[idx]
            if ind < indent:
                break
            if ind > indent:  # should have been consumed by a child
                idx += 1
                continue
            if line.startswith("- "):
                if container is None:
                    container = []
                if not isinstance(container, list):
                    break
                container.append(_scalar(line[2:]))
                idx += 1
                continue
            m = re.match(r"^(.+?):(?:\s+(.*))?$", line)
            if not m:
                idx += 1
                continue
            if container is None:
                container = {}
            if not isinstance(container, dict):
                break
            key = _unquote(m.group(1))
            val = m.group(2)
            if val is None or val == "":
                child, idx2 = parse(idx + 1, _next_indent(lines, idx, ind))
                container[key] = child
                idx = idx2
            else:
                container[key] = _scalar(val)
                idx += 1
        return container, idx

    def _next_indent(lines, idx, cur):
        if idx + 1 < len(lines) and lines[idx + 1][0] > cur:
            return lines[idx + 1][0]
        return cur + 1  # empty value

    result, _ = parse(0, lines[0][0] if lines else 0)
    return result if result is not None else {}


def load_structured(path):
    text = open(path, "r", errors="replace").read()
    try:
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return load_yaml_subset(text)


# -------------------------------------------------------- enum4linux-ng data


def find_key(obj, *names):
    """Depth-first case-insensitive search for the first matching key."""
    wanted = {n.lower() for n in names}
    stack = [obj]
    while stack:
        cur = stack.pop(0)
        if isinstance(cur, dict):
            for k, v in cur.items():
                if str(k).lower() in wanted:
                    return v
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def parse_e4l(path, inv):
    data = load_structured(path)
    if not isinstance(data, dict):
        return

    sig = find_key(data, "SMB signing required", "smb_signing_required", "signing")
    if sig is not None:
        inv["signing"] = bool(sig) if isinstance(sig, bool) else str(sig).lower() in ("true", "yes", "required")

    smb1 = find_key(data, "SMB1 only", "smb1_only")
    dialects = find_key(data, "Supported dialects", "supported_dialects")
    if isinstance(dialects, dict):
        for name, supported in dialects.items():
            if "1.0" in str(name) or "NT LM" in str(name):
                inv["smbv1"] = bool(supported) if isinstance(supported, bool) else str(supported).lower() in ("true", "yes")
    if smb1 is True:
        inv["smbv1"] = True

    for key, names in (("os", ("OS", "os")), ("os_version", ("OS version", "os_version")),
                       ("os_build", ("OS build", "os_build"))):
        v = find_key(data, *names)
        if v is not None and not isinstance(v, (dict, list)):
            inv[key] = str(v)

    dom = find_key(data, "NetBIOS domain name", "domain", "workgroup", "DNS domain")
    if dom and not isinstance(dom, (dict, list)):
        inv["domain"] = str(dom)
    sid = find_key(data, "domain_sid", "Domain SID")
    if sid and not isinstance(sid, (dict, list)):
        inv["domain_sid"] = str(sid)

    users = find_key(data, "users")
    if isinstance(users, dict):
        for _rid, u in users.items():
            if isinstance(u, dict):
                name = u.get("username") or u.get("user") or u.get("name")
                if name:
                    inv["users"].add(str(name))
            elif u:
                inv["users"].add(str(u))
    elif isinstance(users, list):
        inv["users"].update(str(u) for u in users if u)

    groups = find_key(data, "groups")
    if isinstance(groups, dict):
        for _rid, g in groups.items():
            if isinstance(g, dict):
                name = g.get("groupname") or g.get("group") or g.get("name")
                if name:
                    inv["groups"].add(str(name))
            elif g:
                inv["groups"].add(str(g))

    shares = find_key(data, "shares")
    if isinstance(shares, dict):
        for name, meta in shares.items():
            access = "unknown"
            if isinstance(meta, dict):
                acc = meta.get("access") or {}
                if isinstance(acc, dict):
                    r = str(acc.get("read", "")).lower() in ("yes", "true")
                    w = str(acc.get("write", "")).lower() in ("yes", "true")
                    access = "read,write" if (r and w) else "read" if r else "write" if w else "none"
            _add_share(inv, str(name), access)

    pol = find_key(data, "policy")
    if isinstance(pol, dict):
        flat = {}

        def walk(d, prefix=""):
            for k, v in d.items():
                if isinstance(v, dict):
                    walk(v, prefix + str(k) + " / ")
                else:
                    flat[(prefix + str(k)).strip()] = v

        walk(pol)
        for k, v in flat.items():
            lk = k.lower()
            if "lockout threshold" in lk:
                inv["pass_pol"]["lockout_threshold"] = v
            elif "lockout duration" in lk:
                inv["pass_pol"]["lockout_duration"] = v
            elif "observation" in lk:
                inv["pass_pol"]["lockout_window"] = v
            elif "minimum password length" in lk or "min_password_length" in lk:
                inv["pass_pol"]["min_length"] = v
            elif "history" in lk:
                inv["pass_pol"]["history_length"] = v
            elif "complexity" in lk or "pw_properties" in lk or "password properties" in lk:
                inv["pass_pol"]["complexity"] = v
            elif "maximum password age" in lk:
                inv["pass_pol"]["max_age"] = v


# ----------------------------------------------------------------- smbmap txt

SMBMAP_RE = re.compile(
    r"^\s*(\S[^\t]*?)\s{2,}(NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY)\b", re.M)
ACCESS_MAP = {"NO ACCESS": "none", "READ ONLY": "read",
              "READ, WRITE": "read,write", "WRITE ONLY": "write"}


def parse_smbmap(path, inv):
    text = open(path, "r", errors="replace").read()
    for m in SMBMAP_RE.finditer(text):
        name = m.group(1).strip()
        if name.lower() in ("disk", "----"):
            continue
        _add_share(inv, name, ACCESS_MAP[m.group(2)])


# --------------------------------------------------------------- rpcclient txt

RPC_USER_RE = re.compile(r"user:\[([^\]]+)\]\s+rid:\[0x[0-9a-fA-F]+\]")
RPC_GROUP_RE = re.compile(r"group:\[([^\]]+)\]\s+rid:\[0x[0-9a-fA-F]+\]")
RPC_OS_RE = re.compile(r"platform_id\s*:\s*\d+|os version\s*:\s*([\d.]+)", re.I)
RPC_MINLEN_RE = re.compile(r"min_password_length:\s*(\d+)")
RPC_SHARE_RE = re.compile(r"netname:\s*(\S+)")
RPC_DOMAIN_RE = re.compile(r"Domain:\s*\[?([^\]\s]+)\]?")
RPC_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+")


def parse_rpc(path, inv):
    text = open(path, "r", errors="replace").read()
    inv["users"].update(RPC_USER_RE.findall(text))
    inv["groups"].update(RPC_GROUP_RE.findall(text))
    for m in RPC_SHARE_RE.finditer(text):
        _add_share(inv, m.group(1), "unknown")
    m = RPC_MINLEN_RE.search(text)
    if m and "min_length" not in inv["pass_pol"]:
        inv["pass_pol"]["min_length"] = int(m.group(1))
    m = RPC_DOMAIN_RE.search(text)
    if m and not inv.get("domain"):
        inv["domain"] = m.group(1)
    m = RPC_SID_RE.search(text)
    if m and not inv.get("domain_sid"):
        inv["domain_sid"] = m.group(0)
    m = re.search(r"os version\s*:\s*([\d.]+)", text, re.I)
    if m and not inv.get("os_version"):
        inv["os_version"] = m.group(1)


# -------------------------------------------------------------------- helpers


def _add_share(inv, name, access):
    for s in inv["shares"]:
        if s["name"].lower() == name.lower():
            if s["access"] in ("unknown", "none") and access not in ("unknown",):
                s["access"] = access
            return
    inv["shares"].append({"name": name, "access": access})


def build_work_units(inv):
    host = inv["host"]
    wu = []

    for s in inv["shares"]:
        if s["access"] in ("read", "read,write", "write"):
            wu.append({
                "id": "share-walk-%s-%s" % (host, s["name"].strip("$").lower() or "root"),
                "title": "Walk SMB share //%s/%s (%s)" % (host, s["name"], s["access"]),
                "targets": [host],
                "hints": {"skill": "smb-enum", "share": s["name"], "access": s["access"],
                          "cmd": "smbclient //%s/%s -N -c 'recurse ON; prompt OFF; ls'" % (host, s["name"])},
            })
            if "write" in s["access"] and s["name"].upper() in ("SYSVOL", "NETLOGON", "C$", "ADMIN$"):
                wu.append({
                    "id": "writable-critical-%s-%s" % (host, s["name"].strip("$").lower()),
                    "title": "Writable sensitive share //%s/%s - verify and report" % (host, s["name"]),
                    "targets": [host],
                    "hints": {"skill": "finding-report", "share": s["name"]},
                })

    if inv["users"]:
        wu.append({
            "id": "spray-%s" % (inv.get("domain") or host),
            "title": "Password spray %d harvested users" % len(inv["users"]),
            "targets": [host],
            "hints": {"skill": "netexec", "userfile": "users.txt",
                      "lockout_threshold": inv["pass_pol"].get("lockout_threshold"),
                      "lockout_window": inv["pass_pol"].get("lockout_window")},
        })

    if inv["signing"] is False:
        wu.append({
            "id": "relay-%s" % host,
            "title": "NTLM relay candidate: %s (signing not required)" % host,
            "targets": [host],
            "hints": {"targets_file": "relay-targets.txt",
                      "cmd": "ntlmrelayx.py -tf relay-targets.txt -smb2support"},
        })

    if inv["smbv1"]:
        wu.append({
            "id": "ms17-010-%s" % host,
            "title": "SMBv1 enabled on %s - verify MS17-010" % host,
            "targets": [host],
            "hints": {"skill": "nmap",
                      "cmd": "nmap -p445 --script smb-vuln-ms17-010 %s" % host},
        })

    if inv.get("domain") and inv["domain"].upper() not in ("WORKGROUP",):
        wu.append({
            "id": "ldap-pivot-%s" % inv["domain"].lower(),
            "title": "Domain %s discovered - enumerate the DC over LDAP" % inv["domain"],
            "targets": [host],
            "hints": {"skill": "ldap-ad-enum", "domain": inv["domain"]},
        })
    return wu


def main():
    ap = argparse.ArgumentParser(description="Normalize SMB enumeration output")
    ap.add_argument("--host", required=True, help="target host/IP, e.g. 192.0.2.10")
    ap.add_argument("--e4l", help="enum4linux-ng -oY/-oJ output file")
    ap.add_argument("--smbmap", help="smbmap stdout capture")
    ap.add_argument("--rpc", help="rpcclient stdout capture")
    ap.add_argument("-o", "--outdir", default="smb_out", help="output directory")
    args = ap.parse_args()

    inv = {"host": args.host, "domain": None, "domain_sid": None,
           "signing": None, "smbv1": None, "os": None,
           "shares": [], "users": set(), "groups": set(), "pass_pol": {}}

    if args.e4l and os.path.exists(args.e4l):
        parse_e4l(args.e4l, inv)
    if args.smbmap and os.path.exists(args.smbmap):
        parse_smbmap(args.smbmap, inv)
    if args.rpc and os.path.exists(args.rpc):
        parse_rpc(args.rpc, inv)
    if not any((args.e4l, args.smbmap, args.rpc)):
        ap.error("provide at least one of --e4l / --smbmap / --rpc")

    inv["users"] = sorted(inv["users"], key=str.lower)
    inv["groups"] = sorted(inv["groups"], key=str.lower)

    os.makedirs(args.outdir, exist_ok=True)

    with open(os.path.join(args.outdir, "inventory.json"), "w") as f:
        json.dump(inv, f, indent=2)

    with open(os.path.join(args.outdir, "users.txt"), "w") as f:
        f.write("\n".join(inv["users"]) + ("\n" if inv["users"] else ""))

    relay = [args.host] if inv["signing"] is False else []
    with open(os.path.join(args.outdir, "relay-targets.txt"), "w") as f:
        f.write("\n".join(relay) + ("\n" if relay else ""))

    wu = build_work_units(inv)
    with open(os.path.join(args.outdir, "work_units.json"), "w") as f:
        json.dump(wu, f, indent=2)

    print("[*] host=%s domain=%s signing=%s smbv1=%s" %
          (inv["host"], inv["domain"], inv["signing"], inv["smbv1"]))
    print("[*] users=%d groups=%d shares=%d relay-targets=%d work-units=%d" %
          (len(inv["users"]), len(inv["groups"]), len(inv["shares"]), len(relay), len(wu)))
    print("[*] wrote %s/{inventory.json,users.txt,relay-targets.txt,work_units.json}" % args.outdir)


if __name__ == "__main__":
    sys.exit(main())
