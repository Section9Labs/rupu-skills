#!/usr/bin/env python3
"""firmware_triage.py — binwalk-driven firmware extraction + rootfs triage.

Usage:
  python3 scripts/firmware_triage.py ./firmware.bin [-o OUTDIR]
  python3 scripts/firmware_triage.py ./squashfs-root [-o OUTDIR]   # already extracted

Given an image: runs `binwalk` (signature scan, logged) and `binwalk -Me`
(extraction) into OUTDIR, locates the extracted root filesystem.
Given a directory: treats it as (or searches it for) an extracted rootfs.

Then inventories the rootfs: ELF binaries (magic + arch/endianness), setuid
files, credential/key candidates, component version strings
(busybox/dropbear/lighttpd/...), prints a triage report, writes
OUTDIR/triage-report.txt and OUTDIR/work-units.json — a JSON array of
{id, title, targets, hints} units (one per high-value binary) for a rupu
`for_each:` fan-out to the binary-triage / qiling-unicorn skills.

Standard library only. Degrades gracefully when binwalk/unsquashfs are absent.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys

ELF_MAGIC = b"\x7fELF"
MAX_SCAN_BYTES = 16 * 1024 * 1024  # cap per-file reads

E_MACHINE = {
    2: "sparc", 3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm",
    42: "superh", 50: "ia64", 62: "x86-64", 183: "aarch64", 243: "riscv",
}

DAEMON_NAMES = {
    "httpd", "mini_httpd", "lighttpd", "uhttpd", "boa", "goahead", "thttpd",
    "telnetd", "utelnetd", "dropbear", "dropbearmulti", "sshd", "dnsmasq",
    "udhcpd", "miniupnpd", "upnpd", "wscd", "snmpd", "smbd", "nmbd", "ftpd",
    "vsftpd", "bftpd", "tftpd", "mosquitto", "cwmpd", "tr069", "acsd",
    "netctrl", "cfm", "mdnsd", "avahi-daemon", "inetd", "xinetd", "rpcd",
}

SOCKET_STRINGS = [b"\x00bind\x00", b"\x00socket\x00", b"\x00recvfrom\x00",
                  b"\x00accept\x00", b"\x00listen\x00"]

VERSION_PATTERNS = [
    ("busybox", rb"BusyBox v(\d[\d.]*\d)"),
    ("dropbear", rb"[Dd]ropbear[_ ](?:SSH[_ a-z]*)?v?(20\d\d\.\d+)"),
    ("lighttpd", rb"lighttpd/(\d[\d.]*\d)"),
    ("mini_httpd", rb"mini_httpd/(\d[\d.]*\d)"),
    ("goahead", rb"GoAhead[ -][Ww]ebs?[a-z]*/?(\d[\d.]*\d)?"),
    ("boa", rb"[Bb]oa/(\d[\d.]*\d[a-z0-9.]*)"),
    ("dnsmasq", rb"dnsmasq-(\d[\d.]*\d)"),
    ("openssl", rb"OpenSSL (\d[\d.]*\d[a-z]?)"),
    ("miniupnpd", rb"miniupnpd/(\d[\d.]*\d)"),
    ("uclibc", rb"uClibc (\d[\d.]*\d)"),
]

CRED_NAME_PATTERNS = re.compile(
    r"(^|/)(passwd|shadow|passwd-|shadow-|authorized_keys|.*host.*key.*)$|"
    r"\.(pem|key|crt|p12|pfx)$", re.I)
CRED_CONTENT = re.compile(rb"PRIVATE KEY|(password|passwd|secret)\s*[=:]", re.I)
TEXT_CONF_EXT = (".conf", ".cfg", ".ini", ".xml", ".json", ".sh", ".lua",
                 ".txt", ".sample", ".pem", ".key", ".crt")
ROOTFS_MARKER_DIRS = ("squashfs-root", "cpio-root", "jffs2-root", "ubifs-root",
                      "cramfs-root", "romfs-root")


def log(msg):
    print(msg, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def slugify(relpath):
    s = re.sub(r"[^a-z0-9]+", "-", relpath.lower()).strip("-")
    return s or "rootfs-binary"


def run(cmd, cwd=None):
    """Run a command; return (rc, stdout+stderr) or (None, msg) if missing."""
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=1800)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return None, "tool not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return -1, "timed out: %s" % " ".join(cmd)


# ---------------------------------------------------------------- extraction

def run_binwalk(image, outdir):
    """Signature scan + recursive extraction. Returns extraction root or None."""
    if shutil.which("binwalk") is None:
        log("[!] binwalk not found. Install v3 (cargo install binwalk / github\n"
            "    releases) or v2 (pip install binwalk), or extract manually:\n"
            "      binwalk -Me firmware.bin   # then re-run this script on the\n"
            "      extracted directory (e.g. squashfs-root/).")
        return None

    img = os.path.abspath(image)
    rc, sig = run(["binwalk", img])
    sig_log = os.path.join(outdir, "binwalk.sig.txt")
    with open(sig_log, "w") as f:
        f.write(sig)
    log("[*] signature scan -> %s" % sig_log)
    for line in sig.splitlines():
        if re.match(r"^\d+\s", line):
            log("    " + line.rstrip())

    exdir = os.path.join(outdir, "extract")
    os.makedirs(exdir, exist_ok=True)
    rc, out = run(["binwalk", "-M", "-e", img], cwd=exdir)
    if rc not in (0, None) and "--run-as" in out:  # binwalk v2 as root
        rc, out = run(["binwalk", "-M", "-e", "--run-as=root", img], cwd=exdir)
    with open(os.path.join(outdir, "binwalk.extract.txt"), "w") as f:
        f.write(out)
    if rc is None:
        log("[!] %s" % out)
        return None
    log("[*] extraction log -> %s" % os.path.join(outdir, "binwalk.extract.txt"))
    return exdir


def try_unsquashfs(exdir):
    """Fallback: unpack raw squashfs carves binwalk left behind."""
    if shutil.which("unsquashfs") is None and shutil.which("sasquatch") is None:
        return None
    tool = shutil.which("sasquatch") or shutil.which("unsquashfs")
    for dirpath, _dirs, files in os.walk(exdir):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as f:
                    magic = f.read(4)
            except OSError:
                continue
            if magic in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
                dest = os.path.join(dirpath, "squashfs-root-manual")
                log("[*] raw squashfs carve %s -> %s via %s" % (p, dest, tool))
                rc, out = run([tool, "-d", dest, p])
                if rc == 0 and os.path.isdir(dest):
                    return dest
    return None


def score_rootfs(d):
    s = 0
    for marker, pts in (("etc", 2), ("bin", 2), ("sbin", 1), ("lib", 1),
                        ("usr", 1), ("www", 1)):
        if os.path.isdir(os.path.join(d, marker)):
            s += pts
    for marker, pts in (("bin/busybox", 4), ("sbin/init", 3),
                        ("etc/inittab", 2), ("etc/passwd", 2)):
        if os.path.exists(os.path.join(d, marker)):
            s += pts
    if os.path.basename(d).startswith(ROOTFS_MARKER_DIRS):
        s += 3
    return s


def find_rootfs(root):
    best, best_score = None, 2  # require minimal evidence
    for dirpath, dirs, _files in os.walk(root):
        sc = score_rootfs(dirpath)
        if sc > best_score:
            best, best_score = dirpath, sc
        dirs[:] = [d for d in dirs if not d.startswith(".")]
    return best


# ---------------------------------------------------------------- inventory

def parse_elf_header(data):
    if len(data) < 20 or not data.startswith(ELF_MAGIC):
        return None
    bits = {1: "32", 2: "64"}.get(data[4], "?")
    endian = {1: "LSB", 2: "MSB"}.get(data[5], "?")
    fmt = "<H" if data[5] == 1 else ">H"
    e_type = struct.unpack_from(fmt, data, 16)[0]
    e_machine = struct.unpack_from(fmt, data, 18)[0]
    return {
        "arch": E_MACHINE.get(e_machine, "em%d" % e_machine),
        "bits": bits, "endian": endian,
        "type": {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, "?"),
    }


def classify(rel, name, is_setuid, has_socket):
    low = rel.lower()
    if "cgi-bin" in low or (low.startswith(("www/", "web/", "usr/www")) and
                            not low.endswith((".html", ".js", ".css"))):
        return "cgi"
    base = name.lower()
    if base in DAEMON_NAMES or any(k in base for k in
                                   ("httpd", "telnetd", "upnp", "tr069", "cwmp")):
        return "network-daemon"
    if has_socket:
        return "network-daemon"
    if is_setuid:
        return "setuid"
    return "other"


def inventory_rootfs(rootfs):
    inv = {"rootfs": os.path.abspath(rootfs), "elves": [], "setuid": [],
           "creds": [], "versions": []}
    for dirpath, dirs, files in os.walk(rootfs):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
        for name in files:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, rootfs)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            is_setuid = bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))
            try:
                with open(path, "rb") as f:
                    data = f.read(MAX_SCAN_BYTES)
            except OSError:
                continue

            elf = parse_elf_header(data)
            if elf:
                has_socket = any(s in data for s in SOCKET_STRINGS)
                kind = classify(rel, name, is_setuid, has_socket)
                version = None
                for comp, pat in VERSION_PATTERNS:
                    m = re.search(pat, data)
                    if m:
                        ver = (m.group(1) or b"").decode("ascii", "replace")
                        version = ("%s %s" % (comp, ver)).strip()
                        inv["versions"].append({"component": comp, "version": ver,
                                                "path": rel})
                        break
                inv["elves"].append({"rel": rel, "path": os.path.abspath(path),
                                     "kind": kind, "setuid": is_setuid,
                                     "version": version, **elf})
                if is_setuid:
                    inv["setuid"].append(rel)
                continue

            if is_setuid:
                inv["setuid"].append(rel)
            # credential / key candidates
            if CRED_NAME_PATTERNS.search(rel.replace(os.sep, "/")):
                inv["creds"].append({"path": rel, "why": "filename"})
            elif (name.lower().endswith(TEXT_CONF_EXT) or "/etc/" in
                  ("/" + rel.replace(os.sep, "/"))) and st.st_size < (1 << 20):
                m = CRED_CONTENT.search(data)
                if m:
                    inv["creds"].append({
                        "path": rel,
                        "why": m.group(0).decode("latin-1")[:40]})
    return inv


# ---------------------------------------------------------------- outputs

def build_work_units(inv):
    units, seen = [], set()
    for e in sorted(inv["elves"], key=lambda x: x["rel"]):
        if e["kind"] == "other" and not e["setuid"]:
            continue
        uid = slugify(e["rel"])
        if uid in seen:
            uid = "%s-%s" % (uid, len(seen))
        seen.add(uid)
        kind = "setuid" if (e["setuid"] and e["kind"] == "other") else e["kind"]
        hints = ["binary-protections", "binary-triage"]
        if kind in ("network-daemon", "cgi"):
            hints.append("qiling-unicorn")
        units.append({
            "id": uid,
            "title": "Triage %s (%s, %s %s-bit %s) from %s" % (
                os.path.basename(e["rel"]), kind, e["arch"], e["bits"],
                e["endian"], e["rel"]),
            "targets": [{
                "file": e["path"],
                "rootfs_path": e["rel"].replace(os.sep, "/"),
                "kind": kind,
                "version": e["version"],
            }],
            "hints": sorted(hints),
        })
    return units


def write_report(inv, units, outdir, image, image_sha):
    lines = []
    a = lines.append
    a("=" * 72)
    a("FIRMWARE TRIAGE REPORT")
    if image:
        a("image      : %s" % image)
        a("sha256     : %s" % image_sha)
    a("rootfs     : %s" % inv["rootfs"])
    a("ELF count  : %d   setuid: %d   cred candidates: %d" %
      (len(inv["elves"]), len(inv["setuid"]), len(inv["creds"])))
    a("=" * 72)

    daemons = [e for e in inv["elves"] if e["kind"] == "network-daemon"]
    cgis = [e for e in inv["elves"] if e["kind"] == "cgi"]
    a("\n-- network daemons (%d) --" % len(daemons))
    for e in daemons:
        a("  %-40s %s/%s-bit/%s %s" % (e["rel"], e["arch"], e["bits"],
                                       e["endian"], e["version"] or ""))
    a("\n-- CGI binaries (%d) --" % len(cgis))
    for e in cgis:
        a("  %s" % e["rel"])
    a("\n-- setuid files (%d) --" % len(inv["setuid"]))
    for p in sorted(set(inv["setuid"])):
        a("  %s" % p)
    a("\n-- credential/key candidates (%d) --" % len(inv["creds"]))
    for c in inv["creds"][:200]:
        a("  %-50s (%s)" % (c["path"], c["why"]))
    a("\n-- component versions (CVE check these) --")
    for v in sorted({(x["component"], x["version"], x["path"])
                     for x in inv["versions"]}):
        a("  %-12s %-12s %s" % v)
    a("\n-- rupu handoff --")
    a("  work units : %s (feed a rupu for_each: fan-out, see work-units skill)"
      % os.path.join(outdir, "work-units.json"))
    a("  assets.mark: each ELF above as binary:file (t=file, v=sha256) at")
    a("               depth 'discovered'; carved rootfs + binwalk logs stay")
    a("               in %s as evidence." % outdir)
    a("  findings   : report credentials/keys and CVE-bearing versions via")
    a("               findings.report (finding-report skill contract).")
    report = "\n".join(lines)
    print(report)
    with open(os.path.join(outdir, "triage-report.txt"), "w") as f:
        f.write(report + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="firmware image file OR extracted rootfs dir")
    ap.add_argument("-o", "--outdir", default="triage-out",
                    help="output directory (default: triage-out)")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    image = image_sha = None
    if os.path.isdir(args.target):
        search_root = args.target
    elif os.path.isfile(args.target):
        image = os.path.abspath(args.target)
        image_sha = sha256_file(image)
        log("[*] image sha256: %s" % image_sha)
        search_root = run_binwalk(image, args.outdir)
        if search_root is None:
            log("[!] no extraction performed; re-run on an extracted rootfs dir.")
            sys.exit(1)
    else:
        log("[!] no such file or directory: %s" % args.target)
        sys.exit(2)

    rootfs = find_rootfs(search_root)
    if rootfs is None and image:
        rootfs = try_unsquashfs(search_root)
    if rootfs is None:
        log("[!] no root filesystem located under %s" % search_root)
        log("    Likely encrypted/exotic image. Check entropy (binwalk -E),")
        log("    carve raw (binwalk --dd='.*' / --carve), unpack manually")
        log("    (unsquashfs/sasquatch/jefferson/ubireader, see")
        log("    references/filesystems.md), then re-run on the extracted dir.")
        sys.exit(1)
    log("[*] rootfs: %s" % rootfs)

    inv = inventory_rootfs(rootfs)
    units = build_work_units(inv)
    units_path = os.path.join(args.outdir, "work-units.json")
    with open(units_path, "w") as f:
        json.dump(units, f, indent=2)
    write_report(inv, units, args.outdir, image, image_sha)
    log("\n[*] %d work units -> %s" % (len(units), units_path))


if __name__ == "__main__":
    main()
