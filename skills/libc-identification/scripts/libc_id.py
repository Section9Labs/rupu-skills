#!/usr/bin/env python3
"""libc_id.py - identify a remote libc build from leaked addresses.

Usage:
  python3 scripts/libc_id.py SYMBOL=LEAK [SYMBOL=LEAK ...]

  LEAK may be a full runtime address (0x7f3c6a4b85a0) or just the last
  3 hex digits (5a0). Full addresses additionally let the script compute
  libc_base once a unique build is matched.

Behavior:
  * Looks for a libc-database clone at $LIBC_DATABASE, ./libc-database,
    or ~/libc-database and runs its ./find.
  * If no clone exists, prints the exact libc.rip web query and exits 0.
  * On a unique match, runs ./dump and prints system/str_bin_sh/puts (plus
    your queried symbols) and, when full addresses were given, the computed
    base and absolute addresses.
  * Always writes rupu work units to libc-id-work-units.json (JSON array of
    {id,title,targets,hints}) when at least one candidate was found.

Standard library only. Degrades gracefully when libc-database is absent.
"""
import json
import os
import re
import subprocess
import sys

WORKUNITS_FILE = "libc-id-work-units.json"
DUMP_DEFAULT_SYMBOLS = ["system", "str_bin_sh", "puts"]
ID_RE = re.compile(r"\(id ([^)]+)\)")
OFFSET_RE = re.compile(r"^offset_(\S+)\s*=\s*(0x[0-9a-fA-F]+)")


def die(msg, code=1):
    print("[!] " + msg, file=sys.stderr)
    sys.exit(code)


def find_database():
    candidates = [
        os.environ.get("LIBC_DATABASE"),
        "./libc-database",
        os.path.expanduser("~/libc-database"),
    ]
    for cand in candidates:
        if cand and os.path.isfile(os.path.join(cand, "find")) \
                and os.access(os.path.join(cand, "find"), os.X_OK):
            return cand
    return None


def parse_pairs(argv):
    pairs = []
    for arg in argv:
        if "=" not in arg:
            die("bad argument %r (expected SYMBOL=LEAKHEX)" % arg)
        sym, _, val = arg.partition("=")
        val = val.strip().lower()
        if val.startswith("0x"):
            val = val[2:]
        try:
            leak = int(val, 16)
        except ValueError:
            die("bad hex value %r for symbol %s" % (val, sym))
        full = leak > 0xFFF  # full address vs last-3-digits form
        pairs.append((sym.strip(), leak, full))
    if not pairs:
        die("no SYMBOL=LEAK pairs given\n\n" + __doc__)
    return pairs


def web_fallback(pairs):
    symdict = {s: format(l & 0xFFF, "03x") for s, l, _ in pairs}
    body = json.dumps({"symbols": symdict})
    print("[!] No local libc-database clone found "
          "($LIBC_DATABASE / ./libc-database / ~/libc-database).")
    print("[*] Either clone it:")
    print("      git clone https://github.com/niklasb/libc-database && "
          "cd libc-database && ./get ubuntu debian")
    print("[*] Or query the web service directly:")
    print("      curl -s https://libc.rip/api/find "
          "-H 'Content-Type: application/json' \\")
    print("        -d '%s' | python3 -m json.tool" % body)
    print("[*] Then: ./dump <id>  (or read \"symbols\" in the API response) "
          "and compute libc_base = leak - offset_symbol.")


def run(cmd, cwd):
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        die("failed to run %s: %s" % (" ".join(cmd), exc))
    return proc.stdout + proc.stderr


def write_workunits(units):
    with open(WORKUNITS_FILE, "w") as fh:
        json.dump(units, fh, indent=2)
    print("[*] rupu work units -> %s" % WORKUNITS_FILE)


def slugify(text):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


def main():
    pairs = parse_pairs(sys.argv[1:])
    db = find_database()
    if db is None:
        web_fallback(pairs)
        return 0

    find_args = []
    for sym, leak, _ in pairs:
        find_args += [sym, format(leak & 0xFFF, "03x")]
    print("[*] libc-database at %s" % db)
    print("[*] running: ./find %s" % " ".join(find_args))
    out = run([os.path.join(db, "find")] + find_args, cwd=db)
    sys.stdout.write(out)

    ids = []
    for line in out.splitlines():
        m = ID_RE.search(line)
        if m and m.group(1) not in ids:
            ids.append(m.group(1))

    if not ids:
        print("[!] No candidates. Options:")
        print("    - populate more distros: (cd %s && ./get all)" % db)
        print("    - query the larger web corpus:")
        web_fallback(pairs)
        return 0

    if len(ids) > 1:
        print("[!] %d candidates - narrow with a second symbol, e.g.:" % len(ids))
        print("    ./find %s printf <last3hex>" % " ".join(find_args))
        units = []
        for i, build in enumerate(ids):
            units.append({
                "id": "libc-candidate-%d-%s" % (i, slugify(build)),
                "title": "Candidate libc build %s (ambiguous match)" % build,
                "targets": [{"t": "libc-id", "v": build}],
                "hints": sorted(["libc-identification", "one_gadget"]),
            })
        write_workunits(units)
        return 0

    build = ids[0]
    print("[+] unique match: %s" % build)
    want = list(DUMP_DEFAULT_SYMBOLS)
    for sym, _, _ in pairs:
        if sym not in want:
            want.append(sym)
    out = run([os.path.join(db, "dump"), build] + want, cwd=db)
    sys.stdout.write(out)

    offsets = {}
    for line in out.splitlines():
        m = OFFSET_RE.match(line.strip())
        if m:
            offsets[m.group(1)] = int(m.group(2), 16)

    base = None
    for sym, leak, full in pairs:
        if full and sym in offsets:
            base = leak - offsets[sym]
            print("[+] libc_base = %#x - %#x = %#x  (%s)" %
                  (leak, offsets[sym], base, sym))
            if base & 0xFFF:
                print("[!] base is NOT page aligned - wrong build or bad leak")
            break
    if base is not None:
        for sym in want:
            if sym in offsets:
                print("    %-16s = %#x" % (sym, base + offsets[sym]))

    targets = [{"t": "libc-id", "v": build}]
    if base is not None:
        targets.append({"t": "libc-base", "v": hex(base)})
    for sym in ("system", "str_bin_sh"):
        if sym in offsets:
            targets.append({"t": "symbol-offset",
                            "v": "%s=%#x" % (sym, offsets[sym])})
    write_workunits([{
        "id": "libc-match-" + slugify(build),
        "title": "Matched libc %s%s" % (
            build, " (base %s)" % hex(base) if base is not None else ""),
        "targets": targets,
        "hints": sorted(["heap-exploitation", "one_gadget", "rop-chains"]),
    }])
    return 0


if __name__ == "__main__":
    sys.exit(main())
