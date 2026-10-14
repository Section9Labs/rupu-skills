#!/usr/bin/env python3
"""route.py — tell the agent which Phase 1 sub-skill handles each given file.

Usage: python3 scripts/route.py <file> [<file> ...]

Reads magic bytes only (no external tools needed) and prints, per file:
  <path>  <detected type>  -> load `<sub-skill>`

Degrades gracefully: unreadable/missing files are reported, never crash.
"""
import sys
import os

MAGICS = [
    (b"\x7fELF", "ELF executable/library", "binary-triage"),
    (b"MZ", "PE/DOS executable", "binary-triage"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit BE", "binary-triage"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE", "binary-triage"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit BE", "binary-triage"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE", "binary-triage"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal (fat)", "binary-triage"),
    (b"!<arch>\n", "ar archive (static lib)", "binary-triage"),
    (b"hsqs", "SquashFS image", "binwalk-firmware"),
    (b"sqsh", "SquashFS image (BE)", "binwalk-firmware"),
    (b"\x27\x05\x19\x56", "uImage (U-Boot)", "binwalk-firmware"),
    (b"UBI#", "UBI image", "binwalk-firmware"),
    (b"\x85\x19", "JFFS2 filesystem", "binwalk-firmware"),
    (b"\x1f\x8b", "gzip data", "binwalk-firmware"),
    (b"\xfd7zXZ\x00", "xz data", "binwalk-firmware"),
    (b"BZh", "bzip2 data", "binwalk-firmware"),
    (b"\x89LZO", "LZO data", "binwalk-firmware"),
    (b"PK\x03\x04", "zip archive", "binwalk-firmware"),
    (b"070701", "cpio (newc) archive", "binwalk-firmware"),
]


def shannon_entropy(data):
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def classify(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as e:
        return ("unreadable: %s" % e.strerror, None)
    if not head:
        return ("empty file", None)
    for magic, desc, skill in MAGICS:
        if head.startswith(magic):
            return (desc, skill)
    ent = shannon_entropy(head)
    if ent > 7.2:
        return ("unknown high-entropy blob (entropy %.2f: packed/encrypted/"
                "compressed firmware?)" % ent, "binwalk-firmware")
    if all(32 <= b < 127 or b in (9, 10, 13) for b in head[:512]):
        return ("looks like text (entropy %.2f)" % ent, None)
    return ("unknown binary data (entropy %.2f)" % ent, "binwalk-firmware")


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 1
    for path in argv[1:]:
        if not os.path.exists(path):
            print("%s\tmissing file" % path)
            continue
        desc, skill = classify(path)
        if skill:
            print("%s\t%s\t-> load `%s` (then `binary-protections` for "
                  "executables)" % (path, desc, skill))
        else:
            print("%s\t%s\t-> no binary-pack route; inspect manually"
                  % (path, desc))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
