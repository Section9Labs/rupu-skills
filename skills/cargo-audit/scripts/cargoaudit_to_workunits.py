#!/usr/bin/env python3
"""Convert `cargo audit --json` output into a clean JSON array of rupu work units.

Usage:
    python3 scripts/cargoaudit_to_workunits.py audit.json -o workunits.json
    cargo audit --json | python3 scripts/cargoaudit_to_workunits.py - -o workunits.json

Output file is a top-level JSON array:
    [{"id": "...", "title": "...", "targets": ["crate@version"],
      "hints": {"rustsec": "...", "cve": "...", "severity": "...",
                "patched": [...], "kind": "..."}}, ...]
"""
import argparse
import hashlib
import json
import math
import sys

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1,
            "unknown": 0}

# ---------------------------------------------------------------- CVSS v3.x
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vector):
    """Compute the CVSS v3.0/v3.1 base score from a vector string.

    Returns a float score or None if the vector is missing/unparseable.
    """
    if not vector or not isinstance(vector, str):
        return None
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
        scope_changed = parts["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        pr = pr_table[parts["PR"]]
        ui = _UI[parts["UI"]]
        c = _CIA[parts["C"]]
        i = _CIA[parts["I"]]
        a = _CIA[parts["A"]]
    except (KeyError, ValueError):
        return None
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    raw = min(raw, 10.0)
    return math.ceil(raw * 10.0) / 10.0  # CVSS "roundup" to 1 decimal


def score_to_severity(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


# -------------------------------------------------------------- extraction
def primary_cve(aliases):
    aliases = aliases or []
    for a in aliases:
        if isinstance(a, str) and a.startswith("CVE-"):
            return a
    return aliases[0] if aliases else None


def _unit(kind, package, advisory, versions, affected, severity_default):
    name = (package or {}).get("name") or "unknown"
    version = (package or {}).get("version") or "unknown"
    target = "%s@%s" % (name, version)

    advisory = advisory or {}
    rustsec = advisory.get("id")
    aliases = advisory.get("aliases") or []
    cvss = advisory.get("cvss")
    score = cvss3_base_score(cvss)
    severity = score_to_severity(score) if score is not None else severity_default
    cve = primary_cve(aliases)
    patched = (versions or {}).get("patched") or []
    label = rustsec or advisory.get("title") or kind
    title = "%s \u2014 %s" % (target, label)

    key = "|".join([kind, target, str(rustsec), str(advisory.get("title"))])
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]

    hints = {
        "kind": kind,
        "crate": name,
        "version": version,
        "rustsec": rustsec,
        "cve": cve,
        "aliases": aliases,
        "severity": severity,
        "cvss": cvss,
        "cvss_score": score,
        "patched": patched,
        "unaffected": (versions or {}).get("unaffected") or [],
        "advisory_title": advisory.get("title"),
        "advisory_url": advisory.get("url"),
        "affected_functions": sorted(((affected or {}).get("functions") or {}).keys()),
        "source": (package or {}).get("source"),
        "rule": "cargo-audit",
    }
    return {
        "id": "cargoaudit-%s" % digest,
        "title": title,
        "targets": [target],
        "hints": hints,
    }


def to_workunits(doc, include_warnings=True):
    units = []
    seen = set()

    vulns = ((doc.get("vulnerabilities") or {}).get("list")) or []
    for v in vulns:
        unit = _unit("vulnerability", v.get("package"), v.get("advisory"),
                     v.get("versions"), v.get("affected"),
                     severity_default="unknown")
        if unit["id"] not in seen:
            seen.add(unit["id"])
            units.append(unit)

    if include_warnings:
        warnings = doc.get("warnings") or {}
        if isinstance(warnings, dict):
            groups = warnings.items()
        elif isinstance(warnings, list):  # very old cargo-audit: flat list
            groups = [("warning", warnings)]
        else:
            groups = []
        for kind, entries in groups:
            for w in entries or []:
                wkind = w.get("kind") or kind
                unit = _unit(wkind, w.get("package"), w.get("advisory"),
                             w.get("versions"), w.get("affected"),
                             severity_default="low")
                if unit["id"] not in seen:
                    seen.add(unit["id"])
                    units.append(unit)

    units.sort(key=lambda u: (-SEV_RANK.get(u["hints"]["severity"], 0),
                              u["targets"][0], u["id"]))
    return units


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Normalize `cargo audit --json` output into rupu work units.")
    ap.add_argument("report", help="audit.json from `cargo audit --json` "
                                   "(use '-' for stdin)")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output file (clean JSON array), default workunits.json")
    ap.add_argument("--no-warnings", action="store_true",
                    help="exclude unmaintained/unsound/yanked warning units")
    args = ap.parse_args(argv)

    try:
        if args.report == "-":
            doc = json.load(sys.stdin)
        else:
            with open(args.report, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print("error: cannot read %s: %s" % (args.report, exc), file=sys.stderr)
        return 2

    if not isinstance(doc, dict):
        print("error: unexpected JSON shape (expected cargo audit object)",
              file=sys.stderr)
        return 2

    units = to_workunits(doc, include_warnings=not args.no_warnings)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")

    dep_count = (doc.get("lockfile") or {}).get("dependency-count")
    print("wrote %d work unit(s) to %s (lockfile deps audited: %s)"
          % (len(units), args.output,
             dep_count if dep_count is not None else "?"))
    by_kind = {}
    for u in units:
        k = u["hints"]["kind"]
        by_kind[k] = by_kind.get(k, 0) + 1
    for k in sorted(by_kind):
        print("  %-14s %d" % (k, by_kind[k]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
