#!/usr/bin/env python3
"""Convert Retire.js JSON output into a clean JSON array of rupu work units.

Usage:
    python3 scripts/retirejs_to_workunits.py retire.json -o workunits.json
    python3 scripts/retirejs_to_workunits.py retire.json --min-severity medium

Output file is a top-level JSON array:
    [{"id": "...", "title": "...", "targets": ["component@version"],
      "hints": {"file": "...", "severity": "...", "cve": "...",
                "identifiers": {...}, ...}}, ...]
"""
import argparse
import hashlib
import json
import sys

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def iter_data(doc):
    """Yield file-entries from either v3+ ({"data": [...]}) or legacy ([...])."""
    if isinstance(doc, dict):
        return doc.get("data") or []
    if isinstance(doc, list):
        return doc
    return []


def primary_id(identifiers):
    """Pick the headline advisory identifier for the title/hints."""
    if not isinstance(identifiers, dict):
        return None
    cves = identifiers.get("CVE") or []
    if isinstance(cves, str):
        cves = [cves]
    if cves:
        return cves[0]
    for key in ("githubID", "osvdb", "issue", "bug"):
        val = identifiers.get(key)
        if val:
            return val if isinstance(val, str) else str(val)
    return None


def make_unit(file_path, component, version, vuln):
    identifiers = vuln.get("identifiers") or {}
    severity = (vuln.get("severity") or "unknown").lower()
    cve = primary_id(identifiers)
    summary = identifiers.get("summary") if isinstance(identifiers, dict) else None
    target = "%s@%s" % (component, version)

    label = cve or summary or "known vulnerability"
    title = "%s \u2014 %s" % (target, label)

    key = "|".join([target, str(cve), str(summary), str(file_path)])
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]

    hints = {
        "file": file_path,
        "component": component,
        "version": version,
        "severity": severity,
        "cve": cve,
        "identifiers": identifiers,
        "summary": summary,
        "info": vuln.get("info") or [],
        "below": vuln.get("below"),
        "atOrAbove": vuln.get("atOrAbove"),
        "rule": "retire-js",
    }
    return {
        "id": "retirejs-%s" % digest,
        "title": title,
        "targets": [target],
        "hints": hints,
    }


def to_workunits(doc, min_severity="low"):
    threshold = SEV_RANK.get(min_severity.lower(), 1)
    units = []
    seen = set()
    for entry in iter_data(doc):
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file") or ""
        for result in entry.get("results") or []:
            component = result.get("component") or "unknown"
            version = result.get("version") or "unknown"
            for vuln in result.get("vulnerabilities") or []:
                unit = make_unit(file_path, component, version, vuln)
                sev = SEV_RANK.get(unit["hints"]["severity"], 0)
                if sev < threshold and unit["hints"]["severity"] != "unknown":
                    continue
                if unit["id"] in seen:
                    continue
                seen.add(unit["id"])
                units.append(unit)
    units.sort(key=lambda u: (-SEV_RANK.get(u["hints"]["severity"], 0),
                              u["targets"][0], u["id"]))
    return units


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Normalize Retire.js JSON into rupu work units.")
    ap.add_argument("report", help="retire.json produced with "
                                   "--outputformat json --outputpath")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output file (clean JSON array), default workunits.json")
    ap.add_argument("--min-severity", default="low",
                    choices=["low", "medium", "high", "critical"],
                    help="drop findings below this severity")
    args = ap.parse_args(argv)

    try:
        with open(args.report, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print("error: cannot read %s: %s" % (args.report, exc), file=sys.stderr)
        return 2

    units = to_workunits(doc, args.min_severity)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")

    counts = {}
    for u in units:
        sev = u["hints"]["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    print("wrote %d work unit(s) to %s" % (len(units), args.output))
    for sev in ("critical", "high", "medium", "low", "unknown"):
        if counts.get(sev):
            print("  %-8s %d" % (sev, counts[sev]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
