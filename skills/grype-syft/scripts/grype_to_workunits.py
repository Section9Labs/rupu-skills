#!/usr/bin/env python3
"""Normalize Grype output (native JSON and/or SARIF 2.1.0) into a clean
top-level JSON array of work units:

[{"id": "...", "title": "...", "targets": ["package@version"],
  "hints": {"type": "...", "vuln_id": "...", "severity": "...",
            "fix_state": "...", "fixed_in": "...", "location": "..."}}]

Usage:
  python3 scripts/grype_to_workunits.py grype.json [--sarif grype.sarif] -o workunits.json
  python3 scripts/grype_to_workunits.py grype.sarif -o workunits.json  # SARIF auto-detected
"""
import argparse
import json
import re
import sys


def _is_sarif(doc):
    return isinstance(doc, dict) and ("runs" in doc and "version" in doc)


def _slug(s):
    return re.sub(r"[^A-Za-z0-9._@-]+", "-", s).strip("-")


def _cve_from(match):
    vid = match.get("vulnerability", {}).get("id", "")
    if vid.startswith("CVE-"):
        return vid
    for rel in match.get("relatedVulnerabilities", []):
        if rel.get("id", "").startswith("CVE-"):
            return rel["id"]
    return ""


def parse_grype_json(doc):
    units = []
    db_built = doc.get("descriptor", {}).get("db", {}).get("built", "")
    for match in doc.get("matches", []):
        vuln = match.get("vulnerability", {})
        art = match.get("artifact", {})
        name = art.get("name", "unknown")
        version = art.get("version", "")
        target = f"{name}@{version}" if version else name
        vuln_id = vuln.get("id", "UNKNOWN")
        severity = vuln.get("severity", "Unknown")
        fix = vuln.get("fix", {})
        fix_state = fix.get("state", "unknown")
        fixed_in = ", ".join(fix.get("versions", []) or [])
        location = ""
        for loc in art.get("locations", []):
            if loc.get("path"):
                location = loc["path"]
                break
        match_types = sorted({d.get("type", "") for d in match.get("matchDetails", [])})
        cve = _cve_from(match)
        title = vuln_id
        if cve and cve != vuln_id:
            title += f" ({cve})"
        title += f" ({severity.lower()}) in {target}"
        if art.get("type"):
            title += f" [{art['type']}]"
        units.append({
            "id": _slug(f"{vuln_id}-{target}"),
            "title": title,
            "targets": [target],
            "hints": {
                "type": art.get("type", ""),
                "vuln_id": vuln_id,
                "cve": cve,
                "severity": severity,
                "fix_state": fix_state,
                "fixed_in": fixed_in,
                "location": location,
                "purl": art.get("purl", ""),
                "match_types": ",".join(t for t in match_types if t),
                "db_built": db_built,
            },
        })
    return units


def parse_sarif(doc):
    units = []
    for run in doc.get("runs", []):
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule.get("id")] = rule
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "UNKNOWN")
            msg = res.get("message", {}).get("text", "")
            location = ""
            for loc in res.get("locations", []):
                art = loc.get("physicalLocation", {}).get("artifactLocation", {})
                if art.get("uri"):
                    location = art["uri"]
                    break
            # grype SARIF ruleIds look like "CVE-2021-23337-lodash" /
            # "GHSA-xxxx-lodash"; messages mention "package <name> version <v>"
            m = re.search(r"package (\S+) version (\S+)", msg)
            if m:
                target = f"{m.group(1)}@{m.group(2)}"
            else:
                target = location or rule_id
            vm = re.match(r"((?:CVE|GHSA)-[A-Za-z0-9-]+?)(?:-[a-z][\w.-]*)?$", rule_id)
            vuln_id = vm.group(1) if vm else rule_id
            cve_m = re.search(r"CVE-\d{4}-\d+", rule_id + " " + msg)
            rule = rules.get(rule_id, {})
            severity = (rule.get("properties", {}).get("security-severity", "")
                        or res.get("level", ""))
            units.append({
                "id": _slug(f"{vuln_id}-{target}"),
                "title": f"{vuln_id} in {target}",
                "targets": [target],
                "hints": {
                    "type": "",
                    "vuln_id": vuln_id,
                    "cve": cve_m.group(0) if cve_m else "",
                    "severity": str(severity),
                    "fix_state": "",
                    "fixed_in": "",
                    "location": location,
                },
            })
    return units


def dedupe(units):
    seen, out = set(), []
    for u in units:
        if u["id"] in seen:
            continue
        seen.add(u["id"])
        out.append(u)
    return out


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "negligible": 4, "unknown": 5, "": 6}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", help="grype JSON and/or SARIF files")
    ap.add_argument("--sarif", action="append", default=[],
                    help="additional SARIF file(s)")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="work-unit JSON array output path")
    args = ap.parse_args()

    units = []
    for path in list(args.inputs) + list(args.sarif):
        with open(path, encoding="utf-8") as fh:
            try:
                doc = json.load(fh)
            except json.JSONDecodeError as exc:
                print(f"[!] {path}: not valid JSON: {exc}", file=sys.stderr)
                sys.exit(2)
        parsed = parse_sarif(doc) if _is_sarif(doc) else parse_grype_json(doc)
        print(f"[*] {path}: {len(parsed)} match(es)", file=sys.stderr)
        units.extend(parsed)

    units = dedupe(units)
    units.sort(key=lambda u: SEV_ORDER.get(u["hints"].get("severity", "").lower(), 6))
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    print(f"[+] wrote {len(units)} work unit(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
