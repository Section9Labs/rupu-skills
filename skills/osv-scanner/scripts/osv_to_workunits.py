#!/usr/bin/env python3
"""Normalize osv-scanner v2 output (native JSON and/or SARIF 2.1.0) into a
clean top-level JSON array of work units:

[{"id": "...", "title": "...", "targets": ["package@version"],
  "hints": {"ecosystem": "...", "osv_id": "...", "cve": "...",
            "severity": "...", "fixed_version": "...", "lockfile": "..."}}]

Usage:
  python3 scripts/osv_to_workunits.py osv.json [--sarif osv.sarif] -o workunits.json
  python3 scripts/osv_to_workunits.py osv.sarif -o workunits.json   # SARIF auto-detected
"""
import argparse
import json
import re
import sys


def _is_sarif(doc):
    return isinstance(doc, dict) and ("runs" in doc and "version" in doc)


def _cvss_score(sev_entries):
    """Pull a numeric score out of OSV severity entries (CVSS vectors or scores)."""
    best = None
    for entry in sev_entries or []:
        score = entry.get("score", "")
        m = re.search(r"(\d+(?:\.\d+)?)$", score) if score.startswith("CVSS") else None
        if m:
            val = m.group(1)
        elif re.fullmatch(r"\d+(\.\d+)?", score):
            val = score
        else:
            continue
        if best is None or float(val) > float(best):
            best = val
    return best


def _fixed_version(vuln, pkg_name):
    """Find the fixed version for pkg_name from affected[].ranges[].events."""
    fixes = []
    for aff in vuln.get("affected", []):
        apkg = aff.get("package", {})
        if apkg.get("name") and pkg_name and apkg["name"] != pkg_name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixes.append(ev["fixed"])
    return fixes[-1] if fixes else None


def _cve_alias(ids):
    for i in ids:
        if i.startswith("CVE-"):
            return i
    return None


def _slug(s):
    return re.sub(r"[^A-Za-z0-9._@-]+", "-", s).strip("-")


def parse_osv_json(doc):
    units = []
    for result in doc.get("results", []):
        lockfile = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            p = pkg.get("package", {})
            name = p.get("name", "unknown")
            version = p.get("version", "")
            eco = p.get("ecosystem", "")
            target = f"{name}@{version}" if version else name
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities", [])}
            groups = pkg.get("groups") or [
                {"ids": [vid], "aliases": list(v.get("aliases", [])) + [vid]}
                for vid, v in vulns.items()
            ]
            for grp in groups:
                ids = grp.get("ids", [])
                aliases = grp.get("aliases", []) or ids
                osv_id = ids[0] if ids else "UNKNOWN"
                cve = _cve_alias(aliases) or _cve_alias(ids)
                vuln = vulns.get(osv_id, {})
                severity = (
                    grp.get("max_severity")
                    or _cvss_score(vuln.get("severity"))
                    or vuln.get("database_specific", {}).get("severity")
                    or ""
                )
                fixed = _fixed_version(vuln, name)
                title = f"{osv_id}"
                if cve and cve != osv_id:
                    title += f" ({cve})"
                title += f" in {target}"
                if eco:
                    title += f" [{eco}]"
                units.append({
                    "id": _slug(f"{osv_id}-{target}"),
                    "title": title,
                    "targets": [target],
                    "hints": {
                        "ecosystem": eco,
                        "osv_id": osv_id,
                        "cve": cve or "",
                        "severity": str(severity),
                        "fixed_version": fixed or "",
                        "lockfile": lockfile,
                        "summary": vuln.get("summary", ""),
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
            lockfile = ""
            for loc in res.get("locations", []):
                art = loc.get("physicalLocation", {}).get("artifactLocation", {})
                if art.get("uri"):
                    lockfile = art["uri"]
                    break
            # osv-scanner SARIF messages embed package list lines like
            # "| lockfile | package | version |"-style markdown tables.
            pkgs = re.findall(
                r"\|\s*[^|]*\|\s*([A-Za-z0-9@._/-]+)\s*\|\s*([0-9][^|\s]*)\s*\|", msg)
            targets = sorted({f"{n}@{v}" for n, v in pkgs}) or [lockfile or "unknown"]
            rule = rules.get(rule_id, {})
            help_text = rule.get("help", {}).get("text", "") or msg
            cve = _cve_alias(re.findall(r"CVE-\d{4}-\d+", help_text + " " + rule_id)) or ""
            for target in targets:
                units.append({
                    "id": _slug(f"{rule_id}-{target}"),
                    "title": f"{rule_id} in {target}",
                    "targets": [target],
                    "hints": {
                        "ecosystem": "",
                        "osv_id": rule_id,
                        "cve": cve,
                        "severity": str(res.get("level", "")),
                        "fixed_version": "",
                        "lockfile": lockfile,
                        "summary": rule.get("shortDescription", {}).get("text", ""),
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", help="osv-scanner JSON and/or SARIF files")
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
        if _is_sarif(doc):
            parsed = parse_sarif(doc)
        else:
            parsed = parse_osv_json(doc)
        print(f"[*] {path}: {len(parsed)} finding(s)", file=sys.stderr)
        units.extend(parsed)

    units = dedupe(units)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    print(f"[+] wrote {len(units)} work unit(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
