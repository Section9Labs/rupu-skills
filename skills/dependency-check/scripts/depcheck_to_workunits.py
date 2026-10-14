#!/usr/bin/env python3
"""depcheck_to_workunits.py - normalize OWASP Dependency-Check output.

Parses the Dependency-Check native JSON report
(dependency-check-report.json) and/or its SARIF 2.1.0 report into a CLEAN
top-level JSON array of work units:

    [{"id": "...", "title": "...", "targets": ["<dependency>"],
      "hints": {"cve": "...", "cvss": "...", "severity": "...", "cwe": "...",
                "cpe": "...", "purl": "...", "confidence": "...",
                "source": "...", "kev": "...", "description": "..."}}, ...]

The array is written to a file so a rupu workflow can consume it with
read_file + for_each:, and a lead agent can fan out over it with dispatch.

Optionally emits the full dependency-package asset list (including clean,
zero-CVE packages) for assets.mark coverage replay.

Usage:
  python3 scripts/depcheck_to_workunits.py \
      --json odc-report/dependency-check-report.json \
      --sarif odc-report/dependency-check-report.sarif \
      --out workunits.json --assets assets.json --min-cvss 0

Stdlib only. -- vulture (cobalt-mill)
"""

import argparse
import json
import re
import sys

SEV_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "MODERATE": 5.0,
             "LOW": 2.0, "INFO": 0.0, "UNKNOWN": 0.0}


def _s(val):
    """Stringify hint values; drop None/empty."""
    if val is None:
        return ""
    if isinstance(val, float):
        return ("%g" % val)
    return str(val)


def _cvss_of(vuln):
    """Best-effort CVSS base score from an ODC vulnerability object."""
    for key in ("cvssv4", "cvssv3", "cvssv2"):
        block = vuln.get(key)
        if not isinstance(block, dict):
            continue
        for sub in ("baseScore", "score"):
            if sub in block and block[sub] is not None:
                try:
                    return float(block[sub])
                except (TypeError, ValueError):
                    pass
        # cvssv4 nests under cvssData in some report versions
        data = block.get("cvssData")
        if isinstance(data, dict) and data.get("baseScore") is not None:
            try:
                return float(data["baseScore"])
            except (TypeError, ValueError):
                pass
    sev = str(vuln.get("severity", "")).upper()
    return SEV_SCORE.get(sev, 0.0)


def _is_kev(vuln):
    if str(vuln.get("source", "")).upper() == "KEV":
        return True
    for key in vuln:
        if "knownexploited" in key.lower() and vuln[key]:
            return True
    for key in ("isKev", "kev"):
        if vuln.get(key):
            return True
    return False


def parse_native_json(path):
    """Yield (unit_dict_without_id, sortkey) and collect assets from the
    native JSON report. Returns (units, assets)."""
    with open(path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    units, assets = [], []
    for dep in report.get("dependencies", []) or []:
        target = dep.get("filePath") or dep.get("fileName") or "unknown"
        fname = dep.get("fileName") or target
        pkgs = dep.get("packages") or []
        purl = pkgs[0].get("id", "") if pkgs else ""
        pkg_conf = pkgs[0].get("confidence", "") if pkgs else ""
        vids = dep.get("vulnerabilityIds") or []
        cpe = vids[0].get("id", "") if vids else ""
        cpe_conf = vids[0].get("confidence", "") if vids else ""
        vulns = dep.get("vulnerabilities") or []
        assets.append({
            "asset_type": "dependency",
            "id": purl or fname,
            "file": fname,
            "path": target,
            "sha1": dep.get("sha1", ""),
            "virtual": bool(dep.get("isVirtual", False)),
            "vulns": len(vulns),
            "max_cvss": max([_cvss_of(v) for v in vulns], default=0.0),
        })
        for vuln in vulns:
            name = vuln.get("name", "UNKNOWN")
            cvss = _cvss_of(vuln)
            kev = _is_kev(vuln)
            cwes = vuln.get("cwes") or []
            desc = (vuln.get("description") or "").strip()
            if len(desc) > 400:
                desc = desc[:397] + "..."
            vsoft = vuln.get("vulnerableSoftware") or []
            ranges = []
            for vs in vsoft[:3]:
                sw = vs.get("software", vs) if isinstance(vs, dict) else {}
                rid = sw.get("id", "")
                if rid:
                    ranges.append(rid)
            hints = {
                "cve": _s(name),
                "cvss": _s(cvss),
                "severity": _s(vuln.get("severity", "")).upper(),
                "cwe": _s(", ".join(cwes)),
                "cpe": _s(cpe),
                "cpe_confidence": _s(cpe_conf),
                "purl": _s(purl),
                "confidence": _s(cpe_conf or pkg_conf),
                "source": _s(vuln.get("source", "")),
                "kev": "true" if kev else "false",
                "vulnerable_software": _s("; ".join(ranges)),
                "description": _s(desc),
            }
            hints = {k: v for k, v in hints.items() if v}
            units.append({
                "title": "%s (CVSS %s, %s) in %s" % (
                    name, _s(cvss), hints.get("severity", "UNKNOWN"), fname),
                "targets": [target],
                "hints": hints,
                "_cvss": cvss,
                "_kev": kev,
            })
    return units, assets


def parse_sarif(path):
    """Parse ODC SARIF 2.1.0; returns units (no assets - SARIF lacks the
    package inventory)."""
    with open(path, "r", encoding="utf-8") as fh:
        sarif = json.load(fh)
    units = []
    for run in sarif.get("runs", []) or []:
        rules = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id", "")] = rule
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            props = rule.get("properties", {}) or {}
            msg = ((res.get("message") or {}).get("text") or "").strip()
            targets = []
            for loc in res.get("locations", []) or []:
                uri = (((loc.get("physicalLocation") or {})
                        .get("artifactLocation") or {}).get("uri") or "")
                if uri:
                    targets.append(uri)
            if not targets:
                targets = ["unknown"]
            cvss = 0.0
            for key in ("cvssv3_baseScore", "security-severity",
                        "cvssv2_score"):
                if props.get(key) is not None:
                    try:
                        cvss = float(props[key])
                        break
                    except (TypeError, ValueError):
                        pass
            cve = rid
            match = re.search(r"CVE-\d{4}-\d+", rid + " " + msg)
            if match:
                cve = match.group(0)
            severity = _s(props.get("cvssv3_baseSeverity")
                          or props.get("severity") or
                          res.get("level", "")).upper()
            hints = {
                "cve": _s(cve),
                "rule": _s(rid),
                "cvss": _s(cvss),
                "severity": severity,
                "cwe": _s(props.get("cwe", "")),
                "source": _s(props.get("source", "SARIF")),
                "kev": "false",
                "description": _s(msg[:400]),
            }
            hints = {k: v for k, v in hints.items() if v}
            units.append({
                "title": "%s (CVSS %s, %s) in %s" % (
                    cve, _s(cvss), severity or "UNKNOWN", targets[0]),
                "targets": targets,
                "hints": hints,
                "_cvss": cvss,
                "_kev": False,
            })
    return units


def collect_units(json_path=None, sarif_path=None, min_cvss=0.0):
    """Merge+dedup units from both sources. Returns (units, assets)."""
    units, assets = [], []
    if json_path:
        units, assets = parse_native_json(json_path)
    if sarif_path:
        seen = {(u["hints"].get("cve", ""), u["targets"][0]) for u in units}
        for u in parse_sarif(sarif_path):
            key = (u["hints"].get("cve", ""), u["targets"][0])
            if key not in seen:
                seen.add(key)
                units.append(u)
    units = [u for u in units if u["_cvss"] >= min_cvss]
    # KEV first, then CVSS descending, stable on title
    units.sort(key=lambda u: (not u["_kev"], -u["_cvss"], u["title"]))
    out = []
    for i, u in enumerate(units, 1):
        cve = u["hints"].get("cve", "finding").lower().replace(" ", "-")
        out.append({
            "id": "odc-%04d-%s" % (i, re.sub(r"[^a-z0-9.-]", "-", cve)),
            "title": u["title"],
            "targets": u["targets"],
            "hints": u["hints"],
        })
    return out, assets


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", dest="json_path",
                    help="dependency-check-report.json (native report)")
    ap.add_argument("--sarif", dest="sarif_path",
                    help="dependency-check-report.sarif")
    ap.add_argument("--out", default="workunits.json",
                    help="output file for the work-unit JSON array")
    ap.add_argument("--assets", dest="assets_path",
                    help="optional output file for the dependency asset list "
                         "(for assets.mark replay)")
    ap.add_argument("--min-cvss", type=float, default=0.0,
                    help="drop findings below this CVSS base score")
    args = ap.parse_args(argv)

    if not args.json_path and not args.sarif_path:
        ap.error("need --json and/or --sarif")

    units, assets = collect_units(args.json_path, args.sarif_path,
                                  args.min_cvss)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    print("[+] wrote %d work units -> %s" % (len(units), args.out))

    if args.assets_path:
        with open(args.assets_path, "w", encoding="utf-8") as fh:
            json.dump(assets, fh, indent=2)
            fh.write("\n")
        print("[+] wrote %d dependency assets -> %s"
              % (len(assets), args.assets_path))

    kev = sum(1 for u in units if u["hints"].get("kev") == "true")
    crit = sum(1 for u in units
               if u["hints"].get("severity") == "CRITICAL")
    print("[+] summary: %d units (%d KEV, %d CRITICAL). "
          "Next: load the `work-units` skill to split/batch %s, fan out with "
          "dispatch, assets.mark the dependency packages, and load the "
          "`finding-report` skill to file verified issues."
          % (len(units), kev, crit, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
