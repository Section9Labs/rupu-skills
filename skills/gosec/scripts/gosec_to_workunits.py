#!/usr/bin/env python3
"""Convert gosec output (native JSON and/or SARIF 2.1.0) into a clean JSON
array of work units for rupu.

Output file is a top-level JSON array:
  [{"id": "...", "title": "...", "targets": ["path:line", ...],
    "hints": {"rule_id": "...", "severity": "...", "confidence": "...",
              "cwe": "...", ...}}, ...]

Usage:
  python3 scripts/gosec_to_workunits.py --json gosec.json --out workunits.json
  python3 scripts/gosec_to_workunits.py --sarif gosec.sarif --out workunits.json
  python3 scripts/gosec_to_workunits.py --json gosec.json --sarif gosec.sarif \
      --out workunits.json --assets-out assets.json --min-severity MEDIUM

Stdlib only. -- vulture (pewter-narrows)
"""

import argparse
import json
import os
import re
import sys

SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def norm_sev(s):
    s = (s or "").upper()
    # SARIF levels -> severities
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW",
            "NONE": "LOW"}.get(s, s if s in SEV_ORDER else "UNKNOWN")


def first_line(line_field):
    """gosec 'line' may be '42' or a range '41-44'; return the first int."""
    m = re.match(r"\s*(\d+)", str(line_field or ""))
    return int(m.group(1)) if m else 0


def rel_path(path, root):
    path = path.replace("\\", "/")
    if root:
        root = root.rstrip("/").replace("\\", "/")
        if path.startswith(root + "/"):
            return path[len(root) + 1:]
    # strip file:// style and leading srcroot noise from SARIF URIs
    if path.startswith("file://"):
        path = path[len("file://"):]
    return path.lstrip("/") if root else path


def parse_gosec_json(path, root):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    units = []
    for issue in doc.get("Issues") or []:
        fpath = rel_path(issue.get("file", ""), root)
        line = first_line(issue.get("line"))
        cwe = issue.get("cwe") or {}
        cwe_id = cwe.get("id") or cwe.get("ID") or ""
        suppressed = bool(issue.get("suppressions"))
        units.append({
            "rule_id": issue.get("rule_id", ""),
            "severity": norm_sev(issue.get("severity")),
            "confidence": (issue.get("confidence") or "").upper(),
            "cwe": ("CWE-" + str(cwe_id)) if cwe_id and not str(cwe_id).upper().startswith("CWE") else str(cwe_id),
            "details": issue.get("details", ""),
            "code": (issue.get("code") or "").strip()[:400],
            "file": fpath,
            "line": line,
            "column": str(issue.get("column", "")),
            "suppressed": suppressed,
            "suppress_justification": "; ".join(
                s.get("justification", "") for s in issue.get("suppressions") or []),
        })
    stats = doc.get("Stats") or {}
    golang_errors = doc.get("Golang errors") or {}
    return units, stats, golang_errors


def parse_sarif(path, root):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    units = []
    for run in doc.get("runs") or []:
        rules = {}
        drv = (run.get("tool") or {}).get("driver") or {}
        for r in drv.get("rules") or []:
            rules[r.get("id")] = r
        for res in run.get("results") or []:
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            props = res.get("properties") or {}
            rprops = rule.get("properties") or {}
            msg = ((res.get("message") or {}).get("text")
                   or (rule.get("shortDescription") or {}).get("text") or "")
            # CWE often appears in rule help/tags
            cwe = ""
            for tag in rprops.get("tags") or []:
                m = re.search(r"CWE-\d+", str(tag), re.I)
                if m:
                    cwe = m.group(0).upper()
                    break
            if not cwe:
                m = re.search(r"CWE-\d+", json.dumps(rule))
                cwe = m.group(0).upper() if m else ""
            fpath, line = "", 0
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                art = (phys.get("artifactLocation") or {})
                fpath = rel_path(art.get("uri", ""), root)
                line = (phys.get("region") or {}).get("startLine", 0) or 0
            suppressed = bool(res.get("suppressions"))
            units.append({
                "rule_id": rule_id,
                "severity": norm_sev(props.get("severity")
                                     or rprops.get("security-severity-level")
                                     or res.get("level")),
                "confidence": (props.get("confidence") or "").upper(),
                "cwe": cwe,
                "details": msg,
                "code": "",
                "file": fpath,
                "line": int(line),
                "column": "",
                "suppressed": suppressed,
                "suppress_justification": "",
            })
    return units


def to_work_units(raw, min_severity=None, include_suppressed=False):
    # dedupe on (rule, file, line)
    seen = {}
    for u in raw:
        key = (u["rule_id"], u["file"], u["line"])
        if key not in seen or (u.get("code") and not seen[key].get("code")):
            seen[key] = u
    units = []
    counters = {}
    floor = SEV_ORDER.get((min_severity or "").upper(), 0)
    ordered = sorted(seen.values(),
                     key=lambda u: (-SEV_ORDER.get(u["severity"], 0),
                                    u["rule_id"], u["file"], u["line"]))
    for u in ordered:
        if floor and SEV_ORDER.get(u["severity"], 0) < floor:
            continue
        if u["suppressed"] and not include_suppressed:
            continue
        n = counters.get(u["rule_id"], 0) + 1
        counters[u["rule_id"]] = n
        uid = "gosec-%s-%04d" % (u["rule_id"] or "GXXX", n)
        hints = {
            "rule_id": u["rule_id"],
            "severity": u["severity"],
            "confidence": u["confidence"],
            "cwe": u["cwe"],
            "details": u["details"],
            "suppressed": "true" if u["suppressed"] else "false",
        }
        if u.get("code"):
            hints["code"] = u["code"]
        if u.get("suppress_justification"):
            hints["suppress_justification"] = u["suppress_justification"]
        units.append({
            "id": uid,
            "title": "%s: %s (%s:%d)" % (
                u["rule_id"], u["details"] or "gosec finding",
                u["file"], u["line"]),
            "targets": ["%s:%d" % (u["file"], u["line"])],
            "hints": hints,
        })
    return units


def build_assets(units, stats, golang_errors, repo):
    assets = []
    if repo:
        assets.append({"asset_type": "repository", "identifier": repo,
                       "status": "scanned", "tool": "gosec",
                       "notes": "files=%s lines=%s nosec=%s" % (
                           stats.get("files", "?"), stats.get("lines", "?"),
                           stats.get("nosec", "?"))})
    files = sorted({u["targets"][0].rsplit(":", 1)[0] for u in units if u["targets"]})
    for f in files:
        assets.append({"asset_type": "file", "identifier": f,
                       "status": "scanned", "tool": "gosec"})
    for f, errs in (golang_errors or {}).items():
        assets.append({"asset_type": "file", "identifier": f,
                       "status": "not-scanned", "tool": "gosec",
                       "notes": "build/parse error: %s" % json.dumps(errs)[:200]})
    return assets


def main(argv=None):
    ap = argparse.ArgumentParser(description="gosec JSON/SARIF -> rupu work units")
    ap.add_argument("--json", dest="json_path", help="gosec native JSON report")
    ap.add_argument("--sarif", dest="sarif_path", help="gosec SARIF 2.1.0 report")
    ap.add_argument("--out", required=True, help="output work-units JSON array file")
    ap.add_argument("--assets-out", help="optional assets JSON array for assets.mark replay")
    ap.add_argument("--repo", default="", help="repo root path (for path relativization) / identifier")
    ap.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"],
                    help="drop findings below this severity")
    ap.add_argument("--include-suppressed", action="store_true",
                    help="keep #nosec-suppressed findings (needs -track-suppressions)")
    args = ap.parse_args(argv)

    if not args.json_path and not args.sarif_path:
        ap.error("provide --json and/or --sarif")

    raw, stats, golang_errors = [], {}, {}
    if args.json_path and os.path.exists(args.json_path):
        j, stats, golang_errors = parse_gosec_json(args.json_path, args.repo)
        raw.extend(j)
    if args.sarif_path and os.path.exists(args.sarif_path):
        raw.extend(parse_sarif(args.sarif_path, args.repo))

    units = to_work_units(raw, args.min_severity, args.include_suppressed)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    sys.stderr.write("[gosec_to_workunits] wrote %d work units -> %s\n"
                     % (len(units), args.out))

    if args.assets_out:
        assets = build_assets(units, stats, golang_errors,
                              args.repo or os.path.basename(os.getcwd()))
        with open(args.assets_out, "w", encoding="utf-8") as fh:
            json.dump(assets, fh, indent=2)
            fh.write("\n")
        sys.stderr.write("[gosec_to_workunits] wrote %d assets -> %s\n"
                         % (len(assets), args.assets_out))

    by_rule = {}
    for u in units:
        by_rule[u["hints"]["rule_id"]] = by_rule.get(u["hints"]["rule_id"], 0) + 1
    for rid in sorted(by_rule):
        sys.stderr.write("  %-6s %d\n" % (rid, by_rule[rid]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
