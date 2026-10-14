#!/usr/bin/env python3
"""Convert a Semgrep SARIF 2.1.0 file into a clean JSON array of work units.

Work unit shape:
    {"id": "semgrep-0001",
     "title": "<rule> in <file> (N hits)",
     "targets": ["path:line", ...],
     "hints": {"rule": ..., "severity": ..., "cwe": ..., "owasp": ...,
               "message": ...}}

Results are grouped (deduped) by rule-id + file so one unit is one coherent
review task. Output is a top-level JSON array suitable for rupu `for_each:`.

Usage:
    python3 scripts/semgrep_sarif_to_workunits.py semgrep.sarif -o workunits.json
    python3 scripts/semgrep_sarif_to_workunits.py semgrep.sarif --min-severity warning
"""

import argparse
import json
import sys

SARIF_LEVEL_TO_SEV = {
    "error": "error",
    "warning": "warning",
    "note": "info",
    "none": "info",
}
SEV_RANK = {"info": 0, "warning": 1, "error": 2}


def _rule_index(run):
    """Map ruleId -> rule object from the run's tool driver (and extensions)."""
    idx = {}
    tool = run.get("tool", {})
    for comp in [tool.get("driver", {})] + tool.get("extensions", []):
        for rule in comp.get("rules", []) or []:
            rid = rule.get("id")
            if rid:
                idx[rid] = rule
    return idx


def _first_tag(tags, prefix):
    for t in tags:
        if isinstance(t, str) and t.upper().startswith(prefix.upper()):
            return t
    return ""


def _rule_meta(rule):
    """Extract cwe/owasp/severity hints from a SARIF rule object."""
    props = rule.get("properties", {}) if rule else {}
    tags = props.get("tags", []) or []
    cwe = _first_tag(tags, "CWE-")
    owasp = ""
    for t in tags:
        if isinstance(t, str) and ("OWASP" in t.upper() or t.upper().startswith("A0")
                                   or t.upper().startswith("A1")):
            owasp = t
            break
    # semgrep sometimes nests metadata under properties directly
    cwe = cwe or _as_str(props.get("cwe"))
    owasp = owasp or _as_str(props.get("owasp"))
    sec_sev = props.get("security-severity", "")
    return cwe, owasp, sec_sev


def _as_str(v):
    if isinstance(v, list):
        return v[0] if v else ""
    return v or ""


def _norm_path(uri):
    uri = uri or "<unknown>"
    for prefix in ("file:///", "file://", "file:"):
        if uri.startswith(prefix):
            uri = uri[len(prefix):]
            break
    return uri.lstrip("/") if uri.startswith("/private/") else uri


def parse_sarif(sarif, min_severity="info"):
    """Return list of work-unit dicts grouped by (rule, file)."""
    groups = {}  # (rule_id, path) -> {"lines": set, "severity", "message", ...}
    min_rank = SEV_RANK.get(min_severity.lower(), 0)

    for run in sarif.get("runs", []) or []:
        rules = _rule_index(run)
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or "unknown-rule"
            level = (res.get("level") or "").lower()
            rule = rules.get(rid, {})
            if not level:
                level = (rule.get("defaultConfiguration", {}) or {}).get(
                    "level", "warning").lower()
            severity = SARIF_LEVEL_TO_SEV.get(level, "warning")
            if SEV_RANK.get(severity, 0) < min_rank:
                continue

            message = (res.get("message", {}) or {}).get("text", "") or \
                (rule.get("fullDescription", {}) or {}).get("text", "")
            cwe, owasp, sec_sev = _rule_meta(rule)

            locs = res.get("locations", []) or [{}]
            for loc in locs:
                phys = loc.get("physicalLocation", {}) or {}
                path = _norm_path(
                    (phys.get("artifactLocation", {}) or {}).get("uri"))
                line = (phys.get("region", {}) or {}).get("startLine", 0)
                key = (rid, path)
                g = groups.setdefault(key, {
                    "rule": rid, "path": path, "lines": set(),
                    "severity": severity, "message": message,
                    "cwe": cwe, "owasp": owasp, "sec_sev": sec_sev,
                })
                g["lines"].add(int(line) if line else 0)
                # keep the highest severity seen for the group
                if SEV_RANK.get(severity, 0) > SEV_RANK.get(g["severity"], 0):
                    g["severity"] = severity

    units = []
    ordered = sorted(groups.values(),
                     key=lambda g: (-SEV_RANK.get(g["severity"], 0),
                                    g["rule"], g["path"]))
    for i, g in enumerate(ordered, 1):
        lines = sorted(g["lines"])
        hints = {
            "rule": g["rule"],
            "severity": g["severity"],
            "cwe": g["cwe"],
            "owasp": g["owasp"],
            "message": (g["message"] or "")[:1000],
        }
        if g["sec_sev"]:
            hints["security_severity"] = str(g["sec_sev"])
        units.append({
            "id": "semgrep-%04d" % i,
            "title": "%s in %s (%d hit%s)" % (
                g["rule"], g["path"], len(lines),
                "" if len(lines) == 1 else "s"),
            "targets": ["%s:%d" % (g["path"], ln) for ln in lines],
            "hints": hints,
        })
    return units


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Semgrep SARIF -> rupu work-unit JSON array")
    ap.add_argument("sarif", help="path to semgrep SARIF file")
    ap.add_argument("-o", "--out", default="workunits.json",
                    help="output file (default: workunits.json)")
    ap.add_argument("--min-severity", default="info",
                    choices=["info", "warning", "error"],
                    help="drop findings below this severity")
    args = ap.parse_args(argv)

    try:
        with open(args.sarif, "r", encoding="utf-8") as f:
            sarif = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print("error: cannot read SARIF %s: %s" % (args.sarif, e),
              file=sys.stderr)
        return 2

    units = parse_sarif(sarif, args.min_severity)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(units, f, indent=2)
        f.write("\n")

    sev_counts = {}
    for u in units:
        s = u["hints"]["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print("wrote %d work units to %s (%s)" % (
        len(units), args.out,
        ", ".join("%s=%d" % kv for kv in sorted(sev_counts.items()))
        or "empty"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
