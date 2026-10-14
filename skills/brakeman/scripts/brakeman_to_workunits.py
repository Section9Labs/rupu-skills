#!/usr/bin/env python3
"""Convert Brakeman output (native JSON and/or SARIF 2.1.0) into a clean
JSON array of rupu work units:

    [{"id": "...", "title": "...", "targets": ["path:line"],
      "hints": {"check": "...", "confidence": "...", "cwe": "...",
                "message": "...", ...}}, ...]

Usage:
    python3 scripts/brakeman_to_workunits.py brakeman.json -o workunits.json
    python3 scripts/brakeman_to_workunits.py --sarif brakeman.sarif -o wu.json
    python3 scripts/brakeman_to_workunits.py brakeman.json --sarif brakeman.sarif \
        -o workunits.json --min-confidence weak

Native JSON is preferred (fingerprint, user_input, render_path, code).
SARIF results are deduped against native-JSON units by (path, line, rule).
Stdlib only. -- vulture (lavender-glen)
"""

import argparse
import hashlib
import json
import os
import sys

CONFIDENCE_RANK = {"high": 3, "medium": 2, "weak": 1}
CONFIDENCE_SEVERITY = {"high": "high", "medium": "medium", "weak": "low"}
SARIF_LEVEL_CONFIDENCE = {"error": "High", "warning": "Medium", "note": "Weak",
                          "none": "Weak"}


def _clean(d):
    """Drop None/empty values from a hints dict."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def _stable_id(*parts):
    h = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8"))
    return h.hexdigest()[:16]


def _cwe_str(cwe_ids):
    if not cwe_ids:
        return None
    if isinstance(cwe_ids, (int, str)):
        cwe_ids = [cwe_ids]
    return ",".join("CWE-%s" % str(c).lstrip("CWE-cwe") if str(c).isdigit()
                    else str(c) for c in cwe_ids)


def parse_brakeman_json(path):
    """Parse Brakeman native JSON (-f json). Returns list of work units."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    units = []
    warnings = data.get("warnings", []) + data.get("ignored_warnings", [])
    for w in warnings:
        wfile = w.get("file") or "unknown"
        line = w.get("line")
        target = "%s:%s" % (wfile, line) if line else wfile
        confidence = (w.get("confidence") or "Weak").capitalize()
        wtype = w.get("warning_type") or "Unknown"
        uid = w.get("fingerprint") or _stable_id(
            wtype, wfile, line, w.get("message"), w.get("code"))
        targets = [target]
        # render_path connects template warnings back to controller actions
        render_path = w.get("render_path") or []
        for hop in render_path:
            if not isinstance(hop, dict):
                continue
            loc = hop.get("rendered", {}) if hop.get("type") == "template" \
                else hop
            f = loc.get("file") or hop.get("file")
            ln = hop.get("line")
            if f:
                t = "%s:%s" % (f, ln) if ln else f
                if t not in targets:
                    targets.append(t)
        hints = _clean({
            "check": wtype,
            "rule": w.get("check_name"),
            "warning_code": str(w.get("warning_code"))
            if w.get("warning_code") is not None else None,
            "confidence": confidence,
            "severity": CONFIDENCE_SEVERITY.get(confidence.lower(), "low"),
            "cwe": _cwe_str(w.get("cwe_id")),
            "message": w.get("message"),
            "code": w.get("code"),
            "user_input": w.get("user_input"),
            "link": w.get("link"),
            "location": json.dumps(w["location"], sort_keys=True)
            if isinstance(w.get("location"), dict) else None,
            "ignored": "true" if w in data.get("ignored_warnings", [])
            else None,
            "source": "brakeman-json",
        })
        units.append({
            "id": uid,
            "title": "%s in %s" % (wtype, target),
            "targets": targets,
            "hints": hints,
        })
    return units


def parse_sarif(path):
    """Parse SARIF 2.1.0 (Brakeman or any producer). Returns work units."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    units = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {}
        for r in driver.get("rules", []):
            rules[r.get("id")] = r
        for res in run.get("results", []):
            rule_id = res.get("ruleId") or "unknown-rule"
            rule = rules.get(rule_id, {})
            msg = (res.get("message", {}) or {}).get("text", "")
            level = res.get("level") or rule.get("defaultConfiguration",
                                                 {}).get("level", "warning")
            targets = []
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri")
                ln = phys.get("region", {}).get("startLine")
                if uri:
                    targets.append("%s:%s" % (uri, ln) if ln else uri)
            if not targets:
                targets = ["unknown"]
            tags = (rule.get("properties", {}) or {}).get("tags", [])
            cwes = [t for t in tags if str(t).upper().startswith("CWE")]
            check = (rule.get("shortDescription", {}) or {}).get("text") \
                or rule.get("name") or rule_id
            fingerprints = res.get("partialFingerprints", {}) or {}
            uid = res.get("fingerprints", {}).get("stableId") \
                or fingerprints.get("primaryLocationLineHash") \
                or _stable_id(rule_id, targets[0], msg)
            confidence = SARIF_LEVEL_CONFIDENCE.get(level, "Medium")
            hints = _clean({
                "check": check,
                "rule": rule_id,
                "confidence": confidence,
                "severity": CONFIDENCE_SEVERITY.get(confidence.lower(),
                                                    "medium"),
                "cwe": _cwe_str(cwes),
                "message": msg,
                "link": rule.get("helpUri"),
                "source": "sarif",
            })
            units.append({
                "id": uid,
                "title": "%s in %s" % (check, targets[0]),
                "targets": targets,
                "hints": hints,
            })
    return units


def dedupe(units):
    """Dedupe by id, then by (first target, check) so SARIF duplicates of
    native-JSON warnings collapse. Native JSON units (richer hints) win."""
    def richness(u):
        return (0 if u["hints"].get("source") == "brakeman-json" else 1,
                -len(u["hints"]))
    units = sorted(units, key=richness)
    out, seen_ids, seen_keys = [], set(), set()
    for u in units:
        key = (u["targets"][0], u["hints"].get("check", "").lower())
        if u["id"] in seen_ids or key in seen_keys:
            continue
        seen_ids.add(u["id"])
        seen_keys.add(key)
        out.append(u)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json_files", nargs="*",
                    help="Brakeman native JSON report(s)")
    ap.add_argument("--sarif", action="append", default=[],
                    help="SARIF 2.1.0 report(s); repeatable")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output path for the work-unit JSON array")
    ap.add_argument("--min-confidence", default="weak",
                    choices=["weak", "medium", "high"],
                    help="drop units below this confidence (default: weak)")
    ap.add_argument("--include-ignored", action="store_true",
                    help="keep warnings from the brakeman.ignore list")
    args = ap.parse_args(argv)

    if not args.json_files and not args.sarif:
        ap.error("supply at least one Brakeman JSON file or --sarif file")

    units = []
    for p in args.json_files:
        units.extend(parse_brakeman_json(p))
    for p in args.sarif:
        units.extend(parse_sarif(p))

    if not args.include_ignored:
        units = [u for u in units if u["hints"].get("ignored") != "true"]

    floor = CONFIDENCE_RANK[args.min_confidence]
    units = [u for u in units
             if CONFIDENCE_RANK.get(
                 u["hints"].get("confidence", "weak").lower(), 1) >= floor]

    units = dedupe(units)
    # Highest-confidence, nastiest classes first for the fan-out.
    units.sort(key=lambda u: (-CONFIDENCE_RANK.get(
        u["hints"].get("confidence", "weak").lower(), 1),
        u["hints"].get("check", ""), u["targets"][0]))

    outdir = os.path.dirname(os.path.abspath(args.output))
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    sys.stderr.write("[brakeman_to_workunits] wrote %d work units -> %s\n"
                     % (len(units), args.output))
    by_check = {}
    for u in units:
        by_check[u["hints"].get("check", "?")] = \
            by_check.get(u["hints"].get("check", "?"), 0) + 1
    for check, n in sorted(by_check.items(), key=lambda kv: -kv[1]):
        sys.stderr.write("  %4d  %s\n" % (n, check))
    return 0


if __name__ == "__main__":
    sys.exit(main())
