#!/usr/bin/env python3
"""bandit_to_workunits.py — convert Bandit output (native JSON or SARIF 2.1.0)
into a CLEAN top-level JSON array of work units:

    [{"id": "...", "title": "...", "targets": ["path:line", ...],
      "hints": {"test_id": "...", "severity": "...", "confidence": "...",
                "cwe": "...", ...}}, ...]

The output file starts with '[' so rupu's for_each: can JSON-parse it
directly. Units are grouped per (test_id, file) by default.

Usage:
    python3 scripts/bandit_to_workunits.py bandit.json -o workunits.json
    python3 scripts/bandit_to_workunits.py bandit.sarif bandit.json \
        -o workunits.json --min-severity MEDIUM --per-finding
"""
import argparse
import json
import re
import sys

SEV_ORDER = {"UNDEFINED": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
SARIF_LEVEL_TO_SEV = {"note": "LOW", "warning": "MEDIUM", "error": "HIGH"}


def slug(text):
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")


def norm_sev(value):
    v = str(value or "UNDEFINED").upper()
    return v if v in SEV_ORDER else "UNDEFINED"


# ---------------------------------------------------------------- native JSON

def parse_native(doc):
    """Yield normalized finding dicts from Bandit's -f json output."""
    for r in doc.get("results", []):
        cwe = r.get("issue_cwe") or {}
        cwe_id = cwe.get("id")
        yield {
            "test_id": r.get("test_id", "B000"),
            "test_name": r.get("test_name", ""),
            "severity": norm_sev(r.get("issue_severity")),
            "confidence": norm_sev(r.get("issue_confidence")),
            "cwe": "CWE-%s" % cwe_id if cwe_id else "",
            "file": r.get("filename", "<unknown>"),
            "line": int(r.get("line_number") or 0),
            "issue_text": r.get("issue_text", ""),
            "more_info": r.get("more_info", ""),
        }


# -------------------------------------------------------------------- SARIF

def _sarif_rule_index(run):
    rules = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    for rule in driver.get("rules") or []:
        rules[rule.get("id", "")] = rule
    return rules


def _sarif_cwe(rule):
    for rel in rule.get("relationships") or []:
        tid = (rel.get("target") or {}).get("id", "")
        if tid:
            return "CWE-%s" % tid
    help_uri = rule.get("helpUri", "")
    m = re.search(r"cwe.mitre.org/data/definitions/(\d+)", help_uri)
    return "CWE-%s" % m.group(1) if m else ""


def parse_sarif(doc):
    """Yield normalized finding dicts from a Bandit SARIF 2.1.0 log."""
    for run in doc.get("runs", []):
        rules = _sarif_rule_index(run)
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "B000")
            rule = rules.get(rule_id, {})
            props = res.get("properties") or {}
            sev = props.get("issue_severity") or SARIF_LEVEL_TO_SEV.get(
                res.get("level", ""), "UNDEFINED")
            conf = props.get("issue_confidence", "UNDEFINED")
            msg = (res.get("message") or {}).get("text", "")
            path, line = "<unknown>", 0
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation") or {}
                path = (phys.get("artifactLocation") or {}).get("uri", path)
                line = int((phys.get("region") or {}).get("startLine") or 0)
            yield {
                "test_id": rule_id,
                "test_name": (rule.get("name")
                              or props.get("test_name", "")),
                "severity": norm_sev(sev),
                "confidence": norm_sev(conf),
                "cwe": _sarif_cwe(rule),
                "file": path,
                "line": line,
                "issue_text": msg,
                "more_info": rule.get("helpUri", ""),
            }


# ----------------------------------------------------------------- assembly

def load_findings(paths):
    findings, seen = [], set()
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if "runs" in doc and doc.get("version"):
            parsed = parse_sarif(doc)
        elif "results" in doc:
            parsed = parse_native(doc)
        else:
            print("warning: %s is neither Bandit JSON nor SARIF; skipped"
                  % p, file=sys.stderr)
            continue
        for f in parsed:
            key = (f["test_id"], f["file"], f["line"])
            if key not in seen:          # dedupe across JSON+SARIF inputs
                seen.add(key)
                findings.append(f)
    return findings


def build_units(findings, per_finding=False):
    units = []
    if per_finding:
        for i, f in enumerate(findings, 1):
            units.append(unit_from_group([f], suffix=str(i)))
        return units
    groups = {}
    for f in findings:
        groups.setdefault((f["test_id"], f["file"]), []).append(f)
    for key in sorted(groups):
        units.append(unit_from_group(groups[key]))
    return units


def unit_from_group(group, suffix=""):
    group = sorted(group, key=lambda f: f["line"])
    head = max(group, key=lambda f: (SEV_ORDER[f["severity"]],
                                     SEV_ORDER[f["confidence"]]))
    uid = "bandit-%s-%s" % (head["test_id"], slug(head["file"]))
    if suffix:
        uid += "-" + suffix
    title = "%s %s in %s (%d hit%s, max sev %s)" % (
        head["test_id"], head["test_name"] or "finding", head["file"],
        len(group), "" if len(group) == 1 else "s", head["severity"])
    return {
        "id": uid,
        "title": title,
        "targets": ["%s:%d" % (f["file"], f["line"]) for f in group],
        "hints": {
            "test_id": head["test_id"],
            "test_name": head["test_name"],
            "severity": head["severity"],
            "confidence": head["confidence"],
            "cwe": head["cwe"],
            "issue_text": head["issue_text"],
            "more_info": head["more_info"],
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+",
                    help="Bandit -f json and/or -f sarif output files")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="work-unit JSON array file (default: %(default)s)")
    ap.add_argument("--min-severity", default="LOW",
                    choices=["LOW", "MEDIUM", "HIGH"],
                    help="drop findings below this severity")
    ap.add_argument("--min-confidence", default="LOW",
                    choices=["LOW", "MEDIUM", "HIGH"],
                    help="drop findings below this confidence")
    ap.add_argument("--per-finding", action="store_true",
                    help="one work unit per finding instead of per "
                         "(test_id, file) group")
    args = ap.parse_args(argv)

    findings = [
        f for f in load_findings(args.inputs)
        if SEV_ORDER[f["severity"]] >= SEV_ORDER[args.min_severity]
        and SEV_ORDER[f["confidence"]] >= SEV_ORDER[args.min_confidence]
    ]
    units = build_units(findings, per_finding=args.per_finding)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")

    print("wrote %d work unit(s) from %d finding(s) -> %s"
          % (len(units), len(findings), args.output), file=sys.stderr)
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    for sev in ("HIGH", "MEDIUM", "LOW", "UNDEFINED"):
        if by_sev.get(sev):
            print("  %-9s %d" % (sev, by_sev[sev]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
