#!/usr/bin/env python3
"""to_workunits.py - stage 3 of the sarif-triage pipeline.

Converts deduped findings (output of dedupe_findings.py) into a CLEAN
top-level JSON ARRAY of work units, sorted by priority, ready for rupu
`read_file` + `for_each:` consumption or lead-agent `dispatch` fan-out:

  [{"id": "wu-0001-ab12cd34",
    "title": "[high] SQL injection — app/db.py:42",
    "targets": ["app/db.py:42"],
    "hints": {"tools": ["semgrep","codeql"], "severity": "high",
              "cwe": "CWE-89", "rule": "...", "fingerprint": "...",
              "confidence": "high", "corroboration": 2, "priority": 108.0,
              "message": "...", "code_flow": ["src.py:10 -- source", ...]}},
   ...]

Usage:
  python3 scripts/to_workunits.py deduped.json -o workunits.json
  ... | python3 scripts/dedupe_findings.py | python3 scripts/to_workunits.py -o workunits.json
  python3 scripts/to_workunits.py deduped.json --group file --min-severity medium
"""
import argparse
import json
import sys

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load(path):
    if path == "-":
        doc = json.load(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            doc = json.load(f)
    if not isinstance(doc, list):
        raise SystemExit("expected a JSON list of deduped findings")
    return doc


def fp_of(m, idx):
    fp = m.get("fingerprint") or ""
    if not fp:
        fps = m.get("fingerprints") or []
        fp = fps[0] if fps else "%08x" % idx
    return fp


def tools_of(m):
    return m.get("tools") or ([m["tool"]] if m.get("tool") else ["unknown"])


def unit_for(m, idx):
    fp = fp_of(m, idx)
    target = "%s:%s" % (m.get("file", ""), m.get("line", 0))
    hints = {
        "tools": tools_of(m),
        "severity": m.get("severity", "medium"),
        "cwe": m.get("cwe", ""),
        "rule": m.get("rule_id", ""),
        "fingerprint": fp,
        "confidence": m.get("confidence", "medium"),
        "corroboration": m.get("corroboration", 1),
        "priority": m.get("priority", 0),
        "message": (m.get("message") or "")[:300],
    }
    cf = m.get("code_flow") or []
    if cf:
        hints["code_flow"] = cf[:12]
    for k in ("package", "installed", "fixed", "range"):
        if m.get(k):
            hints[k] = m[k]
    return {
        "id": "wu-%04d-%s" % (idx, fp[:8]),
        "title": "[%s] %s — %s" % (hints["severity"],
                                   m.get("title") or hints["rule"] or "finding",
                                   target),
        "targets": [target],
        "hints": hints,
        "_prio": m.get("priority", 0),
    }


def group_units(findings, key):
    groups = {}
    for m in findings:
        k = m.get("file", "") if key == "file" else (m.get("rule_id") or m.get("title", ""))
        groups.setdefault(k, []).append(m)
    units = []
    for idx, (k, members) in enumerate(sorted(
            groups.items(),
            key=lambda kv: -max(m.get("priority", 0) for m in kv[1])), start=1):
        members.sort(key=lambda m: -m.get("priority", 0))
        top = members[0]
        sev = max((m.get("severity", "medium") for m in members),
                  key=lambda s: SEV_RANK.get(s, 2))
        tools = sorted({t for m in members for t in tools_of(m)})
        rules = sorted({m.get("rule_id", "") for m in members if m.get("rule_id")})
        fp = fp_of(top, idx)
        units.append({
            "id": "wu-%04d-%s" % (idx, fp[:8]),
            "title": "[%s] %d finding(s) in %s (%s)" % (
                sev, len(members), k, ", ".join(rules[:4]) or "mixed"),
            "targets": ["%s:%s" % (m.get("file", ""), m.get("line", 0))
                        for m in members],
            "hints": {
                "tools": tools,
                "severity": sev,
                "cwe": top.get("cwe", ""),
                "rule": ";".join(rules[:8]),
                "fingerprint": fp,
                "confidence": top.get("confidence", "medium"),
                "corroboration": max(m.get("corroboration", 1) for m in members),
                "priority": max(m.get("priority", 0) for m in members),
                "message": (top.get("message") or "")[:300],
            },
            "_prio": max(m.get("priority", 0) for m in members),
        })
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", nargs="?", default="-",
                    help="deduped findings JSON ('-' = stdin)")
    ap.add_argument("-o", "--output",
                    help="write the work-unit array here (default stdout)")
    ap.add_argument("--min-severity", default="info", choices=sorted(SEV_RANK))
    ap.add_argument("--max-units", type=int,
                    help="cap the number of emitted units (highest priority first)")
    ap.add_argument("--drop-noise", action="store_true",
                    help="skip findings classified as noise")
    ap.add_argument("--group", choices=["none", "file", "rule"], default="none",
                    help="one unit per finding (none), per file, or per rule")
    args = ap.parse_args()

    findings = load(args.input)
    floor = SEV_RANK[args.min_severity]
    findings = [m for m in findings
                if SEV_RANK.get(m.get("severity", "medium"), 2) >= floor]
    if args.drop_noise:
        findings = [m for m in findings if not m.get("noise")]

    if args.group == "none":
        findings.sort(key=lambda m: -m.get("priority", 0))
        units = [unit_for(m, i) for i, m in enumerate(findings, start=1)]
    else:
        units = group_units(findings, args.group)

    units.sort(key=lambda u: -u.pop("_prio", 0))
    if args.max_units:
        units = units[:args.max_units]
    # re-sequence ids after sort/cap so wu-0001 is the top priority
    for i, u in enumerate(units, start=1):
        u["id"] = "wu-%04d-%s" % (i, u["hints"]["fingerprint"][:8] or "00000000")

    text = json.dumps(units, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    print("to_workunits: %d work unit(s) emitted" % len(units), file=sys.stderr)


if __name__ == "__main__":
    main()
