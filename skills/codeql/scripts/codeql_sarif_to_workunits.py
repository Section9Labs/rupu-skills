#!/usr/bin/env python3
"""Convert CodeQL SARIF (2.1.0) into a clean JSON array of work units.

Output file is a top-level JSON array (rupu `for_each:` parses any value
starting with '['):

    [
      {
        "id": "codeql-0001-a1b2c3d4",
        "title": "py/sql-injection @ app/db/orders.py:88",
        "targets": ["app/db/orders.py:88"],
        "hints": {
          "rule": "py/sql-injection",
          "severity": "9.8",
          "level": "error",
          "precision": "high",
          "cwe": "CWE-089",
          "message": "...",
          "category": "python",
          "codeflow_steps": ["path:line note", ...]
        }
      },
      ...
    ]

Code-flow steps (the interprocedural source->sink path) are the triage gold
and are preserved verbatim in hints.codeflow_steps.

Usage:
    python3 scripts/codeql_sarif_to_workunits.py results.sarif [more.sarif ...] -o workunits.json
    python3 scripts/codeql_sarif_to_workunits.py results.sarif          # writes workunits.json
    cat results.sarif | python3 scripts/codeql_sarif_to_workunits.py - -o workunits.json
"""

import argparse
import hashlib
import json
import re
import sys

CWE_TAG = re.compile(r"external/cwe/cwe-0*(\d+)", re.IGNORECASE)


def _build_rule_index(run):
    """ruleId -> metadata dict, from tool.driver.rules and tool.extensions[].rules."""
    index = {}
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + list(tool.get("extensions", []) or [])
    for comp in components:
        for rule in comp.get("rules", []) or []:
            rid = rule.get("id")
            if not rid:
                continue
            props = rule.get("properties", {}) or {}
            cwes = []
            for tag in props.get("tags", []) or []:
                m = CWE_TAG.search(tag)
                if m:
                    cwes.append("CWE-%03d" % int(m.group(1)))
            index[rid] = {
                "security_severity": props.get("security-severity"),
                "precision": props.get("precision"),
                "level": (rule.get("defaultConfiguration") or {}).get("level"),
                "cwes": cwes,
                "name": rule.get("name"),
                "short_description": ((rule.get("shortDescription") or {}).get("text")),
            }
    return index


def _loc_to_target(loc):
    """physicalLocation -> 'path:line' (line defaults to 1)."""
    phys = (loc or {}).get("physicalLocation", {}) or {}
    uri = ((phys.get("artifactLocation") or {}).get("uri")) or "<unknown>"
    line = ((phys.get("region") or {}).get("startLine")) or 1
    return "%s:%d" % (uri, int(line))


def _loc_message(loc):
    msg = (loc or {}).get("message", {}) or {}
    return (msg.get("text") or "").strip()


def _codeflow_steps(result):
    """Flatten the first codeFlow's threadFlow into ['path:line note', ...]."""
    steps = []
    flows = result.get("codeFlows") or []
    if not flows:
        return steps
    thread_flows = flows[0].get("threadFlows") or []
    if not thread_flows:
        return steps
    for tf_loc in thread_flows[0].get("locations") or []:
        loc = tf_loc.get("location", {}) or {}
        target = _loc_to_target(loc)
        note = _loc_message(loc)
        steps.append(("%s %s" % (target, note)).strip())
    return steps


def sarif_to_workunits(sarif, counter_start=1):
    """Parse a loaded SARIF dict into a list of work-unit dicts."""
    units = []
    n = counter_start
    for run in sarif.get("runs", []) or []:
        rule_index = _build_rule_index(run)
        category = ((run.get("automationDetails") or {}).get("id") or "").rstrip("/")
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "unknown-rule"
            meta = rule_index.get(rule_id, {})
            message = ((result.get("message") or {}).get("text") or "").strip()

            targets = [_loc_to_target(l) for l in result.get("locations") or []]
            if not targets:
                targets = ["<unknown>:1"]

            # related locations add context (e.g. "user-provided value" origin)
            related = [_loc_to_target(l) for l in result.get("relatedLocations") or []]

            steps = _codeflow_steps(result)

            fingerprint_src = json.dumps(
                [rule_id, targets, message], sort_keys=True
            ).encode()
            digest = hashlib.sha256(fingerprint_src).hexdigest()[:8]
            uid = "codeql-%04d-%s" % (n, digest)
            n += 1

            hints = {
                "rule": rule_id,
                "severity": meta.get("security_severity") or "",
                "level": result.get("level") or meta.get("level") or "",
                "precision": meta.get("precision") or "",
                "cwe": ",".join(meta.get("cwes") or []),
                "message": message,
            }
            if category:
                hints["category"] = category
            if related:
                hints["related_locations"] = related
            if steps:
                hints["codeflow_steps"] = steps

            units.append({
                "id": uid,
                "title": "%s @ %s" % (rule_id, targets[0]),
                "targets": targets,
                "hints": hints,
            })
    return units


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sarif", nargs="+", help="SARIF file(s), or '-' for stdin")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output work-unit JSON array (default: workunits.json)")
    ap.add_argument("--min-severity", type=float, default=None,
                    help="drop results with security-severity below this (unscored kept)")
    args = ap.parse_args(argv)

    units = []
    for path in args.sarif:
        if path == "-":
            sarif = json.load(sys.stdin)
        else:
            with open(path, "r", encoding="utf-8") as fh:
                sarif = json.load(fh)
        units.extend(sarif_to_workunits(sarif, counter_start=len(units) + 1))

    if args.min_severity is not None:
        def keep(u):
            sev = u["hints"].get("severity")
            try:
                return float(sev) >= args.min_severity
            except (TypeError, ValueError):
                return True
        units = [u for u in units if keep(u)]

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")

    with_flows = sum(1 for u in units if u["hints"].get("codeflow_steps"))
    print("wrote %d work units (%d with code flows) -> %s"
          % (len(units), with_flows, args.output), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
