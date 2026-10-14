#!/usr/bin/env python3
"""Convert njsscan output (native JSON and/or SARIF 2.1.0) into rupu work units.

Output is a CLEAN top-level JSON array:
    [{"id": "...", "title": "...", "targets": ["path:line", ...],
      "hints": {"rule": "...", "severity": "...", "cwe": "...", "owasp": "...", ...}}, ...]

Usage:
    python3 scripts/njsscan_to_workunits.py njsscan.json [njsscan.sarif ...] -o workunits.json
    python3 scripts/njsscan_to_workunits.py eslint.sarif -o eslint-wu.json

Input format is auto-detected per file (SARIF has "runs"; njsscan native JSON
has rule-id maps under keys like "nodejs"/"templates"). Units are deduped on
(tool, rule, file); targets within a unit are deduped and sorted by line.
"""

import argparse
import hashlib
import json
import re
import sys

CWE_RE = re.compile(r"(CWE[-_ ]?\d+)", re.IGNORECASE)

# njsscan native JSON: top-level keys that hold rule-id -> result maps.
# Different versions have used slightly different section names.
NJSSCAN_SECTIONS = ("nodejs", "templates", "nodejs_security", "template", "regex")


def norm_cwe(value):
    if not value:
        return ""
    m = CWE_RE.search(str(value))
    if not m:
        return str(value)
    return m.group(1).upper().replace("_", "-").replace(" ", "-")


def unit_id(*parts):
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:8]
    return f"njsscan-{h}"


def looks_like_sarif(doc):
    return isinstance(doc, dict) and isinstance(doc.get("runs"), list)


def looks_like_njsscan(doc):
    if not isinstance(doc, dict):
        return False
    for key in NJSSCAN_SECTIONS:
        if isinstance(doc.get(key), dict):
            return True
    return False


# ---------------------------------------------------------------- njsscan JSON

def parse_njsscan_json(doc):
    """Yield (rule, file_path, lines, meta) tuples from njsscan native JSON."""
    for section in NJSSCAN_SECTIONS:
        rules = doc.get(section)
        if not isinstance(rules, dict):
            continue
        for rule_id, body in rules.items():
            if not isinstance(body, dict):
                continue
            meta = body.get("metadata") or {}
            per_file = {}
            for hit in body.get("files") or []:
                if not isinstance(hit, dict):
                    continue
                path = hit.get("file_path") or hit.get("path") or ""
                if not path:
                    continue
                lines = hit.get("match_lines") or []
                if isinstance(lines, int):
                    lines = [lines]
                # match_lines is [start, end]; the start line is the anchor.
                line = int(lines[0]) if lines else 0
                per_file.setdefault(path, set()).add(line)
            for path, lineset in per_file.items():
                yield rule_id, path, sorted(lineset), {
                    "severity": str(meta.get("severity", "")).upper(),
                    "cwe": norm_cwe(meta.get("cwe", "")),
                    "owasp": meta.get("owasp", "") or meta.get("owasp-web", ""),
                    "description": (meta.get("description") or "").strip(),
                    "engine": section,
                }
    errors = doc.get("errors") or []
    if errors:
        print(f"[!] njsscan reported {len(errors)} scan error(s) — "
              f"those files were NOT analyzed (mark the gap with assets.mark)",
              file=sys.stderr)


# --------------------------------------------------------------------- SARIF

LEVEL_TO_SEV = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}


def sarif_rule_index(run):
    idx = {}
    driver = ((run.get("tool") or {}).get("driver")) or {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id")
        if not rid:
            continue
        tags = ((rule.get("properties") or {}).get("tags")) or []
        cwe = ""
        owasp = ""
        for tag in tags:
            t = str(tag)
            if not cwe and CWE_RE.search(t):
                cwe = norm_cwe(t)
            if not owasp and "owasp" in t.lower():
                owasp = t
        desc = ((rule.get("fullDescription") or {}).get("text")
                or (rule.get("shortDescription") or {}).get("text") or "")
        props = rule.get("properties") or {}
        sev = str(props.get("problem.severity") or props.get("severity") or "").upper()
        idx[rid] = {"cwe": cwe or norm_cwe(props.get("cwe", "")),
                    "owasp": owasp or props.get("owasp", ""),
                    "description": desc.strip(), "severity": sev}
    return idx


def parse_sarif(doc):
    """Yield (rule, file_path, lines, meta) tuples from a SARIF 2.1.0 log."""
    for run in doc.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        tool = driver.get("name") or "sarif"
        rules_meta = sarif_rule_index(run)
        per_key = {}
        for res in run.get("results") or []:
            rule_id = res.get("ruleId") or "unknown-rule"
            level = LEVEL_TO_SEV.get(str(res.get("level", "")).lower(), "")
            msg = ((res.get("message") or {}).get("text") or "").strip()
            for loc in res.get("locations") or [{}]:
                phys = (loc.get("physicalLocation") or {})
                uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
                uri = uri.replace("file://", "").lstrip("/") if uri.startswith("file://") else uri
                if not uri:
                    continue
                line = int(((phys.get("region") or {}).get("startLine")) or 0)
                key = (rule_id, uri)
                entry = per_key.setdefault(key, {"lines": set(), "level": level, "msg": msg})
                entry["lines"].add(line)
                if level == "ERROR":
                    entry["level"] = "ERROR"
        for (rule_id, uri), entry in per_key.items():
            rm = rules_meta.get(rule_id, {})
            yield rule_id, uri, sorted(entry["lines"]), {
                "severity": rm.get("severity") or entry["level"] or "WARNING",
                "cwe": rm.get("cwe", ""),
                "owasp": rm.get("owasp", ""),
                "description": rm.get("description") or entry["msg"],
                "engine": tool,
            }


# --------------------------------------------------------------------- main

def build_units(records, tool_default="njsscan"):
    units = {}
    for rule_id, path, lines, meta in records:
        key = (meta.get("engine", tool_default), rule_id, path)
        targets = [f"{path}:{ln}" for ln in lines if ln] or [f"{path}:0"]
        if key in units:
            merged = sorted(set(units[key]["targets"]) | set(targets),
                            key=lambda t: (t.rsplit(":", 1)[0], int(t.rsplit(":", 1)[1])))
            units[key]["targets"] = merged
            continue
        hints = {"rule": rule_id,
                 "severity": meta.get("severity") or "WARNING",
                 "cwe": meta.get("cwe", ""),
                 "owasp": meta.get("owasp", ""),
                 "tool": meta.get("engine", tool_default)}
        desc = meta.get("description", "")
        if desc:
            hints["description"] = desc[:500]
        units[key] = {
            "id": unit_id(*key),
            "title": f"{rule_id} in {path}",
            "targets": targets,
            "hints": hints,
        }
    sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    return sorted(units.values(),
                  key=lambda u: (sev_rank.get(u["hints"]["severity"], 3),
                                 u["hints"]["rule"], u["targets"][0]))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="njsscan JSON and/or SARIF files")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output file for the work-unit JSON array (default: workunits.json)")
    args = ap.parse_args(argv)

    records = []
    for path in args.inputs:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] cannot read {path}: {exc}", file=sys.stderr)
            continue
        if looks_like_sarif(doc):
            n = len(records)
            records.extend(parse_sarif(doc))
            print(f"[+] {path}: SARIF, {len(records) - n} (rule,file) groups", file=sys.stderr)
        elif looks_like_njsscan(doc):
            n = len(records)
            records.extend(parse_njsscan_json(doc))
            print(f"[+] {path}: njsscan JSON, {len(records) - n} (rule,file) groups", file=sys.stderr)
        else:
            print(f"[!] {path}: unrecognized format (not SARIF, not njsscan JSON)", file=sys.stderr)

    units = build_units(records)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    print(f"[+] wrote {len(units)} work units -> {args.output}", file=sys.stderr)
    print(f"[>] next: load the `work-units` skill to split/dispatch "
          f"{args.output}; route SARIF inputs to `sarif-triage`; file verified "
          f"issues via the `finding-report` skill.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
