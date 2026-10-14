#!/usr/bin/env python3
"""fsb_to_workunits.py - normalize SpotBugs/findsecbugs output into work units.

Parses SpotBugs SARIF 2.1.0 and/or native SpotBugs XML (BugCollection) and
writes a CLEAN top-level JSON array of work units:

    [{"id": "...", "title": "...", "targets": ["path:line", ...],
      "hints": {"pattern": "...", "rank": "...", "priority": "...",
                "cwe": "...", "severity": "...", ...}}, ...]

The output file is directly consumable by a rupu workflow `for_each:` (it
JSON-parses any value starting with '[') or by a lead agent `dispatch`
fan-out.

Usage:
    python3 scripts/fsb_to_workunits.py fsb.sarif fsb.xml -o workunits.json \
        [--repo-root .] [--min-rank 20] [--min-priority 3] [--security-only]

Multiple input files are merged and deduplicated on (pattern, path, line);
XML entries enrich SARIF entries with rank/priority/CWE where both exist.
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

RANK_SEVERITY = ((4, "critical"), (9, "high"), (14, "medium"), (20, "low"))
PRIORITY_NAME = {1: "High", 2: "Medium", 3: "Low"}
SARIF_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low",
                        "none": "info"}


def severity_from(rank, level):
    if rank is not None:
        for ceiling, sev in RANK_SEVERITY:
            if rank <= ceiling:
                return sev
    return SARIF_LEVEL_SEVERITY.get(level or "", "medium")


def slug(text, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:maxlen] or "finding"


class SourceIndex:
    """Map bytecode sourcepaths (com/example/Foo.java) to real repo paths."""

    def __init__(self, root):
        self.root = root
        self.by_name = {}
        if not root:
            return
        skip = {".git", "node_modules", "target", "build", "out", ".gradle"}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                if fn.endswith((".java", ".kt", ".kts", ".scala", ".groovy",
                                ".jsp")):
                    rel = os.path.relpath(os.path.join(dirpath, fn), root)
                    self.by_name.setdefault(fn, []).append(
                        rel.replace(os.sep, "/"))

    def resolve(self, sourcepath):
        if not sourcepath:
            return None
        sp = sourcepath.replace("\\", "/").lstrip("/")
        if self.root and os.path.exists(os.path.join(self.root, sp)):
            return sp
        candidates = self.by_name.get(sp.rsplit("/", 1)[-1], [])
        # prefer a candidate whose tail matches the package path
        for cand in candidates:
            if cand.endswith("/" + sp) or cand == sp:
                return cand
        if len(candidates) == 1:
            return candidates[0]
        return sp


def parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------

def parse_sarif(path, index):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    records = []
    for run in doc.get("runs", []):
        rules = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for ext in [driver] + ((run.get("tool") or {}).get("extensions") or []):
            for rule in ext.get("rules") or []:
                rules[rule.get("id")] = rule
        for res in run.get("results", []):
            rule_id = res.get("ruleId") or "UNKNOWN"
            rule = rules.get(rule_id, {})
            props = dict(rule.get("properties") or {})
            props.update(res.get("properties") or {})
            msg = ((res.get("message") or {}).get("text") or "").strip()
            rank = parse_int(props.get("rank"))
            if rank is None:
                # SARIF numeric rank 1..100; SpotBugs maps bug rank onto it
                r = res.get("rank")
                if isinstance(r, (int, float)) and 1 <= r <= 20:
                    rank = int(r)
            priority = parse_int(props.get("priority"))
            cwe = None
            for tag in props.get("tags") or []:
                m = re.search(r"(?:CWE|cwe)[-:]?(\d+)", str(tag))
                if m:
                    cwe = "CWE-" + m.group(1)
            targets = []
            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
                line = (phys.get("region") or {}).get("startLine")
                resolved = index.resolve(uri) or uri
                if resolved:
                    targets.append("%s:%s" % (resolved, line if line else 0))
                logical = loc.get("logicalLocations") or []
                for ll in logical:
                    fq = ll.get("fullyQualifiedName")
                    if fq and "class" not in props:
                        props["logical"] = fq
            records.append({
                "pattern": rule_id,
                "message": msg,
                "rank": rank,
                "priority": priority,
                "cwe": cwe,
                "level": res.get("level"),
                "targets": targets,
                "class": props.get("logical"),
                "method": None,
                "category": None,
            })
    return records


# --------------------------------------------------------------------------
# SpotBugs native XML (BugCollection)
# --------------------------------------------------------------------------

def parse_spotbugs_xml(path, index):
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "BugCollection":
        raise ValueError("%s: not a SpotBugs BugCollection XML" % path)
    records = []
    for bug in root.iter("BugInstance"):
        pattern = bug.get("type") or "UNKNOWN"
        priority = parse_int(bug.get("priority"))
        rank = parse_int(bug.get("rank"))
        cweid = parse_int(bug.get("cweid"))
        cwe = ("CWE-%d" % cweid) if cweid else None
        category = bug.get("category")
        lm = bug.find("LongMessage")
        sm = bug.find("ShortMessage")
        message = ((lm is not None and lm.text) or
                   (sm is not None and sm.text) or "").strip()
        cls = bug.find("Class")
        classname = cls.get("classname") if cls is not None else None
        meth = bug.find("Method")
        method = meth.get("name") if meth is not None else None
        # pick the primary SourceLine (direct child preferred)
        sline = None
        for cand in bug.findall("SourceLine"):
            if cand.get("primary") == "true":
                sline = cand
                break
        if sline is None:
            sline = (bug.find("SourceLine")
                     or (meth.find("SourceLine") if meth is not None else None)
                     or (cls.find("SourceLine") if cls is not None else None))
        targets = []
        if sline is not None:
            sp = sline.get("sourcepath") or sline.get("sourcefile") or ""
            start = sline.get("start") or "0"
            resolved = index.resolve(sp) or sp
            if resolved:
                targets.append("%s:%s" % (resolved, start))
        records.append({
            "pattern": pattern,
            "message": message,
            "rank": rank,
            "priority": priority,
            "cwe": cwe,
            "level": None,
            "targets": targets,
            "class": classname,
            "method": method,
            "category": category,
        })
    return records


# --------------------------------------------------------------------------
# merge / dedup / emit
# --------------------------------------------------------------------------

def merge(records):
    merged = {}
    order = []
    for rec in records:
        key = (rec["pattern"], rec["targets"][0] if rec["targets"] else
               (rec.get("class"), rec.get("method")))
        if key not in merged:
            merged[key] = rec
            order.append(key)
        else:
            cur = merged[key]
            for field in ("rank", "priority", "cwe", "class", "method",
                          "message", "category", "level"):
                if cur.get(field) in (None, "") and rec.get(field):
                    cur[field] = rec[field]
            for t in rec["targets"]:
                if t not in cur["targets"]:
                    cur["targets"].append(t)
    return [merged[k] for k in order]


def to_workunits(records):
    records.sort(key=lambda r: (r["rank"] if r["rank"] is not None else 99,
                                r["priority"] if r["priority"] is not None
                                else 9))
    units = []
    for i, rec in enumerate(records, 1):
        where = rec["targets"][0] if rec["targets"] else "unknown:0"
        locus = rec.get("class") or where.split(":")[0]
        if rec.get("method"):
            locus += "." + rec["method"]
        title = "%s in %s (%s)" % (rec["pattern"], locus, where)
        hints = {
            "pattern": rec["pattern"],
            "severity": severity_from(rec["rank"], rec.get("level")),
        }
        if rec["rank"] is not None:
            hints["rank"] = str(rec["rank"])
        if rec["priority"] is not None:
            hints["priority"] = str(rec["priority"])
            hints["confidence"] = PRIORITY_NAME.get(rec["priority"],
                                                    str(rec["priority"]))
        if rec.get("cwe"):
            hints["cwe"] = rec["cwe"]
        if rec.get("category"):
            hints["category"] = rec["category"]
        if rec.get("class"):
            hints["class"] = rec["class"]
        if rec.get("method"):
            hints["method"] = rec["method"]
        if rec.get("message"):
            hints["message"] = rec["message"][:500]
        units.append({
            "id": "fsb-%04d-%s" % (i, slug(rec["pattern"])),
            "title": title,
            "targets": rec["targets"] or [where],
            "hints": hints,
        })
    return units


def sniff(path):
    with open(path, "rb") as fh:
        head = fh.read(512).lstrip()
    if head.startswith(b"{"):
        return "sarif"
    if head.startswith(b"<"):
        return "xml"
    raise ValueError("%s: cannot determine format (want SARIF JSON or "
                     "SpotBugs XML)" % path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+",
                    help="SpotBugs SARIF and/or XML files (merged)")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output JSON array file (default workunits.json)")
    ap.add_argument("--repo-root", default=None,
                    help="repo root used to resolve sourcepaths to real files")
    ap.add_argument("--min-rank", type=int, default=20,
                    help="drop results ranked worse than N (default 20=keep all)")
    ap.add_argument("--min-priority", type=int, default=3,
                    help="drop results with confidence priority worse than N "
                         "(default 3=keep all)")
    ap.add_argument("--security-only", action="store_true",
                    help="keep only category SECURITY (XML inputs carry "
                         "category)")
    ap.add_argument("--pattern", action="append", default=[],
                    help="keep only these bug pattern types (repeatable)")
    args = ap.parse_args(argv)

    index = SourceIndex(args.repo_root)
    records = []
    for path in args.inputs:
        fmt = sniff(path)
        parsed = (parse_sarif if fmt == "sarif" else parse_spotbugs_xml)(
            path, index)
        print("[fsb] %s: %d results (%s)" % (path, len(parsed), fmt),
              file=sys.stderr)
        records.extend(parsed)

    records = merge(records)
    if args.security_only:
        records = [r for r in records
                   if (r.get("category") or "SECURITY") == "SECURITY"]
    if args.pattern:
        keep = set(args.pattern)
        records = [r for r in records if r["pattern"] in keep]
    records = [r for r in records
               if (r["rank"] is None or r["rank"] <= args.min_rank)
               and (r["priority"] is None or r["priority"] <= args.min_priority)]

    units = to_workunits(records)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    print("[fsb] wrote %d work units -> %s" % (len(units), args.output),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
