#!/usr/bin/env python3
"""dedupe_findings.py - stage 2 of the sarif-triage pipeline.

Reads one or more normalized findings JSON lists (output of
normalize_sarif.py), merges them, deduplicates within and across tools, and
annotates each surviving record with corroboration, noise classification,
confidence, and a priority score.

Dedup strategy:
  pass 1: exact fingerprint match (partialFingerprints-derived or content hash)
  pass 2: same (file, line) bucket; merge records whose CWE agrees (or where
          one side has no CWE) when they come from DIFFERENT tools, or from
          the same tool with the same rule id. Cross-tool corroboration is
          recorded in `tools` and raises confidence.

Usage:
  python3 scripts/dedupe_findings.py normalized-semgrep.json normalized-codeql.json
  python3 scripts/normalize_sarif.py *.sarif | python3 scripts/dedupe_findings.py

Composable: pipe the output into to_workunits.py.
"""
import argparse
import json
import re
import sys

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_WEIGHT = {"info": 5, "low": 15, "medium": 40, "high": 70, "critical": 100}

# Paths that usually mean "not production code" -> likely-noise class
NOISE_RE = re.compile(
    r"(^|/)(tests?|spec|specs|fixtures?|testdata|mocks?|examples?|samples?|"
    r"docs?|vendor|node_modules|third[_-]?party|dist|build|target|out|"
    r"\.venv|venv|migrations)(/|$)"
    r"|\.min\.(js|css)$"
    r"|(^|/)[^/]*_test\.(go|py|rb|js|ts)$"
    r"|(^|/)test_[^/]*\.py$"
    r"|\.generated\.|_pb2\.py$|\.pb\.go$",
    re.I)


def load_all(paths):
    recs = []
    for p in paths:
        if p == "-":
            doc = json.load(sys.stdin)
        else:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
        if not isinstance(doc, list):
            raise SystemExit("expected a JSON list of normalized findings: %s" % p)
        recs.extend(doc)
    return recs


def to_merged(rec):
    m = dict(rec)
    tool = m.get("tool", "unknown")
    m["tools"] = [tool]
    m["rule_ids"] = {tool: m.get("rule_id", "")}
    m["messages"] = {tool: m.get("message", "")}
    m["fingerprints"] = [m.get("fingerprint", "")]
    m.pop("tool", None)
    return m


def compatible(a, b):
    """Can two merged records at the same file:line be collapsed?"""
    if a.get("cwe") and b.get("cwe") and a["cwe"] != b["cwe"]:
        return False
    if set(a["tools"]) & set(b["tools"]):
        # same tool twice at the same line: only collapse identical rules
        return a.get("rule_id") == b.get("rule_id")
    return True


def merge(a, b):
    a["tools"] = sorted(set(a["tools"]) | set(b["tools"]))
    a["rule_ids"].update(b["rule_ids"])
    a["messages"].update(b["messages"])
    a["fingerprints"] = sorted(set(a["fingerprints"]) | set(b["fingerprints"]))
    if SEV_RANK.get(b["severity"], 0) > SEV_RANK.get(a["severity"], 0):
        a["severity"] = b["severity"]
        a["title"] = b.get("title") or a.get("title")
        a["rule_id"] = b.get("rule_id") or a.get("rule_id")
        a["message"] = b.get("message") or a.get("message")
    a["cwe"] = a.get("cwe") or b.get("cwe", "")
    if len(b.get("code_flow") or []) > len(a.get("code_flow") or []):
        a["code_flow"] = b["code_flow"]
    return a


def dedupe(records):
    # pass 1: exact fingerprint
    by_fp = {}
    order = []
    for rec in records:
        fp = rec.get("fingerprint", "")
        key = (rec.get("tool", ""), fp) if fp else id(rec)
        if fp and key in by_fp:
            merge(by_fp[key], to_merged(rec))
        else:
            m = to_merged(rec)
            by_fp[key] = m
            order.append(m)

    # pass 2: cross-tool collapse at (file, line)
    buckets = {}
    for m in order:
        buckets.setdefault((m.get("file", "").lower(), m.get("line", 0)),
                           []).append(m)
    final = []
    for _, group in sorted(buckets.items()):
        kept = []
        for m in group:
            for k in kept:
                if compatible(k, m):
                    merge(k, m)
                    break
            else:
                kept.append(m)
        final.extend(kept)
    return final


def score(m):
    m["corroboration"] = len(m["tools"])
    m["noise"] = bool(NOISE_RE.search(m.get("file", "")))
    s = SEV_WEIGHT.get(m["severity"], 40) * (1 + 0.4 * (m["corroboration"] - 1))
    if m.get("code_flow"):
        s += 10
    if str(m.get("tool_confidence", "")).lower() in ("high",):
        s += 5
    if m["noise"]:
        s *= 0.3
    m["priority"] = round(s, 1)
    if m["noise"] or m["severity"] == "info":
        m["confidence"] = "low"
    elif m["corroboration"] >= 2 or m.get("code_flow"):
        m["confidence"] = "high"
    else:
        m["confidence"] = "medium"
    # keep a single primary fingerprint for downstream ids
    m["fingerprint"] = (m.get("fingerprints") or [""])[0] or m.get("fingerprint", "")
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", default=["-"],
                    help="normalized findings JSON files ('-' or none = stdin)")
    ap.add_argument("--min-severity", default="info", choices=sorted(SEV_RANK),
                    help="drop merged records below this severity")
    ap.add_argument("--drop-noise", action="store_true",
                    help="drop records in test/vendor/generated paths")
    ap.add_argument("-o", "--output", help="write JSON list here (default stdout)")
    args = ap.parse_args()

    records = load_all(args.inputs or ["-"])
    merged = [score(m) for m in dedupe(records)]

    floor = SEV_RANK[args.min_severity]
    merged = [m for m in merged if SEV_RANK.get(m["severity"], 2) >= floor]
    if args.drop_noise:
        merged = [m for m in merged if not m["noise"]]
    merged.sort(key=lambda m: (-m["priority"], -SEV_RANK.get(m["severity"], 0),
                               m.get("file", ""), m.get("line", 0)))

    text = json.dumps(merged, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    corro = sum(1 for m in merged if m["corroboration"] >= 2)
    print("dedupe_findings: %d raw -> %d unique (%d corroborated by 2+ tools)"
          % (len(records), len(merged), corro), file=sys.stderr)


if __name__ == "__main__":
    main()
