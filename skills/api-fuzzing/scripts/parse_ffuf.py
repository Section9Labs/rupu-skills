#!/usr/bin/env python3
"""parse_ffuf.py — normalize ffuf -of json output into hits + rupu work units.

Reads one or more ffuf JSON output files (shell glob or quoted glob pattern),
clusters each run's results by (status, size), flags outliers, and writes:

  --hits  reports/api-fuzzing-hits.json   normalized hit records (JSON array)
  -o      reports/api-fuzzing-units.json  work units [{"id","title","targets","hints"}]
          written atomically (temp file + rename) for rupu for_each / dispatch.

Optional --manifest reports/ffuf/manifest.json (from spec_to_ffuf.py) maps each
output file back to its task kind for sharper titles/hints.

Usage:
  python3 scripts/parse_ffuf.py 'reports/ffuf/out/*.json' \
      --manifest reports/ffuf/manifest.json \
      --hits reports/api-fuzzing-hits.json -o reports/api-fuzzing-units.json

Only python3 stdlib.
"""

import argparse
import glob as globmod
import json
import os
import sys
import tempfile

TARGET_CAP = 200          # max chars per target string (units are untrusted data)
MAX_TARGETS_PER_UNIT = 20

# Fixed vocabulary — raw tool output never reaches titles or hints.
TITLES = {
    "path-id": "ffuf hit: id enumeration candidate",
    "path-segment": "ffuf hit: undocumented route",
    "param-name": "ffuf hit: hidden parameter candidate",
    "param-value": "ffuf anomaly: parameter value outlier",
    "body-field": "ffuf anomaly: body field outlier",
    "method": "ffuf hit: verb tampering candidate",
    "generic": "ffuf anomaly: response outlier",
    "server-error": "ffuf anomaly: server error",
    "timing": "ffuf anomaly: response time outlier",
}
HINTS = {
    "path-id": ["probe-authorization", "verify-second-identity"],
    "path-segment": ["new-route", "mark-mapped", "respider"],
    "param-name": ["probe-param", "probe-injection"],
    "param-value": ["probe-injection"],
    "body-field": ["probe-injection", "check-mass-assignment"],
    "method": ["verify-verb-tampering", "probe-authorization"],
    "generic": ["manual-triage"],
    "server-error": ["probe-injection", "inspect-stacktrace"],
    "timing": ["probe-injection", "time-based-suspect"],
}


def atomic_write(path, data):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def cap(s):
    s = str(s).replace("\n", " ").replace("\r", " ")
    return s[:TARGET_CAP]


def load_manifest(path):
    """Map abs output path -> task dict."""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tasks = json.load(fh)
    except (OSError, ValueError) as e:
        sys.stderr.write("warn: cannot read manifest %s: %s\n" % (path, e))
        return {}
    out = {}
    for t in tasks if isinstance(tasks, list) else []:
        if isinstance(t, dict) and t.get("output"):
            out[os.path.abspath(t["output"])] = t
    return out


def parse_file(path, task):
    """Yield normalized hit dicts for one ffuf json output file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        sys.stderr.write("warn: skip %s: %s\n" % (path, e))
        return []
    results = doc.get("results") or []
    if not results:
        return []
    config = doc.get("config") or {}
    method = (task or {}).get("method") or config.get("method") or "GET"
    kind = (task or {}).get("kind") or "generic"

    # Cluster by (status, length). Dominant cluster = noise; minority = signal.
    clusters = {}
    for r in results:
        key = (r.get("status"), r.get("length"))
        clusters.setdefault(key, []).append(r)
    total = len(results)
    # minority threshold: small absolute count or <5% of the run
    thresh = max(2, int(total * 0.05)) if total >= 20 else max(1, total // 4)

    durations = sorted(r.get("duration", 0) for r in results)
    med = durations[len(durations) // 2] if durations else 0

    hits = []
    for key, members in sorted(clusters.items(), key=lambda kv: str(kv[0])):
        status, length = key
        minority = len(members) <= thresh and len(clusters) > 1
        for r in members:
            reasons = []
            if isinstance(status, int) and status >= 500:
                reasons.append("server-error")
            if minority:
                reasons.append("status-size-outlier")
            dur = r.get("duration", 0)
            if med and dur > max(3 * med, med + 2_000_000_000):  # ffuf duration is ns
                reasons.append("timing")
            if not reasons:
                continue
            hits.append({
                "source": path,
                "task": (task or {}).get("task_id"),
                "kind": kind,
                "op": (task or {}).get("op_id"),
                "method": method,
                "url": r.get("url", ""),
                "input": r.get("input", {}),
                "status": status,
                "length": length,
                "words": r.get("words"),
                "lines": r.get("lines"),
                "duration_ns": dur,
                "resultfile": r.get("resultfile", ""),
                "reasons": reasons,
                "cluster_size": len(members),
                "run_total": total,
            })
    return hits


def hit_title_kind(hit):
    if "server-error" in hit["reasons"]:
        return "server-error"
    if "timing" in hit["reasons"] and "status-size-outlier" not in hit["reasons"]:
        return "timing"
    return hit["kind"] if hit["kind"] in TITLES else "generic"


def build_units(hits):
    """Group hits per (title-kind, method, source-task) into work units."""
    groups = {}
    for h in hits:
        tk = hit_title_kind(h)
        key = (tk, h["method"], h.get("task") or h["source"])
        groups.setdefault(key, []).append(h)

    units = []
    n = 0
    for (tk, method, _), members in sorted(groups.items(), key=lambda kv: str(kv[0])):
        n += 1
        targets = []
        for h in members[:MAX_TARGETS_PER_UNIT]:
            targets.append(cap("%s %s" % (method, h["url"])))
            inp = " ".join("%s=%s" % (k, v) for k, v in sorted(h["input"].items()))
            if inp:
                targets.append(cap("input " + inp))
            targets.append(cap("status %s len %s words %s (cluster %d/%d)" % (
                h["status"], h["length"], h["words"],
                h["cluster_size"], h["run_total"])))
            if h.get("resultfile"):
                targets.append(cap("evidence " + h["resultfile"]))
        base_kind = members[0]["kind"] if members[0]["kind"] in HINTS else "generic"
        hints = list(dict.fromkeys(HINTS[tk] + HINTS.get(base_kind, [])))
        units.append({
            "id": "afz-%03d" % n,
            "title": TITLES[tk],
            "targets": targets[: MAX_TARGETS_PER_UNIT * 4],
            "hints": hints,
        })
    return units


def main():
    ap = argparse.ArgumentParser(description="ffuf json output -> hits + work units")
    ap.add_argument("inputs", nargs="+",
                    help="ffuf -of json output files or glob patterns")
    ap.add_argument("--manifest", default=None,
                    help="spec_to_ffuf.py manifest.json for task kind mapping")
    ap.add_argument("--hits", default="reports/api-fuzzing-hits.json",
                    help="normalized hit list output")
    ap.add_argument("-o", "--units", default="reports/api-fuzzing-units.json",
                    help="work-unit JSON array output (atomic)")
    args = ap.parse_args()

    files = []
    for pat in args.inputs:
        matched = globmod.glob(pat)
        files.extend(matched if matched else ([pat] if os.path.exists(pat) else []))
    files = sorted(set(os.path.abspath(f) for f in files))
    if not files:
        sys.stderr.write("error: no input files matched\n")
        sys.exit(1)

    manifest = load_manifest(args.manifest)
    all_hits = []
    for f in files:
        all_hits.extend(parse_file(f, manifest.get(f)))

    atomic_write(args.hits, json.dumps(all_hits, indent=2) + "\n")
    units = build_units(all_hits)
    atomic_write(args.units, json.dumps(units, indent=2) + "\n")

    sys.stderr.write("parsed %d files: %d hits -> %d work units\n"
                     % (len(files), len(all_hits), len(units)))
    print(args.units)


if __name__ == "__main__":
    main()
