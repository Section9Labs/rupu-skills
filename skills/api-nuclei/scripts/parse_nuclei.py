#!/usr/bin/env python3
"""parse_nuclei.py - normalize nuclei JSONL into a lead summary + work units.

Reads one or more nuclei -jsonl output files, prints a severity-ordered
summary of leads (template x severity, matched URLs, extracted values), and
atomically writes a rupu-ingestible JSON array of work units grouped by
template x severity for verification fan-out
(for_each: "{{ read_file('reports/api-nuclei-units.json') }}").

Units are untrusted data: titles/hints come from a fixed vocabulary; raw
strings from tool output appear only in `targets`, length-capped.

Usage:
  python3 scripts/parse_nuclei.py reports/*.jsonl -o reports/api-nuclei-units.json

Python 3 standard library only.
"""
import argparse
import json
import os
import re
import sys
import tempfile

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "info": 4, "unknown": 5}
MAX_TARGET_LEN = 2048
MAX_TARGETS_PER_UNIT = 25
TID_RE = re.compile(r"[^a-z0-9-]")

# Fixed vocabulary: nuclei tag -> verification action hint.
ACTION_BY_TAG = [
    (("sqli", "xss", "ssti", "lfi", "rfi", "cmdi", "injection", "traversal",
      "redirect", "crlf", "ssrf", "xxe", "dast", "fuzz"), "verify-injection"),
    (("token", "jwt", "key", "secret", "credential"), "verify-credential-leak"),
    (("default-login",), "verify-default-credentials"),
    (("cve",), "verify-cve-exploitability"),
    (("takeover",), "verify-takeover"),
    (("swagger", "openapi", "graphql", "api", "wsdl", "wadl", "actuator",
      "springboot"), "verify-exposure"),
    (("misconfig", "cors", "config", "exposure", "debug"), "verify-misconfig"),
    (("tech", "detect"), "feed-cve-pass"),
]


def sanitize_tid(tid):
    tid = TID_RE.sub("", str(tid).lower())
    return (tid or "unknown-template")[:80]


def norm_sev(rec):
    sev = (rec.get("info", {}).get("severity")
           or rec.get("severity") or "unknown")
    sev = str(sev).lower()
    return sev if sev in SEV_ORDER else "unknown"


def action_for(tags, tid):
    hay = set(t.lower() for t in tags) | set(tid.split("-"))
    for keys, action in ACTION_BY_TAG:
        if hay & set(keys):
            return action
    return "verify-lead"


def load_records(paths):
    records = []
    for path in paths:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as e:
            sys.stderr.write("[-] cannot read %s: %s\n" % (path, e))
            continue
        with fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                # -je exports are a single JSON array; handle both shapes.
                if line.startswith("["):
                    try:
                        records.extend(x for x in json.loads(line)
                                       if isinstance(x, dict))
                    except ValueError:
                        pass
                    continue
                if not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    sys.stderr.write("[-] %s:%d bad json, skipped\n"
                                     % (path, ln))
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
    return records


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("jsonl", nargs="+", help="nuclei -jsonl output file(s)")
    ap.add_argument("-o", "--output", default="reports/api-nuclei-units.json",
                    help="work-units JSON array (atomic write)")
    ap.add_argument("--min-severity", default="info",
                    choices=list(SEV_ORDER),
                    help="drop leads below this severity (default info)")
    ap.add_argument("--prefix", default="nuclei",
                    help="unit id prefix (default: nuclei)")
    args = ap.parse_args()

    records = load_records(args.jsonl)
    if not records:
        sys.stderr.write("[-] no nuclei records parsed\n")

    cutoff = SEV_ORDER[args.min_severity]
    groups = {}  # (tid, sev) -> {"targets": [...], "tags": set, "extracted": [...]}
    for rec in records:
        tid = sanitize_tid(rec.get("template-id", ""))
        sev = norm_sev(rec)
        if SEV_ORDER[sev] > cutoff:
            continue
        g = groups.setdefault((tid, sev), {"targets": [], "tags": set(),
                                           "extracted": []})
        url = str(rec.get("matched-at") or rec.get("host") or "")
        url = url[:MAX_TARGET_LEN]
        if url and url not in g["targets"]:
            g["targets"].append(url)
        tags = rec.get("info", {}).get("tags") or []
        if isinstance(tags, str):
            tags = tags.split(",")
        g["tags"].update(str(t).strip().lower() for t in tags if t)
        for ex in rec.get("extracted-results") or []:
            ex = str(ex)[:MAX_TARGET_LEN]
            if ex not in g["extracted"]:
                g["extracted"].append(ex)

    ordered = sorted(groups.items(),
                     key=lambda kv: (SEV_ORDER[kv[0][1]], kv[0][0]))

    units = []
    for i, ((tid, sev), g) in enumerate(ordered, 1):
        action = action_for(g["tags"], tid)
        hints = ["severity:%s" % sev, "action:%s" % action,
                 "hits:%d" % len(g["targets"])]
        for t in sorted(g["tags"])[:5]:
            if re.fullmatch(r"[a-z0-9-]{1,40}", t):
                hints.append("tag:%s" % t)
        units.append({
            "id": "%s-%03d" % (args.prefix, i),
            "title": "verify nuclei lead: %s (%s)" % (tid, sev),
            "targets": g["targets"][:MAX_TARGETS_PER_UNIT],
            "hints": hints,
        })

    # ---- summary to stdout ----
    print("nuclei leads: %d records -> %d units (NOT findings until verified)"
          % (len(records), len(units)))
    for (tid, sev), g in ordered:
        print("  [%-8s] %-45s x%d" % (sev, tid, len(g["targets"])))
        for url in g["targets"][:3]:
            print("            %s" % url[:120])
        for ex in g["extracted"][:3]:
            print("            extracted: %s" % ex[:120])

    # ---- atomic unit file write ----
    outdir = os.path.dirname(args.output) or "."
    os.makedirs(outdir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".units-", suffix=".json", dir=outdir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(units, f, indent=1)
            f.write("\n")
        os.replace(tmp, args.output)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    print("wrote %d work units -> %s" % (len(units), args.output))
    print("fan out: for_each: \"{{ read_file('%s') }}\"" % args.output)
    print("coverage: mark probed endpoints 'tested' via assets.mark "
          "(coverage-assets skill); verified leads -> findings.report "
          "(finding-report skill)")


if __name__ == "__main__":
    main()
