#!/usr/bin/env python3
"""Convert trufflehog --json output (JSONL: ONE JSON object per line) into a
clean JSON array of work units for rupu `for_each:` / lead-agent `dispatch`.

Usage:
    python3 scripts/trufflehog_to_workunits.py trufflehog.jsonl [more.jsonl ...] -o workunits.json
    trufflehog git file:///tmp/app.git --json | python3 scripts/trufflehog_to_workunits.py - -o workunits.json

Output (clean top-level JSON array, verified-first):
    [{"id": "...", "title": "...", "targets": ["path:line"],
      "hints": {"detector": "...", "verified": "true|unknown|false",
                "severity": "...", "commit": "...", "redacted": "...",
                "cwe": "CWE-798"}}, ...]

Raw secrets are never emitted; the redacted form keeps a short prefix.
"""
import argparse
import hashlib
import json
import sys


def redact(value):
    if not value:
        return ""
    value = str(value)
    keep = min(4, max(1, len(value) // 8))
    return value[:keep] + "*" * (max(0, len(value) - keep))


def flatten_extra(extra):
    if not isinstance(extra, dict):
        return ""
    return " ".join("%s=%s" % (k, v) for k, v in sorted(extra.items()))[:500]


def location_of(obj):
    """Return (path, line, commit, extra_loc_hints) from SourceMetadata."""
    meta = (obj.get("SourceMetadata") or {}).get("Data") or {}
    for key in ("Git", "Github", "Gitlab"):
        d = meta.get(key)
        if d:
            return (d.get("file", "<unknown>"), d.get("line", 0),
                    d.get("commit", ""), {"email": d.get("email", ""),
                                          "repository": d.get("repository", "")})
    d = meta.get("Filesystem")
    if d:
        return d.get("file", "<unknown>"), d.get("line", 0), "", {}
    d = meta.get("Docker")
    if d:
        return d.get("file", "<unknown>"), 0, "", {"image": d.get("image", ""),
                                                   "layer": d.get("layer", "")}
    d = meta.get("S3")
    if d:
        return "s3://%s/%s" % (d.get("bucket", "?"), d.get("file", "?")), 0, "", {}
    d = meta.get("GCS")
    if d:
        return "gs://%s/%s" % (d.get("bucket", "?"), d.get("filename", "?")), 0, "", {}
    for key, d in meta.items():
        if isinstance(d, dict) and d.get("file"):
            return d.get("file"), d.get("line", 0), d.get("commit", ""), {}
    return "<unknown>", 0, "", {}


def verified_state(obj):
    if obj.get("Verified"):
        return "true"
    if obj.get("VerificationError"):
        return "unknown"
    return "false"


def severity_for(state, detector):
    if state == "true":
        return "critical"
    if state == "unknown":
        return "high"
    hot = ("aws", "github", "gitlab", "stripe", "slack", "privatekey",
           "gcp", "azure", "postgres", "mysql", "mongodb", "jdbc", "openai")
    return "medium" if any(h in (detector or "").lower() for h in hot) else "low"


def to_unit(obj):
    detector = obj.get("DetectorName") or str(obj.get("DetectorType", "unknown"))
    path, line, commit, loc_hints = location_of(obj)
    state = verified_state(obj)
    raw = obj.get("Raw") or obj.get("RawV2") or ""
    redacted = obj.get("Redacted") or redact(raw)
    uid = hashlib.sha1("|".join([detector, path, str(line), commit,
                                 redact(raw)]).encode("utf-8")).hexdigest()[:12]
    tag = {"true": "[VERIFIED] ", "unknown": "[UNKNOWN] ", "false": ""}[state]
    hints = {
        "detector": detector,
        "verified": state,
        "severity": severity_for(state, detector),
        "commit": commit,
        "redacted": redacted if redacted else redact(raw),
        "cwe": "CWE-798",
    }
    extra = flatten_extra(obj.get("ExtraData"))
    if extra:
        hints["extra"] = extra
    if obj.get("VerificationError"):
        hints["verification_error"] = str(obj["VerificationError"])[:300]
    if obj.get("DecoderName") and obj["DecoderName"] not in ("PLAIN", ""):
        hints["decoder"] = obj["DecoderName"]
    for k, v in loc_hints.items():
        if v:
            hints[k] = v
    return {
        "id": "trufflehog-" + uid,
        "title": "%s%s in %s:%s" % (tag, detector, path, line),
        "targets": ["%s:%s" % (path, line)],
        "hints": hints,
    }


def read_jsonl(stream):
    for lineno, line in enumerate(stream, 1):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue  # skip log lines mixed into the stream
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            print("warning: line %d: bad JSON, skipped" % lineno, file=sys.stderr)
            continue
        if isinstance(obj, dict) and ("DetectorName" in obj or "DetectorType" in obj):
            yield obj


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="trufflehog --json files (JSONL); '-' for stdin")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output file for the work-unit JSON array (default: workunits.json)")
    args = ap.parse_args(argv)

    units, seen = [], set()
    for src in args.inputs:
        if src == "-":
            objs = read_jsonl(sys.stdin)
        else:
            try:
                fh = open(src, "r", encoding="utf-8", errors="replace")
            except OSError as exc:
                print("warning: %s: %s" % (src, exc), file=sys.stderr)
                continue
            objs = read_jsonl(fh)
        for obj in objs:
            u = to_unit(obj)
            if u["id"] in seen:
                continue
            seen.add(u["id"])
            units.append(u)

    order = {"true": 0, "unknown": 1, "false": 2}
    units.sort(key=lambda u: (order.get(u["hints"]["verified"], 3),
                              u["hints"]["detector"],
                              u["targets"][0] if u["targets"] else ""))

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    verified = sum(1 for u in units if u["hints"]["verified"] == "true")
    print("wrote %d work units (%d verified) to %s"
          % (len(units), verified, args.output), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
