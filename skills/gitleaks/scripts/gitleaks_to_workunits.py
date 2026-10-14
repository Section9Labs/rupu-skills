#!/usr/bin/env python3
"""Convert gitleaks reports (native JSON and/or SARIF 2.1.0) into a clean
JSON array of work units for rupu `for_each:` / lead-agent `dispatch`.

Usage:
    python3 scripts/gitleaks_to_workunits.py gitleaks.json [gitleaks.sarif ...] -o workunits.json

Output (clean top-level JSON array):
    [{"id": "...", "title": "...", "targets": ["path:line"],
      "hints": {"rule": "...", "severity": "...", "commit": "...",
                "entropy": "...", "redacted_match": "...", "cwe": "CWE-798"}}, ...]

Secret values are always redacted (first 4 chars + stars). Units are sorted
provider-specific rules first, then by entropy descending.
"""
import argparse
import hashlib
import json
import sys

GENERIC_RULES = {"generic-api-key", "generic-password", "hashicorp-tf-password"}

HIGH_SEV_HINTS = (
    "aws", "gcp", "azure", "private-key", "privatekey", "github", "gitlab",
    "stripe", "slack", "twilio", "sendgrid", "openai", "vault", "db", "pypi",
    "npm",
)


def redact(value):
    if not value:
        return ""
    value = str(value)
    keep = min(4, max(1, len(value) // 8))
    return value[:keep] + "*" * (len(value) - keep)


def severity_for(rule, entropy):
    r = (rule or "").lower()
    if any(h in r for h in HIGH_SEV_HINTS):
        return "high"
    try:
        if entropy is not None and float(entropy) >= 4.5:
            return "high"
    except (TypeError, ValueError):
        pass
    return "medium" if r not in GENERIC_RULES else "low"


def unit_id(rule, path, line, commit):
    raw = "|".join([str(rule), str(path), str(line), str(commit)])
    return "gitleaks-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def from_native(doc):
    """gitleaks native JSON: a top-level array of finding objects."""
    units = []
    for f in doc:
        if not isinstance(f, dict):
            continue
        rule = f.get("RuleID") or f.get("ruleID") or "unknown-rule"
        path = f.get("File") or f.get("file") or "<unknown>"
        line = f.get("StartLine") or f.get("startLine") or 0
        commit = f.get("Commit") or f.get("commit") or ""
        secret = f.get("Secret") or f.get("secret") or ""
        entropy = f.get("Entropy", f.get("entropy"))
        hints = {
            "rule": rule,
            "severity": severity_for(rule, entropy),
            "commit": commit,
            "entropy": "" if entropy is None else "%.2f" % float(entropy),
            "redacted_match": redact(secret),
            "cwe": "CWE-798",
        }
        if f.get("Author"):
            hints["author"] = f.get("Author")
        if f.get("Email"):
            hints["email"] = f.get("Email")
        if f.get("Date"):
            hints["date"] = f.get("Date")
        if f.get("Fingerprint"):
            hints["fingerprint"] = f.get("Fingerprint")
        units.append({
            "id": unit_id(rule, path, line, commit),
            "title": "%s in %s:%s" % (rule, path, line),
            "targets": ["%s:%s" % (path, line)],
            "hints": hints,
        })
    return units


def from_sarif(doc):
    """SARIF 2.1.0 produced by gitleaks --report-format sarif."""
    units = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            rule = res.get("ruleId", "unknown-rule")
            path, line = "<unknown>", 0
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation", {})
                path = phys.get("artifactLocation", {}).get("uri", path)
                line = phys.get("region", {}).get("startLine", 0)
            # gitleaks puts commit/fingerprint info in partialFingerprints
            pf = res.get("partialFingerprints", {}) or {}
            commit = pf.get("commitSha", "")
            msg = res.get("message", {}).get("text", "")
            hints = {
                "rule": rule,
                "severity": severity_for(rule, None),
                "commit": commit,
                "entropy": "",
                "redacted_match": redact(msg.split()[-1] if msg else ""),
                "cwe": "CWE-798",
            }
            if pf.get("email"):
                hints["email"] = pf["email"]
            if pf.get("author"):
                hints["author"] = pf["author"]
            units.append({
                "id": unit_id(rule, path, line, commit),
                "title": "%s in %s:%s" % (rule, path, line),
                "targets": ["%s:%s" % (path, line)],
                "hints": hints,
            })
    return units


def load_report(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read().strip()
    if not text:
        return []
    doc = json.loads(text)
    if isinstance(doc, list):
        return from_native(doc)
    if isinstance(doc, dict) and "runs" in doc:
        return from_sarif(doc)
    raise ValueError("%s: not gitleaks JSON (array) or SARIF (runs)" % path)


def sort_key(u):
    rule = u["hints"].get("rule", "")
    generic = 1 if rule in GENERIC_RULES or rule.startswith("generic") else 0
    try:
        ent = float(u["hints"].get("entropy") or 0.0)
    except ValueError:
        ent = 0.0
    return (generic, -ent, rule, u["targets"][0] if u["targets"] else "")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("reports", nargs="+", help="gitleaks JSON and/or SARIF report files")
    ap.add_argument("-o", "--output", default="workunits.json",
                    help="output file for the work-unit JSON array (default: workunits.json)")
    args = ap.parse_args(argv)

    units, seen = [], set()
    for path in args.reports:
        try:
            for u in load_report(path):
                if u["id"] in seen:
                    continue
                seen.add(u["id"])
                units.append(u)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("warning: skipping %s: %s" % (path, exc), file=sys.stderr)

    units.sort(key=sort_key)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)
        fh.write("\n")
    print("wrote %d work units to %s" % (len(units), args.output), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
