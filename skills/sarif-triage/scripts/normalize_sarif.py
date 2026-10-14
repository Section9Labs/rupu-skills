#!/usr/bin/env python3
"""normalize_sarif.py - stage 1 of the sarif-triage pipeline.

Reads one or more SARIF 2.1.0 files (or common native JSON output from
semgrep, bandit, gosec, gitleaks, trivy, npm-audit) and emits a normalized
findings JSON list on stdout (or -o FILE).

Normalized record:
  {tool, rule_id, title, file, line, severity, cwe, message, fingerprint,
   code_flow[], [column], [package/...extras]}

Usage:
  python3 scripts/normalize_sarif.py semgrep.sarif codeql.sarif -o normalized.json
  cat gosec.sarif | python3 scripts/normalize_sarif.py --tool gosec
  python3 scripts/normalize_sarif.py bandit-native.json --format bandit

Composable: pipe the output into dedupe_findings.py.
"""
import argparse
import hashlib
import json
import re
import sys

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# SARIF result.level / rule.defaultConfiguration.level -> normalized severity
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

# tool-native severity strings -> normalized severity (see references/severity-map.md)
NATIVE_SEV = {
    "critical": "critical", "blocker": "critical",
    "high": "high", "error": "high", "major": "high", "important": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium",
    "low": "low", "minor": "low", "note": "low", "weak": "low",
    "info": "info", "informational": "info", "unknown": "low",
}

CWE_RE = re.compile(r"cwe[-_/ :]*0*(\d+)", re.I)


def cvss_to_sev(score):
    """GitHub-style security-severity (CVSS 0-10) banding."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def norm_sev(name):
    if name is None:
        return None
    return NATIVE_SEV.get(str(name).strip().lower())


def extract_cwe(*chunks):
    """Pull the first CWE id out of tags, properties, descriptions, ids."""
    for chunk in chunks:
        if chunk is None or chunk == "":
            continue
        if isinstance(chunk, bool):
            continue
        if isinstance(chunk, int):
            return "CWE-%d" % chunk
        if isinstance(chunk, (list, tuple)):
            for item in chunk:
                got = extract_cwe(item)
                if got:
                    return got
            continue
        m = CWE_RE.search(str(chunk))
        if m:
            return "CWE-" + m.group(1)
    return ""


def content_fingerprint(file, line, rule_id, message):
    """Tool-independent fallback fingerprint: file + line + rule + message."""
    msg = re.sub(r"\s+", " ", (message or "")).strip().lower()[:200]
    key = "|".join([str(file or ""), str(line or 0), str(rule_id or ""), msg])
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]


def parse_line(line):
    try:
        return int(str(line).split("-")[0])
    except (TypeError, ValueError):
        return 0


def make_record(tool, rule_id, title, file, line, severity, cwe, message,
                fingerprint=None, code_flow=None, column=None, extra=None):
    line_i = parse_line(line)
    rec = {
        "tool": (tool or "unknown").strip().lower(),
        "rule_id": rule_id or "",
        "title": (title or rule_id or (message or "")[:80] or "finding").strip(),
        "file": file or "",
        "line": line_i,
        "severity": severity if severity in SEV_RANK else "medium",
        "cwe": cwe or "",
        "message": (message or "").strip(),
        "fingerprint": fingerprint or content_fingerprint(file, line_i, rule_id, message),
        "code_flow": code_flow or [],
    }
    if column:
        try:
            rec["column"] = int(column)
        except (TypeError, ValueError):
            pass
    if extra:
        rec.update(extra)
    return rec


# ---------------------------------------------------------------- SARIF 2.1.0

def sarif_location(res):
    for loc in res.get("locations") or []:
        pl = loc.get("physicalLocation") or {}
        uri = (pl.get("artifactLocation") or {}).get("uri") or ""
        region = pl.get("region") or {}
        return uri, region.get("startLine") or 0, region.get("startColumn")
    return "", 0, None


def sarif_code_flow(res):
    """First threadFlow as ['file:line -- step message', ...] (the taint path)."""
    for cf in res.get("codeFlows") or []:
        for tf in cf.get("threadFlows") or []:
            steps = []
            for tfl in tf.get("locations") or []:
                loc = tfl.get("location") or {}
                pl = loc.get("physicalLocation") or {}
                uri = (pl.get("artifactLocation") or {}).get("uri") or ""
                ln = (pl.get("region") or {}).get("startLine") or 0
                msg = (loc.get("message") or {}).get("text") or ""
                step = "%s:%s" % (uri, ln)
                if msg:
                    step += " -- " + msg.strip()
                steps.append(step)
            if steps:
                return steps
    return []


def parse_sarif(doc, tool_tag):
    out = []
    for run in doc.get("runs") or []:
        tool_obj = run.get("tool") or {}
        driver = tool_obj.get("driver") or {}
        tool = (tool_tag or driver.get("name") or "unknown").strip().lower()
        driver_rules = driver.get("rules") or []
        rules = {}
        for comp in [driver] + (tool_obj.get("extensions") or []):
            for rule in comp.get("rules") or []:
                rid = rule.get("id")
                if rid:
                    rules.setdefault(rid, rule)
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or ""
            rule = rules.get(rid)
            if rule is None:
                ri = res.get("ruleIndex")
                if isinstance(ri, int) and 0 <= ri < len(driver_rules):
                    rule = driver_rules[ri]
                    rid = rid or rule.get("id", "")
                else:
                    rule = {}
            file, line, col = sarif_location(res)
            message = ((res.get("message") or {}).get("text")) or ""
            title = ((rule.get("shortDescription") or {}).get("text")) or rid
            props = dict(rule.get("properties") or {})
            props.update(res.get("properties") or {})
            # severity: security-severity (CVSS-like) wins, then level, then
            # any tool-native severity stashed in properties
            sev = cvss_to_sev(props.get("security-severity"))
            if not sev:
                level = res.get("level") or \
                    (rule.get("defaultConfiguration") or {}).get("level")
                sev = SARIF_LEVEL.get(level) \
                    or norm_sev(props.get("severity") or props.get("issue_severity")) \
                    or "medium"
            cwe = extract_cwe(props.get("cwe"), props.get("tags"),
                              (rule.get("fullDescription") or {}).get("text"),
                              rid)
            fp = None
            pf = res.get("partialFingerprints") or {}
            if pf:
                joined = "|".join("%s=%s" % (k, v) for k, v in sorted(pf.items()))
                fp = hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:16]
            out.append(make_record(tool, rid, title, file, line, sev, cwe,
                                   message, fp, sarif_code_flow(res), col))
    return out


# ------------------------------------------------------------- native formats

def parse_semgrep(doc, tool_tag):
    out = []
    for r in doc.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        fp = extra.get("fingerprint")
        if not fp or "requires login" in str(fp):
            fp = None
        else:
            fp = hashlib.sha256(str(fp).encode()).hexdigest()[:16]
        sev = cvss_to_sev(meta.get("security-severity")) \
            or norm_sev(extra.get("severity")) or "medium"
        out.append(make_record(
            tool_tag or "semgrep", r.get("check_id"), r.get("check_id"),
            r.get("path"), (r.get("start") or {}).get("line"), sev,
            extract_cwe(meta.get("cwe")), extra.get("message"), fp,
            column=(r.get("start") or {}).get("col")))
    return out


def parse_bandit(doc, tool_tag):
    out = []
    for r in doc.get("results") or []:
        out.append(make_record(
            tool_tag or "bandit", r.get("test_id"), r.get("test_name"),
            r.get("filename"), r.get("line_number"),
            norm_sev(r.get("issue_severity")) or "medium",
            extract_cwe((r.get("issue_cwe") or {}).get("id")),
            r.get("issue_text"),
            extra={"tool_confidence": str(r.get("issue_confidence", "")).lower()}))
    return out


def parse_gosec(doc, tool_tag):
    out = []
    for r in doc.get("Issues") or []:
        cwe_obj = r.get("cwe") or {}
        out.append(make_record(
            tool_tag or "gosec", r.get("rule_id"), r.get("details"),
            r.get("file"), r.get("line"),
            norm_sev(r.get("severity")) or "medium",
            extract_cwe(cwe_obj.get("id") or cwe_obj.get("ID")),
            r.get("details"), column=parse_line(r.get("column")),
            extra={"tool_confidence": str(r.get("confidence", "")).lower()}))
    return out


def parse_gitleaks(items, tool_tag):
    out = []
    for r in items:
        fp = r.get("Fingerprint")
        fp = hashlib.sha256(str(fp).encode()).hexdigest()[:16] if fp else None
        out.append(make_record(
            tool_tag or "gitleaks", r.get("RuleID"), r.get("Description"),
            r.get("File"), r.get("StartLine"), "high", "CWE-798",
            r.get("Description") or r.get("Match", ""), fp,
            extra={"commit": r.get("Commit", "")}))
    return out


def parse_trivy(doc, tool_tag):
    out = []
    for res in doc.get("Results") or []:
        target = res.get("Target") or ""
        for v in res.get("Vulnerabilities") or []:
            pkg = v.get("PkgName", "")
            out.append(make_record(
                tool_tag or "trivy", v.get("VulnerabilityID"),
                "%s: %s %s" % (v.get("VulnerabilityID"), pkg,
                               v.get("InstalledVersion", "")),
                target, 0, norm_sev(v.get("Severity")) or "medium",
                extract_cwe(v.get("CweIDs")),
                v.get("Title") or (v.get("Description") or "")[:300],
                extra={"package": pkg,
                       "installed": v.get("InstalledVersion", ""),
                       "fixed": v.get("FixedVersion", "")}))
        for s in res.get("Secrets") or []:
            out.append(make_record(
                tool_tag or "trivy", s.get("RuleID"), s.get("Title"),
                target, s.get("StartLine"),
                norm_sev(s.get("Severity")) or "high", "CWE-798",
                s.get("Title")))
    return out


def parse_npm_audit(doc, tool_tag):
    out = []
    for name, v in (doc.get("vulnerabilities") or {}).items():
        advisory = next((x for x in (v.get("via") or [])
                         if isinstance(x, dict)), {})
        title = advisory.get("title") or "vulnerable dependency %s" % name
        rid = str(advisory.get("source") or advisory.get("url") or name)
        out.append(make_record(
            tool_tag or "npm-audit", rid, "%s: %s" % (name, title),
            "package-lock.json", 0,
            norm_sev(v.get("severity")) or "medium",
            extract_cwe(advisory.get("cwe")), title,
            extra={"package": name, "range": v.get("range", "")}))
    return out


PARSERS = {
    "sarif": parse_sarif,
    "semgrep": parse_semgrep,
    "bandit": parse_bandit,
    "gosec": parse_gosec,
    "gitleaks": parse_gitleaks,
    "trivy": parse_trivy,
    "npm-audit": parse_npm_audit,
}


def detect(doc):
    if isinstance(doc, list):
        if doc and isinstance(doc[0], dict) and "RuleID" in doc[0]:
            return "gitleaks"
        if doc and isinstance(doc[0], dict) and "fingerprint" in doc[0] \
                and "severity" in doc[0]:
            return "normalized"  # already normalized: pass through
        return "gitleaks"  # empty list: harmless either way
    if isinstance(doc, dict):
        if "runs" in doc:
            return "sarif"
        if "Issues" in doc:
            return "gosec"
        if "auditReportVersion" in doc or ("advisories" in doc and "metadata" in doc):
            return "npm-audit"
        if "Results" in doc and ("SchemaVersion" in doc or "ArtifactName" in doc):
            return "trivy"
        results = doc.get("results")
        if isinstance(results, list):
            if results and "check_id" in results[0]:
                return "semgrep"
            if results and "issue_severity" in results[0]:
                return "bandit"
            if "metrics" in doc:
                return "bandit"
            return "semgrep"
    raise SystemExit("could not detect format; pass --format explicitly")


def load(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", default=["-"],
                    help="SARIF/native JSON files ('-' or none = stdin)")
    ap.add_argument("--tool", help="tag records with this tool name "
                                   "(overrides the autodetected driver name)")
    ap.add_argument("--format", default="auto",
                    choices=["auto"] + sorted(PARSERS),
                    help="input format (default: autodetect per file)")
    ap.add_argument("--min-severity", default="info", choices=sorted(SEV_RANK),
                    help="drop records below this normalized severity")
    ap.add_argument("-o", "--output", help="write JSON list here (default stdout)")
    args = ap.parse_args()

    records = []
    for path in (args.inputs or ["-"]):
        doc = load(path)
        fmt = args.format if args.format != "auto" else detect(doc)
        if fmt == "normalized":
            records.extend(doc)
            continue
        records.extend(PARSERS[fmt](doc, args.tool))

    floor = SEV_RANK[args.min_severity]
    records = [r for r in records if SEV_RANK.get(r["severity"], 2) >= floor]

    text = json.dumps(records, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    print("normalize_sarif: %d normalized finding(s)" % len(records),
          file=sys.stderr)


if __name__ == "__main__":
    main()
