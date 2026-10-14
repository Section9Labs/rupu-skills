#!/usr/bin/env python3
"""parse_burp_xml.py - parse a Burp Suite issues XML export into normalized
issues + rupu outputs, for when the REST API is unavailable.

Export from Burp: select issues -> right-click -> "Report selected issues"
-> XML, with "Include requests/responses" (base64) checked.

Emits the same normalized structure as burp_scan.py:
    {name, severity, confidence, url, issue_type, evidence}
plus a rupu work-units array (--work-units) and findings.report payloads
(--findings).

Python 3 standard library only.

Example:
  python3 scripts/parse_burp_xml.py burp-export.xml \
      -o issues.json --work-units units.json --findings findings.json \
      --min-severity low
"""

import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET

SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
    "false positive": "info",
}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CLASSIFICATION = [
    ("sql injection", "CWE-89", "WSTG-INPV-05"),
    ("cross-site scripting (stored", "CWE-79", "WSTG-INPV-02"),
    ("cross-site scripting (dom", "CWE-79", "WSTG-CLNT-01"),
    ("cross-site scripting", "CWE-79", "WSTG-INPV-01"),
    ("command injection", "CWE-78", "WSTG-INPV-12"),
    ("xml external entity", "CWE-611", "WSTG-INPV-07"),
    ("template injection", "CWE-1336", "WSTG-INPV-18"),
    ("request forgery (csrf", "CWE-352", "WSTG-SESS-05"),
    ("cross-site request forgery", "CWE-352", "WSTG-SESS-05"),
    ("request forgery", "CWE-918", "WSTG-INPV-19"),
    ("path traversal", "CWE-22", "WSTG-ATHZ-01"),
    ("file path", "CWE-22", "WSTG-ATHZ-01"),
    ("open redirect", "CWE-601", "WSTG-CLNT-04"),
    ("request smuggling", "CWE-444", "WSTG-INPV-15"),
    ("deserial", "CWE-502", "OWASP-Top10:A08:2021"),
    ("cors", "CWE-942", "WSTG-CONF-11"),
    ("session token", "CWE-330", "WSTG-SESS-01"),
    ("tls", "CWE-319", "WSTG-CRYP-03"),
    ("ssl", "CWE-319", "WSTG-CRYP-03"),
    ("cleartext", "CWE-319", "WSTG-CRYP-03"),
    ("certificate", "CWE-295", "WSTG-CRYP-03"),
    ("error message", "CWE-209", "WSTG-ERRH-01"),
    ("information disclosure", "CWE-200", "WSTG-ERRH-01"),
    ("header injection", "CWE-113", "WSTG-INPV-15"),
]
FALLBACK_CLASSIFICATION = ("CWE-693", "OWASP-Top10:A05:2021")


def classify(name):
    low = (name or "").lower()
    for key, cwe, owasp in CLASSIFICATION:
        if key in low:
            return cwe, owasp
    return FALLBACK_CLASSIFICATION


def text(elem, tag, default=""):
    node = elem.find(tag)
    if node is None or node.text is None:
        return default
    return node.text.strip()


def decode_message(node):
    """Decode a <request>/<response> element (base64 attr aware)."""
    if node is None or node.text is None:
        return ""
    raw = node.text.strip()
    if node.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", "replace")
        except Exception:
            return "<undecodable base64>"
    return raw


def parse_issue(elem):
    name = text(elem, "name", "unknown")
    host = text(elem, "host")  # e.g. https://example.com
    path = text(elem, "path")
    url = host + path
    severity = SEVERITY_MAP.get(text(elem, "severity", "info").lower(), "info")
    confidence = text(elem, "confidence").lower()
    evidence = []
    for rr in elem.findall("requestresponse"):
        evidence.append(
            {
                "type": "ExportedRequestResponse",
                "url": url,
                "request": decode_message(rr.find("request")),
                "response": decode_message(rr.find("response")),
            }
        )
    cwe, owasp = classify(name)
    detail = text(elem, "issueDetail") or text(elem, "issueBackground")
    return {
        "name": name,
        "severity": severity,
        "confidence": confidence,
        "url": url,
        "issue_type": text(elem, "type"),
        "serial_number": text(elem, "serialNumber"),
        "location": text(elem, "location"),
        "description": detail,
        "cwe": cwe,
        "owasp": owasp,
        "evidence": evidence,
    }


def parse_file(path):
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        sys.exit(
            "[-] XML parse error ({}). Use Burp's XML export, not the HTML "
            "report.".format(exc)
        )
    root = tree.getroot()
    if root.tag != "issues":
        sys.exit("[-] unexpected root element <{}>; expected <issues>".format(root.tag))
    seen = {}
    for elem in root.findall("issue"):
        issue = parse_issue(elem)
        key = (issue["name"], issue["url"], issue["location"])
        if key not in seen:
            seen[key] = issue
    return list(seen.values())


def build_work_units(issues):
    units = []
    for i, iss in enumerate(issues, 1):
        units.append(
            {
                "id": "burp-issue-{:03d}".format(i),
                "title": "Confirm: {} at {}".format(iss["name"], iss["url"]),
                "targets": [iss["url"]],
                "hints": {
                    "tool": "burp",
                    "issue_name": iss["name"],
                    "issue_type": iss["issue_type"],
                    "severity": iss["severity"],
                    "confidence": iss["confidence"],
                    "location": iss["location"],
                    "cwe": iss["cwe"],
                    "wstg": iss["owasp"],
                    "next": "replay evidence request in Repeater; escalate "
                    "with the matching tool (sqlmap -r / dalfox / "
                    "Collaborator) and file via finding-report",
                },
            }
        )
    return units


def build_findings(issues):
    findings = []
    for iss in issues:
        ev = iss["evidence"][0] if iss["evidence"] else {}
        rationale = (
            "Burp Scanner (confidence: {}) identified '{}' at {} ({}). {} "
            "Classified {} / {}.".format(
                iss["confidence"] or "unknown",
                iss["name"],
                iss["url"],
                iss["location"] or "no location detail",
                (iss["description"] or "").strip()[:400],
                iss["cwe"],
                iss["owasp"],
            )
        )
        findings.append(
            {
                "title": "{} at {}".format(iss["name"], iss["url"]),
                "scope": "endpoint",
                "target_ref": iss["url"],
                "severity": iss["severity"],
                "classification": {"cwe": iss["cwe"], "owasp": iss["owasp"]},
                "evidence": {
                    "rationale": rationale,
                    "http_exchange": {
                        "request": ev.get("request", ""),
                        "response": ev.get("response", ""),
                    },
                },
            }
        )
    return findings


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    print("[+] wrote {}".format(path), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Parse Burp issues XML export into normalized issues, "
        "rupu work units and findings.report payloads."
    )
    ap.add_argument("xml_file", help="Burp XML export (base64 req/resp)")
    ap.add_argument("-o", "--output", help="normalized JSON report file")
    ap.add_argument("--work-units", help="rupu work-units JSON array file")
    ap.add_argument("--findings", help="findings.report payloads JSON array file")
    ap.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="info",
        help="drop issues below this severity (default: info = keep all)",
    )
    args = ap.parse_args()

    issues = parse_file(args.xml_file)
    floor = SEVERITY_ORDER[args.min_severity]
    issues = [i for i in issues if SEVERITY_ORDER[i["severity"]] >= floor]
    issues.sort(key=lambda i: -SEVERITY_ORDER[i["severity"]])

    report = {"source": args.xml_file, "issue_count": len(issues), "issues": issues}

    if args.output:
        write_json(args.output, report)
    if args.work_units:
        write_json(args.work_units, build_work_units(issues))
    if args.findings:
        write_json(args.findings, build_findings(issues))
    if not (args.output or args.work_units or args.findings):
        json.dump(report, sys.stdout, indent=2)
        print()

    print("[+] {} unique issues parsed".format(len(issues)), file=sys.stderr)


if __name__ == "__main__":
    main()
