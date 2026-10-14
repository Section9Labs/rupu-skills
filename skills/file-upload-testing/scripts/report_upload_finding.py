#!/usr/bin/env python3
"""report_upload_finding.py — turn a confirmed upload exploit into a
rupu `findings.report` payload (web profile complete: route pinned, HTTP
exchange in evidence, OWASP/CWE classification).

Usage:
  python3 scripts/report_upload_finding.py \
      --url https://192.0.2.10/uploads/shell.php.jpg \
      --title "Unrestricted file upload to RCE via double extension" \
      --severity critical \
      --upload-request upload.req [--upload-response upload.resp] \
      --exec-request exec.req --exec-response exec.resp \
      [--rationale "..."] [--cwe CWE-434] [--wstg WSTG-BUSL-09] \
      -o finding.json

Submit the resulting JSON via the `finding-report` skill / findings.report
tool. Severity guide: exec=critical, stored-shell/zip-slip write=high,
SVG stored XSS=medium.
"""
import argparse
import json
import sys

SEVERITIES = ("info", "low", "medium", "high", "critical")


def slurp(path):
    if not path:
        return None
    with open(path, "r", errors="replace") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True, help="URL of the stored/executed file (target_ref)")
    ap.add_argument("--title", required=True)
    ap.add_argument("--severity", default="critical", choices=SEVERITIES)
    ap.add_argument("--upload-request", required=True, help="raw upload HTTP request file")
    ap.add_argument("--upload-response", help="raw upload HTTP response file")
    ap.add_argument("--exec-request", required=True, help="raw request that triggered the payload")
    ap.add_argument("--exec-response", required=True, help="raw response proving impact")
    ap.add_argument("--rationale", help="override the default rationale text")
    ap.add_argument("--wstg", default="WSTG-BUSL-09")
    ap.add_argument("--cwe", default="CWE-434")
    ap.add_argument("-o", "--output", help="write findings.report payload here (default stdout)")
    args = ap.parse_args()

    rationale = args.rationale or (
        "The upload endpoint accepted a file that bypassed its validation "
        "(%s / %s). The stored file at %s was then requested and produced "
        "attacker-controlled behavior, as shown in the execution exchange "
        "below. Upload request and triggering request/response are included "
        "as evidence." % (args.wstg, args.cwe, args.url)
    )

    exchanges = [{
        "name": "upload",
        "request": slurp(args.upload_request),
        "response": slurp(args.upload_response) or "(response not captured)",
    }, {
        "name": "execution",
        "request": slurp(args.exec_request),
        "response": slurp(args.exec_response),
    }]

    finding = {
        "title": args.title,
        "scope": "endpoint",
        "target_ref": args.url,
        "severity": args.severity,
        "classification": {"wstg": args.wstg, "cwe": args.cwe},
        "evidence": {
            "rationale": rationale,
            "http_exchanges": exchanges,
        },
    }

    out = json.dumps(finding, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out + "\n")
        print("[+] findings.report payload -> %s (submit via the finding-report skill)"
              % args.output)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
