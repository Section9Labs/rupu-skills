#!/usr/bin/env python3
"""burp_scan.py - thin client for Burp Suite Pro's built-in REST API.

Starts a crawl-and-audit scan, polls the task until it finishes, pulls the
issue events, normalizes each issue to
    {name, severity, confidence, url, issue_type, evidence}
and emits:
  * merged JSON report (-o)
  * a rupu work-units array (--work-units), first char '[', one unit per issue
  * findings.report payloads (--findings), one per issue

Python 3 standard library only.

Examples:
  export BURP_API_URL=http://127.0.0.1:1337 BURP_API_KEY=S9xKEY
  python3 scripts/burp_scan.py --url https://example.com/ \
      --scan-config "Audit checks - light active" \
      -o issues.json --work-units units.json --findings findings.json
  python3 scripts/burp_scan.py --task-id 42 -o issues.json   # resume polling
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

TERMINAL_STATUSES = {"succeeded", "failed"}

SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "information": "info",
    "false_positive": "info",
}

# (keyword in lowercased issue name) -> (CWE, OWASP/WSTG). Order matters.
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


def api_url(base, key, path):
    return "{}/{}/v0.1{}".format(base.rstrip("/"), key, path)


def http_request(method, url, body=None, timeout=60):
    """Return (status, headers-dict, body-bytes). Never raises HTTPError."""
    data = None
    req = urllib.request.Request(url, method=method)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def render_segments(segments):
    """Reconstruct a request/response from Burp's base64 segment array."""
    parts = []
    for seg in segments or []:
        if "data" in seg:
            try:
                parts.append(
                    base64.b64decode(seg["data"]).decode("utf-8", "replace")
                )
            except Exception:
                parts.append("<undecodable segment>")
        elif seg.get("type") == "SnipSegment":
            parts.append(
                "\n...[{} bytes snipped]...\n".format(seg.get("length", "?"))
            )
    return "".join(parts)


def normalize_issue(issue):
    url = (issue.get("origin") or "") + (issue.get("path") or "")
    severity = SEVERITY_MAP.get(
        str(issue.get("severity", "info")).lower(), "info"
    )
    evidence = []
    for ev in issue.get("evidence", []):
        rr = ev.get("request_response") or {}
        evidence.append(
            {
                "type": ev.get("type", ""),
                "url": rr.get("url", url),
                "request": render_segments(rr.get("request")),
                "response": render_segments(rr.get("response")),
            }
        )
    cwe, owasp = classify(issue.get("name", ""))
    return {
        "name": issue.get("name", "unknown"),
        "severity": severity,
        "confidence": str(issue.get("confidence", "")).lower(),
        "url": url,
        "issue_type": str(issue.get("type_index", "")),
        "serial_number": str(issue.get("serial_number", "")),
        "description": issue.get("description", ""),
        "cwe": cwe,
        "owasp": owasp,
        "evidence": evidence,
    }


def start_scan(base, key, args):
    body = {"urls": args.url}
    if args.scan_config:
        body["scan_configurations"] = [
            {"type": "NamedConfiguration", "name": n} for n in args.scan_config
        ]
    if args.username and args.password:
        body["application_logins"] = [
            {
                "type": "UsernameAndPasswordLogin",
                "username": args.username,
                "password": args.password,
            }
        ]
    if args.include or args.exclude:
        body["scope"] = {
            "type": "SimpleScope",
            "include": [{"rule": r} for r in (args.include or [])],
            "exclude": [{"rule": r} for r in (args.exclude or [])],
        }
    if args.resource_pool:
        body["resource_pool"] = args.resource_pool

    status, headers, raw = http_request(
        "POST", api_url(base, key, "/scan"), body
    )
    if status != 201:
        sys.exit(
            "[-] scan start failed: HTTP {} {}".format(
                status, raw.decode("utf-8", "replace")[:500]
            )
        )
    location = headers.get("Location") or headers.get("location") or ""
    task_id = location.rstrip("/").split("/")[-1]
    if not task_id:
        sys.exit("[-] 201 received but no Location header with task id")
    print("[+] scan started, task id {}".format(task_id), file=sys.stderr)
    return task_id


def poll_scan(base, key, task_id, interval, timeout):
    deadline = time.time() + timeout
    last_status = ""
    state = {}
    while True:
        status, _, raw = http_request(
            "GET", api_url(base, key, "/scan/{}".format(task_id))
        )
        if status == 200:
            state = json.loads(raw.decode("utf-8", "replace"))
            scan_status = state.get("scan_status", "unknown")
            metrics = state.get("scan_metrics", {}) or {}
            line = "[*] status={} progress={}% issues={}".format(
                scan_status,
                metrics.get("crawl_and_audit_progress", "?"),
                len(state.get("issue_events", [])),
            )
            if line != last_status:
                print(line, file=sys.stderr)
                last_status = line
            if scan_status in TERMINAL_STATUSES:
                return state
        else:
            print(
                "[!] poll HTTP {}; retrying".format(status), file=sys.stderr
            )
        if time.time() > deadline:
            print("[!] timeout reached; returning partial state", file=sys.stderr)
            return state
        time.sleep(interval)


def dedupe_issues(events):
    seen = {}
    for ev in events or []:
        issue = ev.get("issue") or {}
        key = (
            issue.get("name"),
            (issue.get("origin") or "") + (issue.get("path") or ""),
        )
        if key not in seen:
            seen[key] = normalize_issue(issue)
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
            "Burp Scanner (confidence: {}) identified '{}' at {}. {} "
            "Classified {} / {}.".format(
                iss["confidence"] or "unknown",
                iss["name"],
                iss["url"],
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
        description="Drive Burp Suite Pro REST API: start scan, poll, "
        "normalize issues, emit rupu work units + findings payloads."
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("BURP_API_URL", "http://127.0.0.1:1337"),
        help="REST API base (default env BURP_API_URL or http://127.0.0.1:1337)",
    )
    ap.add_argument(
        "--api-key",
        default=os.environ.get("BURP_API_KEY", ""),
        help="API key (default env BURP_API_KEY)",
    )
    ap.add_argument("--url", action="append", default=[], help="target URL (repeatable)")
    ap.add_argument(
        "--scan-config",
        action="append",
        default=[],
        help='named scan configuration (repeatable), e.g. "Audit checks - light active"',
    )
    ap.add_argument("--username", help="application login username")
    ap.add_argument("--password", help="application login password")
    ap.add_argument("--include", action="append", help="scope include rule (repeatable)")
    ap.add_argument("--exclude", action="append", help="scope exclude rule (repeatable)")
    ap.add_argument("--resource-pool", help="named resource pool")
    ap.add_argument("--task-id", help="poll an existing task instead of starting one")
    ap.add_argument("--no-wait", action="store_true", help="start scan, print task id, exit")
    ap.add_argument("--poll-interval", type=int, default=15, help="seconds between polls")
    ap.add_argument("--timeout", type=int, default=7200, help="max seconds to wait")
    ap.add_argument("-o", "--output", help="merged normalized JSON report file")
    ap.add_argument("--work-units", help="rupu work-units JSON array file")
    ap.add_argument("--findings", help="findings.report payloads JSON array file")
    args = ap.parse_args()

    if not args.api_key:
        sys.exit("[-] API key required (--api-key or BURP_API_KEY)")

    if args.task_id:
        task_id = args.task_id
    else:
        if not args.url:
            sys.exit("[-] at least one --url required (or --task-id to resume)")
        task_id = start_scan(args.base_url, args.api_key, args)
        if args.no_wait:
            print(task_id)
            return

    state = poll_scan(
        args.base_url, args.api_key, task_id, args.poll_interval, args.timeout
    )
    issues = dedupe_issues(state.get("issue_events"))
    report = {
        "task_id": task_id,
        "scan_status": state.get("scan_status", "unknown"),
        "scan_metrics": state.get("scan_metrics", {}),
        "issue_count": len(issues),
        "issues": issues,
    }

    if args.output:
        write_json(args.output, report)
    if args.work_units:
        write_json(args.work_units, build_work_units(issues))
    if args.findings:
        write_json(args.findings, build_findings(issues))
    if not (args.output or args.work_units or args.findings):
        json.dump(report, sys.stdout, indent=2)
        print()

    print(
        "[+] {} unique issues (status: {})".format(
            len(issues), report["scan_status"]
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
