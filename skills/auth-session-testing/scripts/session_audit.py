#!/usr/bin/env python3
"""session_audit.py — grade session cookies and session lifecycle for
auth-session-testing (WSTG-SESS-02/03/06, CWE-384/CWE-614/CWE-1004/CWE-613).

Inputs (any combination):
  --response FILE   raw HTTP response (status line + headers [+ body]); may be
                    given multiple times. Set-Cookie headers are extracted.
  --pairs FILE      JSON describing login/logout exchanges for rotation and
                    invalidation checks. Shape:
                      {
                        "url": "https://example.com/login",
                        "pre_login":  {"set_cookie": ["SESSIONID=aaa; Path=/"]},
                        "post_login": {"set_cookie": ["SESSIONID=aaa; Path=/"]},
                        "post_logout_replay": {"status": 200,
                                               "request": "GET /api/me ...",
                                               "response": "HTTP/1.1 200 ..."}
                      }
  --url URL         target URL for findings/work-units when --pairs lacks one.

Outputs:
  stdout            human summary
  --json FILE       merged machine-readable report
  --work-units FILE rupu work-units JSON array (first char '[') of weaknesses
                    to confirm manually — hand to the `work-units` skill
  --findings FILE   findings.report-shaped payload array (scope endpoint/host,
                    severity, WSTG + CWE, evidence = the offending headers) —
                    finish via the `finding-report` skill

Examples:
  python3 scripts/session_audit.py --response login_resp.txt \
      --url https://example.com/login --json rep.json \
      --work-units wu.json --findings f.json
  python3 scripts/session_audit.py --pairs pairs.json --findings f.json

vulture / sand-atlas
"""

import argparse
import json
import re
import sys

SESSION_NAME_RE = re.compile(
    r"sess|sid$|^sid|token|auth|jwt|login|user|remember|jsession|phpsessid|"
    r"asp\.net|csrftoken|_id$",
    re.I,
)
KNOWN_ATTRS = {"secure", "httponly", "samesite", "path", "domain", "expires",
               "max-age", "priority", "partitioned"}


def parse_set_cookie(line):
    """Parse one Set-Cookie header value into {name, value, attrs}."""
    parts = [p.strip() for p in line.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() if v else True
    return {"name": name.strip(), "value": value.strip(),
            "attrs": attrs, "raw": line.strip()}


def extract_from_response(text):
    """Pull Set-Cookie header values out of a raw HTTP response."""
    cookies = []
    headers_part = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    for line in headers_part.splitlines():
        if line.lower().startswith("set-cookie:"):
            parsed = parse_set_cookie(line.split(":", 1)[1].strip())
            if parsed:
                cookies.append(parsed)
    return cookies, headers_part


def looks_like_session(cookie):
    return bool(SESSION_NAME_RE.search(cookie["name"]))


def grade_cookie(cookie, url, source_excerpt):
    """Return (issues, finding_payloads) for one cookie."""
    issues, findings = [], []
    a = cookie["attrs"]
    is_session = looks_like_session(cookie)
    sev_base = "medium" if is_session else "low"
    name = cookie["name"]

    def finding(title, severity, wstg, cwe, rationale):
        findings.append({
            "title": title,
            "scope": "endpoint",
            "target_ref": url,
            "severity": severity,
            "classification": {"owasp": wstg, "cwe": cwe},
            "evidence": {
                "rationale": rationale,
                "set_cookie_header": cookie["raw"],
                "http_exchange": source_excerpt or "ATTACH-ISSUING-EXCHANGE",
            },
        })

    if "secure" not in a:
        issues.append("missing-Secure")
        finding("Cookie '%s' set without Secure flag" % name, sev_base,
                "WSTG-SESS-02", "CWE-614",
                "The cookie is transmitted over cleartext HTTP channels, "
                "exposing it to on-path interception. Evidence: the Set-Cookie "
                "header issued by the application.")
    if "httponly" not in a:
        issues.append("missing-HttpOnly")
        finding("Cookie '%s' set without HttpOnly flag" % name, sev_base,
                "WSTG-SESS-02", "CWE-1004",
                "The cookie is readable by client-side script; any XSS yields "
                "direct token theft. Evidence: the Set-Cookie header issued by "
                "the application.")
    if "samesite" not in a:
        issues.append("missing-SameSite")
        finding("Cookie '%s' set without SameSite attribute" % name, "low",
                "WSTG-SESS-05", "CWE-1275",
                "Without SameSite the cookie rides on cross-site requests, "
                "easing CSRF. Browsers may default to Lax, but explicit policy "
                "is absent. Evidence: the Set-Cookie header.")
    elif str(a.get("samesite", "")).lower() == "none" and "secure" not in a:
        issues.append("SameSite=None-without-Secure")
    if is_session and ("expires" in a or "max-age" in a):
        issues.append("persistent-session-cookie")
        finding("Session cookie '%s' is persistent (Expires/Max-Age set)" % name,
                "low", "WSTG-SESS-07", "CWE-613",
                "The session cookie survives browser closure, extending the "
                "theft window on shared machines. Evidence: the Set-Cookie "
                "header with its Expires/Max-Age attribute.")
    dom = a.get("domain")
    if isinstance(dom, str) and dom.startswith("."):
        issues.append("broad-Domain-scope(%s)" % dom)
    if is_session and not name.startswith("__Host-"):
        issues.append("no-__Host-prefix")
    # value content: looks decodable / structured?
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", cookie["value"] or ""):
        if cookie["value"].count(".") == 2 and cookie["value"].startswith("eyJ"):
            issues.append("value-is-JWT(run-analyze_jwt.py)")
    if len(cookie["value"] or "") < 16 and is_session:
        issues.append("short-session-id(<16 chars — check entropy, WSTG-SESS-01)")
    unknown = set(a) - KNOWN_ATTRS
    if unknown:
        issues.append("nonstandard-attrs:%s" % ",".join(sorted(unknown)))
    return issues, findings


def audit_pairs(pairs, url):
    """Fixation + lifecycle checks. Returns (notes, findings, work_units)."""
    notes, findings, units = [], [], []
    pre = {c["name"]: c for c in
           (parse_set_cookie(s) for s in pairs.get("pre_login", {}).get("set_cookie", []))
           if c}
    post = {c["name"]: c for c in
            (parse_set_cookie(s) for s in pairs.get("post_login", {}).get("set_cookie", []))
            if c}
    url = pairs.get("url", url)
    host = re.sub(r"^https?://([^/]+).*", r"\1", url) if url else "unknown-host"

    for name, pc in pre.items():
        if not looks_like_session(pc):
            continue
        if name in post and post[name]["value"] == pc["value"]:
            notes.append("FIXATION: '%s' value unchanged across login" % name)
            findings.append({
                "title": "Session fixation: '%s' not rotated on authentication" % name,
                "scope": "endpoint",
                "target_ref": url,
                "severity": "high",
                "classification": {"owasp": "WSTG-SESS-03", "cwe": "CWE-384"},
                "evidence": {
                    "rationale": "The pre-authentication session identifier was "
                    "retained after successful login, so an attacker who plants "
                    "or learns a victim's pre-auth id inherits the authenticated "
                    "session. Evidence: identical Set-Cookie values before and "
                    "after login.",
                    "pre_login_set_cookie": pc["raw"],
                    "post_login_set_cookie": post[name]["raw"],
                    "http_exchange": "ATTACH-LOGIN-EXCHANGE",
                },
            })
        elif name not in post:
            notes.append("SUSPECT-FIXATION: '%s' set pre-login, no new Set-Cookie "
                         "at login — confirm whether the old id stays valid" % name)
            units.append({
                "id": "auth-sess-fixation-%s-%s" % (name, host),
                "title": "Confirm session fixation for cookie '%s'" % name,
                "targets": [url] if url else [],
                "hints": {"mechanism": "session", "attack": "fixation",
                          "cookie": name, "pre_login_value": pc["value"]},
            })
        else:
            notes.append("OK: '%s' rotated on login" % name)

    replay = pairs.get("post_logout_replay")
    if replay:
        status = int(replay.get("status", 0))
        if 200 <= status < 300:
            notes.append("LIFECYCLE: old session replayed AFTER logout -> %d" % status)
            findings.append({
                "title": "Session not invalidated server-side on logout",
                "scope": "endpoint",
                "target_ref": url,
                "severity": "medium",
                "classification": {"owasp": "WSTG-SESS-06", "cwe": "CWE-613"},
                "evidence": {
                    "rationale": "An authenticated request replayed with the "
                    "pre-logout session token still succeeded (HTTP %d), proving "
                    "logout only clears the client. A stolen token remains "
                    "usable after the victim logs out." % status,
                    "http_exchange": "%s\n\n%s" % (
                        replay.get("request", "ATTACH-REQUEST"),
                        replay.get("response", "ATTACH-RESPONSE")),
                },
            })
        else:
            notes.append("OK: post-logout replay rejected (%d)" % status)
    return notes, findings, units


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--response", action="append", default=[],
                    help="raw HTTP response file (repeatable)")
    ap.add_argument("--pairs", help="JSON of login/logout exchanges")
    ap.add_argument("--url", default="", help="target URL for findings/units")
    ap.add_argument("--json", dest="json_out", help="merged report JSON")
    ap.add_argument("--work-units", help="rupu work-units array output")
    ap.add_argument("--findings", help="findings.report payload array output")
    args = ap.parse_args()

    if not args.response and not args.pairs:
        ap.error("need at least one --response or --pairs")

    url = args.url or "SET-TARGET-URL"
    all_cookies, all_findings, all_units, notes = [], [], [], []

    for path in args.response:
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError as exc:
            print("[!] cannot read %s: %s" % (path, exc), file=sys.stderr)
            continue
        cookies, excerpt = extract_from_response(text)
        if not cookies:
            notes.append("%s: no Set-Cookie headers found" % path)
        for c in cookies:
            issues, findings = grade_cookie(c, url, excerpt)
            c["session_like"] = looks_like_session(c)
            c["issues"] = issues
            c["source"] = path
            all_cookies.append(c)
            all_findings.extend(findings)
            for issue in issues:
                if issue.startswith(("value-is-JWT", "short-session-id")):
                    host = re.sub(r"^https?://([^/]+).*", r"\1", url)
                    all_units.append({
                        "id": "auth-sess-%s-%s-%s"
                              % (issue.split("(")[0], c["name"], host),
                        "title": "Follow up '%s' on cookie %s" % (issue, c["name"]),
                        "targets": [url] if args.url else [],
                        "hints": {"mechanism": "session", "cookie": c["name"],
                                  "issue": issue, "value": c["value"]},
                    })

    if args.pairs:
        try:
            with open(args.pairs) as fh:
                pairs = json.load(fh)
        except (OSError, ValueError) as exc:
            print("[!] cannot parse %s: %s" % (args.pairs, exc), file=sys.stderr)
            sys.exit(2)
        pnotes, pfindings, punits = audit_pairs(pairs, url)
        notes.extend(pnotes)
        all_findings.extend(pfindings)
        all_units.extend(punits)

    report = {"url": url, "cookies": all_cookies, "notes": notes,
              "finding_payloads": all_findings, "work_units": all_units}

    print("=== session audit: %s ===" % url)
    for c in all_cookies:
        tag = "SESSION" if c["session_like"] else "cookie "
        print("[%s] %s  issues: %s"
              % (tag, c["name"], ", ".join(c["issues"]) or "none"))
    for n in notes:
        print(" - %s" % n)
    print("--- %d finding payload(s), %d work unit(s) ---"
          % (len(all_findings), len(all_units)))

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(report, fh, indent=2)
        print("[+] report -> %s" % args.json_out)
    if args.work_units:
        with open(args.work_units, "w") as fh:
            json.dump(all_units, fh, indent=2)
        print("[+] work units -> %s (feed to the work-units skill / for_each)"
              % args.work_units)
    if args.findings:
        with open(args.findings, "w") as fh:
            json.dump(all_findings, fh, indent=2)
        print("[+] finding payloads -> %s (submit via findings.report / "
              "finding-report skill; replace ATTACH-* placeholders with the real "
              "exchanges first)" % args.findings)


if __name__ == "__main__":
    main()
