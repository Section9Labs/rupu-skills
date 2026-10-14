#!/usr/bin/env python3
"""parse_wpscan.py - normalize wpscan -f json output for rupu.

Reads a wpscan JSON report and emits:
  --out        merged/normalized JSON summary
  --work-units rupu work-units ARRAY (one unit per vulnerable component /
               credential-attack opportunity) for `for_each:` / dispatch
  --findings   list of findings.report payloads (scope endpoint)
  --assets     list of assets.mark payloads (web:site / web:route)

Usage:
  python3 scripts/parse_wpscan.py wpscan.json \
      --out merged.json --work-units units.json \
      --findings findings.json --assets assets.json
Only Python 3 standard library. (vulture / ebony-atoll)
"""

import argparse
import json
import re
import sys

CRIT_RE = re.compile(
    r"(remote code execution|rce|object injection|sql injection|sqli|"
    r"authentication bypass|auth bypass|privilege escalation|arbitrary file upload)",
    re.I)
HIGH_RE = re.compile(
    r"(stored xss|local file inclusion|lfi|path traversal|directory traversal|"
    r"arbitrary file (read|download|deletion)|ssrf|csrf.*admin|deserializ)", re.I)
MED_RE = re.compile(
    r"(cross.site scripting|xss|csrf|cross.site request forgery|open redirect|"
    r"idor|broken access)", re.I)
LOW_RE = re.compile(
    r"(information disclosure|info disclosure|user enumeration|full path|"
    r"sensitive data|version disclosure)", re.I)


def severity_for(title):
    t = title or ""
    if CRIT_RE.search(t):
        return "critical" if re.search(r"(rce|remote code|object injection)", t, re.I) else "high"
    if HIGH_RE.search(t):
        return "high"
    if MED_RE.search(t):
        return "medium"
    if LOW_RE.search(t):
        return "low"
    return "medium"


def cwe_for(title):
    t = (title or "").lower()
    table = [
        (r"sql injection|sqli", "CWE-89 / OWASP A03:2021"),
        (r"cross.site scripting|xss", "CWE-79 / OWASP A03:2021"),
        (r"remote code execution|rce|code injection", "CWE-94 / OWASP A03:2021"),
        (r"object injection|deserializ", "CWE-502 / OWASP A08:2021"),
        (r"csrf|cross.site request forgery", "CWE-352 / OWASP A01:2021"),
        (r"file inclusion|lfi|path traversal|directory traversal", "CWE-22 / OWASP A01:2021"),
        (r"file upload", "CWE-434 / OWASP A04:2021"),
        (r"ssrf", "CWE-918 / OWASP A10:2021"),
        (r"authentication bypass|auth bypass", "CWE-287 / OWASP A07:2021"),
        (r"privilege escalation", "CWE-269 / OWASP A01:2021"),
        (r"open redirect", "CWE-601 / OWASP A01:2021"),
        (r"information disclosure|sensitive", "CWE-200 / OWASP A05:2021"),
        (r"user enumeration", "CWE-200 / WSTG-IDNT-04"),
    ]
    for pat, cls in table:
        if re.search(pat, t):
            return cls
    return "CWE-1035 / OWASP A06:2021"  # vulnerable & outdated component


def vuln_refs(vuln):
    refs = vuln.get("references") or {}
    out = []
    for cve in refs.get("cve") or []:
        c = cve if str(cve).upper().startswith("CVE-") else "CVE-%s" % cve
        out.append(c)
    for key in ("url", "wpvulndb", "exploitdb"):
        for r in refs.get(key) or []:
            out.append(str(r))
    return out


def component_vulns(name, kind, obj, base_url):
    """Yield normalized vuln dicts for a plugin/theme/core object."""
    version = None
    if isinstance(obj.get("version"), dict):
        version = obj["version"].get("number")
    elif kind == "core":
        version = obj.get("number")
    for v in obj.get("vulnerabilities") or []:
        yield {
            "component": "%s:%s" % (kind, name),
            "kind": kind,
            "name": name,
            "version": version,
            "title": v.get("title") or "untitled",
            "fixed_in": v.get("fixed_in"),
            "cves": [r for r in vuln_refs(v) if r.startswith("CVE-")],
            "references": vuln_refs(v),
            "severity": severity_for(v.get("title")),
            "classification": cwe_for(v.get("title")),
            "location": obj.get("location") or base_url,
        }


def slugify(s):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", s.lower())).strip("-")[:60]


def main():
    ap = argparse.ArgumentParser(description="normalize wpscan JSON for rupu")
    ap.add_argument("report", help="wpscan -f json output file ('-' for stdin)")
    ap.add_argument("--url", help="override target url")
    ap.add_argument("--out", help="write merged summary JSON here")
    ap.add_argument("--work-units", dest="work_units",
                    help="write rupu work-units JSON array here")
    ap.add_argument("--findings", help="write findings.report payload list here")
    ap.add_argument("--assets", help="write assets.mark payload list here")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.report == "-" else open(
        args.report, "r", encoding="utf-8", errors="replace").read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit("not valid JSON (did you run wpscan with -f json?): %s" % e)

    base_url = (args.url or data.get("effective_url") or
                data.get("target_url") or "").rstrip("/")

    vulns = []
    core = data.get("version") or {}
    if core:
        vulns.extend(component_vulns("wordpress-core", "core", core, base_url))
    for name, obj in (data.get("plugins") or {}).items():
        vulns.extend(component_vulns(name, "plugin", obj or {}, base_url))
    for name, obj in (data.get("themes") or {}).items():
        vulns.extend(component_vulns(name, "theme", obj or {}, base_url))
    mt = data.get("main_theme") or {}
    if mt and mt.get("slug") not in (data.get("themes") or {}):
        vulns.extend(component_vulns(mt.get("slug") or "main-theme",
                                     "theme", mt, base_url))

    users = sorted((data.get("users") or {}).keys())
    interesting = [{
        "url": f.get("url"), "summary": f.get("to_s"),
        "type": f.get("type"),
        "references": (f.get("references") or {}).get("url") or [],
    } for f in data.get("interesting_findings") or []]
    config_backups = sorted((data.get("config_backups") or {}).keys())
    db_exports = sorted((data.get("db_exports") or {}).keys())
    creds = {}
    for user, obj in (data.get("password_attack") or {}).items():
        if isinstance(obj, dict) and obj.get("password"):
            creds[user] = obj["password"]

    merged = {
        "target": base_url,
        "wordpress_version": core.get("number"),
        "version_status": core.get("status"),
        "vulnerabilities": vulns,
        "users": users,
        "interesting_findings": interesting,
        "config_backups": config_backups,
        "db_exports": db_exports,
        "credentials": creds,
    }

    # ---- work units (one per vulnerable component, plus credential attack) --
    units, seen = [], set()
    for v in vulns:
        uid = "wp-%s-%s" % (v["kind"], slugify("%s %s" % (v["name"], v["title"])))
        if uid in seen:
            continue
        seen.add(uid)
        units.append({
            "id": uid,
            "title": "Exploit: %s" % v["title"],
            "targets": [v["location"] or base_url],
            "hints": {
                "cms": "wordpress",
                "component": v["component"],
                "version": v["version"] or "unknown",
                "fixed_in": v["fixed_in"] or "",
                "cves": ",".join(v["cves"]),
                "severity": v["severity"],
                "references": " ".join(v["references"][:5]),
            },
        })
    if users and not creds:
        units.append({
            "id": "wp-credential-attack",
            "title": "Credential attack vs enumerated users (xmlrpc-multicall first)",
            "targets": [base_url + "/xmlrpc.php", base_url + "/wp-login.php"],
            "hints": {"cms": "wordpress", "usernames": ",".join(users),
                      "attack": "xmlrpc-multicall,xmlrpc,wp-login"},
        })
    for b in config_backups + db_exports:
        units.append({
            "id": "wp-backup-" + slugify(b),
            "title": "Retrieve exposed backup/export: %s" % b,
            "targets": [b],
            "hints": {"cms": "wordpress", "type": "exposed-backup"},
        })

    # ---- findings.report payloads ----------------------------------------
    findings = []
    for v in vulns:
        findings.append({
            "title": "%s %s - %s" % (v["component"], v["version"] or "(version unknown)",
                                     v["title"]),
            "scope": "endpoint",
            "target_ref": v["location"] or base_url,
            "severity": v["severity"],
            "classification": v["classification"],
            "evidence": {
                "rationale": ("wpscan identified %s version %s; WPScan DB maps: %s "
                              "(fixed in %s). Confirm manually and attach the "
                              "confirming HTTP exchange before reporting.")
                             % (v["component"], v["version"] or "unknown",
                                v["title"], v["fixed_in"] or "n/a"),
                "http_exchange": "GET %s HTTP/1.1\nHost: %s\n\n<attach wpscan/manual "
                                 "verification exchange>" % (
                                     v["location"] or "/",
                                     base_url.split("://")[-1].split("/")[0]),
                "references": v["references"],
            },
        })
    for b in config_backups + db_exports:
        findings.append({
            "title": "Exposed configuration backup / DB export: %s" % b,
            "scope": "endpoint",
            "target_ref": b,
            "severity": "high",
            "classification": "CWE-530 / OWASP A05:2021",
            "evidence": {"rationale": "wpscan located a readable backup/export in "
                                      "the webroot; typically contains DB credentials "
                                      "and auth keys.",
                         "http_exchange": "GET %s HTTP/1.1\n\n<attach 200 response>" % b,
                         "references": []},
        })
    for user, pw in creds.items():
        findings.append({
            "title": "Valid WordPress credentials recovered: %s" % user,
            "scope": "endpoint",
            "target_ref": base_url + "/wp-login.php",
            "severity": "critical",
            "classification": "CWE-521 / OWASP A07:2021",
            "evidence": {"rationale": "wpscan password attack succeeded: %s:%s. "
                                      "Weak credentials permit admin takeover and RCE "
                                      "via theme/plugin editor." % (user, pw),
                         "http_exchange": "POST /wp-login.php HTTP/1.1\n\n"
                                          "<attach successful login exchange>",
                         "references": []},
        })

    # ---- assets.mark payloads ---------------------------------------------
    depth = "exploited" if creds else "tested"
    assets = [{
        "kind": "web:site",
        "label": "%s (WordPress %s)" % (base_url, core.get("number") or "?"),
        "coordinates": [{"t": "url", "v": base_url}],
        "depth": depth,
    }]
    for route, lbl in (("/wp-login.php", "WordPress login"),
                       ("/xmlrpc.php", "WordPress xmlrpc endpoint")):
        assets.append({
            "kind": "web:route", "label": lbl,
            "coordinates": [{"t": "url", "v": base_url},
                            {"t": "http_route", "v": route}],
            "depth": depth if creds else "tested",
        })
    for f in interesting:
        if f["url"]:
            path = f["url"]
            if path.startswith(base_url):
                path = path[len(base_url):] or "/"
            assets.append({
                "kind": "web:route",
                "label": (f["summary"] or path)[:120],
                "coordinates": [{"t": "url", "v": base_url},
                                {"t": "http_route", "v": path}],
                "depth": "crawled",
            })

    def dump(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        print("wrote %s (%d items)" % (path, len(obj) if isinstance(obj, list) else 1),
              file=sys.stderr)

    if args.out:
        dump(args.out, merged)
    if args.work_units:
        dump(args.work_units, units)
    if args.findings:
        dump(args.findings, findings)
    if args.assets:
        dump(args.assets, assets)
    if not any((args.out, args.work_units, args.findings, args.assets)):
        json.dump(merged, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
