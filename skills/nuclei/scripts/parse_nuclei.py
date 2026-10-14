#!/usr/bin/env python3
"""parse_nuclei.py — normalize nuclei JSONL output for rupu ingestion.

Reads one or more nuclei JSON Lines files (produced with `nuclei -jsonl` /
`-je file.jsonl`), normalizes each match to:

    {template_id, name, severity, matched_at, cve, cwe, tags, host}

dedupes on (template_id, matched_at), and can emit:

  --merged out.json       merged normalized matches (JSON array)
  --work-units out.json   rupu work-units array: one unit per non-info match
                          that needs manual confirmation
  --findings out.json     findings.report payload array (scope endpoint,
                          target_ref=matched_at, HTTP exchange in evidence,
                          CWE classification, CVE references)
  --assets out.json       assets.mark payload array (web:site + web:route,
                          depth tested)

Usage:
  python3 scripts/parse_nuclei.py nuclei.jsonl [tech.jsonl ...] \
      --merged merged.json --work-units units.json \
      --findings findings.json --assets assets.json \
      [--min-severity low] [--include-info-units]

Signed-off: vulture (crew graphite-pavilion)
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def map_severity(sev):
    """Map nuclei severity to rupu severity (info|low|medium|high|critical)."""
    sev = (sev or "").strip().lower()
    return sev if sev in SEVERITY_ORDER else "info"


def first_or_str(value):
    """nuclei classification fields may be a string or a list of strings."""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    if value is None:
        return ""
    return str(value)


def listify(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return []
    return [s.strip() for s in str(value).split(",") if s.strip()]


def slug(text):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


def read_jsonl(paths):
    """Yield parsed objects from JSONL files; tolerate blank/garbage lines."""
    for path in paths:
        try:
            fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            print("[!] cannot open %s: %s" % (path, exc), file=sys.stderr)
            continue
        try:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    print("[!] %s:%d: not JSON, skipped" % (path, lineno), file=sys.stderr)
                    continue
                if isinstance(obj, dict):
                    yield obj
                elif isinstance(obj, list):  # someone fed a JSON array file
                    for item in obj:
                        if isinstance(item, dict):
                            yield item
        finally:
            if fh is not sys.stdin:
                fh.close()


def normalize(obj):
    """Normalize one nuclei JSONL object; return None if it is not a match."""
    template_id = obj.get("template-id") or obj.get("template_id") or ""
    matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""
    if not template_id or not matched_at:
        return None
    info = obj.get("info") or {}
    cls = info.get("classification") or {}
    cve = first_or_str(cls.get("cve-id")).upper()
    cwe = first_or_str(cls.get("cwe-id")).upper()
    return {
        "template_id": template_id,
        "name": info.get("name") or template_id,
        "severity": map_severity(info.get("severity")),
        "matched_at": matched_at,
        "cve": cve,
        "cwe": cwe,
        "tags": listify(info.get("tags")),
        "host": obj.get("host") or matched_at,
        "description": info.get("description") or "",
        "references": listify(info.get("reference")),
        "extracted_results": listify(obj.get("extracted-results")),
        "matcher_name": obj.get("matcher-name") or "",
        "curl_command": obj.get("curl-command") or "",
        "request": obj.get("request") or "",
        "response": obj.get("response") or "",
        "ip": obj.get("ip") or "",
        "timestamp": obj.get("timestamp") or "",
        "type": obj.get("type") or "http",
    }


def dedupe(matches):
    seen = {}
    for m in matches:
        key = (m["template_id"], m["matched_at"])
        if key not in seen:
            seen[key] = m
        else:
            # keep extracted results from duplicates (multi-matcher templates)
            prev = seen[key]
            for extra in m["extracted_results"]:
                if extra not in prev["extracted_results"]:
                    prev["extracted_results"].append(extra)
    return list(seen.values())


def site_of(url):
    parts = urlsplit(url if "://" in url else "http://" + url)
    netloc = parts.netloc or parts.path.split("/")[0]
    scheme = parts.scheme or "http"
    return "%s://%s" % (scheme, netloc)


def route_of(url):
    parts = urlsplit(url if "://" in url else "http://" + url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return path


def make_work_units(matches, include_info=False):
    units = []
    for m in matches:
        if not include_info and m["severity"] == "info":
            continue
        units.append({
            "id": "%s:%s" % (m["template_id"], slug(m["matched_at"])),
            "title": m["name"],
            "targets": [m["matched_at"]],
            "hints": {
                "severity": m["severity"],
                "cve": m["cve"],
                "cwe": m["cwe"],
                "tags": ",".join(m["tags"]),
                "template_id": m["template_id"],
                "matcher_name": m["matcher_name"],
                "curl_command": m["curl_command"],
            },
        })
    return units


def make_findings(matches):
    payloads = []
    for m in matches:
        if m["severity"] == "info":
            continue  # tech-detect / informational lines route targets, not findings
        bits = ["nuclei template %s matched at %s." % (m["template_id"], m["matched_at"])]
        if m["description"]:
            bits.append(m["description"].strip())
        if m["matcher_name"]:
            bits.append("Matcher fired: %s." % m["matcher_name"])
        if m["extracted_results"]:
            bits.append("Extracted: %s." % ", ".join(m["extracted_results"][:10]))
        if m["cve"]:
            bits.append("Classification: %s%s." % (m["cve"], (" / " + m["cwe"]) if m["cwe"] else ""))
        elif m["cwe"]:
            bits.append("Classification: %s." % m["cwe"])
        refs = list(m["references"])
        if m["cve"] and not any(m["cve"].lower() in r.lower() for r in refs):
            refs.insert(0, "https://nvd.nist.gov/vuln/detail/%s" % m["cve"])
        title = m["name"]
        if m["cve"] and m["cve"] not in title:
            title = "%s (%s)" % (title, m["cve"])
        payloads.append({
            "scope": "endpoint",
            "target_ref": m["matched_at"],
            "title": title,
            "severity": m["severity"],
            "classification": m["cwe"] or m["cve"] or "OWASP-WSTG",
            "evidence": {
                "rationale": " ".join(bits),
                "request": m["request"],
                "response": m["response"],
            },
            "references": refs,
        })
    return payloads


def make_assets(matches, depth="tested"):
    assets = []
    seen_sites = set()
    seen_routes = set()
    for m in matches:
        site = site_of(m["matched_at"])
        if site not in seen_sites:
            seen_sites.add(site)
            assets.append({
                "kind": "web:site",
                "coordinates": [{"t": "url", "v": site}],
                "label": site,
                "depth": depth,
            })
        route = route_of(m["matched_at"])
        rkey = (site, route)
        if rkey not in seen_routes:
            seen_routes.add(rkey)
            assets.append({
                "kind": "web:route",
                "coordinates": [
                    {"t": "url", "v": site},
                    {"t": "http_route", "v": route},
                ],
                "label": "nuclei: %s @ %s" % (m["template_id"], route),
                "depth": depth,
            })
    return assets


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print("[+] wrote %d entries -> %s" % (len(data), path), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Normalize nuclei JSONL for rupu.")
    ap.add_argument("jsonl", nargs="+", help="nuclei JSONL file(s); '-' for stdin")
    ap.add_argument("--merged", help="write merged normalized matches (JSON array)")
    ap.add_argument("--work-units", help="write rupu work-units array")
    ap.add_argument("--findings", help="write findings.report payload array")
    ap.add_argument("--assets", help="write assets.mark payload array")
    ap.add_argument("--min-severity", default="info",
                    choices=["info", "low", "medium", "high", "critical"],
                    help="drop matches below this severity (default: keep all)")
    ap.add_argument("--include-info-units", action="store_true",
                    help="include info-severity matches in the work-units array")
    ap.add_argument("--asset-depth", default="tested",
                    choices=["mapped", "crawled", "tested", "exploited"],
                    help="depth to record on assets (default: tested)")
    args = ap.parse_args()

    matches = dedupe(m for m in (normalize(o) for o in read_jsonl(args.jsonl)) if m)
    floor = SEVERITY_ORDER[args.min_severity]
    matches = [m for m in matches if SEVERITY_ORDER[m["severity"]] >= floor]
    matches.sort(key=lambda m: (-SEVERITY_ORDER[m["severity"]], m["template_id"], m["matched_at"]))

    counts = {}
    for m in matches:
        counts[m["severity"]] = counts.get(m["severity"], 0) + 1
    print("[*] %d unique matches: %s" % (
        len(matches),
        ", ".join("%s=%d" % (s, counts[s]) for s in ("critical", "high", "medium", "low", "info") if s in counts) or "none",
    ), file=sys.stderr)

    if args.merged:
        write_json(args.merged, matches)
    if args.work_units:
        write_json(args.work_units, make_work_units(matches, args.include_info_units))
    if args.findings:
        write_json(args.findings, make_findings(matches))
    if args.assets:
        write_json(args.assets, make_assets(matches, args.asset_depth))
    if not any([args.merged, args.work_units, args.findings, args.assets]):
        json.dump(matches, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
