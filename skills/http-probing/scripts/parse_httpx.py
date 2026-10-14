#!/usr/bin/env python3
"""parse_httpx.py — normalize httpx (ProjectDiscovery) JSON Lines output.

Reads httpx -json output (JSONL) from a file or stdin, normalizes to one
record per live endpoint, and emits:
  * a flat normalized JSON array        (-o endpoints.json, or stdout)
  * a rupu work-units JSON array        (--work-units units.json)
  * a plain list of live URLs           (--urls live_urls.txt)

Usage:
  python3 scripts/parse_httpx.py httpx.jsonl -o endpoints.json \
      --work-units units.json --urls live_urls.txt
  cat httpx.jsonl | python3 scripts/parse_httpx.py - -o endpoints.json

The work-units array is rupu for_each-ready: first character is '[', each
element {"id","title","targets":[url],"hints":{...}}. Hand it to the
`work-units` skill for normalization before dispatch.

-- vulture (onyx-island)
"""

import argparse
import hashlib
import json
import sys


def _as_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _tech_list(raw):
    """httpx tech entries may be 'Name' or 'Name:version'; keep as-is but
    de-duplicate while preserving order."""
    seen, out = set(), []
    for t in raw or []:
        if isinstance(t, str) and t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def normalize_line(obj):
    """Map one httpx JSONL object to the normalized endpoint record.
    Returns None for failed probes (lines emitted by -probe with failed=true)
    or lines missing a URL."""
    if obj.get("failed") is True:
        return None
    url = obj.get("url")
    if not url:
        return None
    rec = {
        "url": url,
        "input": obj.get("input"),
        "host": obj.get("input") or url,
        "ip": obj.get("host"),  # httpx 'host' field = resolved IP
        "a": obj.get("a") or [],
        "cname": obj.get("cname") or [],
        "port": _as_int(obj.get("port")),
        "scheme": obj.get("scheme"),
        "status": _as_int(obj.get("status_code")),
        "title": obj.get("title") or "",
        "server": obj.get("webserver") or "",
        "tech": _tech_list(obj.get("tech")),
        "content_length": _as_int(obj.get("content_length")),
        "content_type": obj.get("content_type"),
        "cdn": bool(obj.get("cdn")),
        "cdn_name": obj.get("cdn_name") or "",
        "location": obj.get("location") or "",
        "final_url": obj.get("final_url") or "",
        "favicon": obj.get("favicon") or "",
        "jarm": obj.get("jarm") or "",
        "body_sha256": (obj.get("hash") or {}).get("body_sha256", "")
        if isinstance(obj.get("hash"), dict)
        else "",
    }
    return rec


def parse_stream(fh):
    endpoints, seen_urls = [], set()
    errors = 0
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        rec = normalize_line(obj)
        if rec is None or rec["url"] in seen_urls:
            continue
        seen_urls.add(rec["url"])
        endpoints.append(rec)
    if errors:
        print("[parse_httpx] skipped %d unparseable lines" % errors,
              file=sys.stderr)
    return endpoints


def unit_id(url):
    return "site-" + hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]


def to_work_units(endpoints):
    units = []
    for ep in endpoints:
        title = ep["title"] or ep["url"]
        if ep["title"]:
            title = "%s — %s" % (ep["title"], ep["url"])
        hints = {
            "tech": ep["tech"],
            "status": ep["status"],
            "server": ep["server"],
        }
        if ep.get("ip"):
            hints["ip"] = ep["ip"]
        if ep.get("cdn"):
            hints["cdn"] = ep.get("cdn_name") or "unknown"
        if ep.get("title"):
            hints["title"] = ep["title"]
        if ep.get("final_url") and ep["final_url"] != ep["url"]:
            hints["final_url"] = ep["final_url"]
        units.append(
            {
                "id": unit_id(ep["url"]),
                "title": title,
                "targets": [ep["url"]],
                "hints": hints,
            }
        )
    return units


def main():
    ap = argparse.ArgumentParser(
        description="Normalize httpx JSONL into endpoints / rupu work units."
    )
    ap.add_argument("jsonl", nargs="?", default="-",
                    help="httpx -json output file, or '-' for stdin (default)")
    ap.add_argument("-o", "--output",
                    help="write normalized endpoint JSON array here "
                         "(default: stdout)")
    ap.add_argument("--work-units", metavar="FILE",
                    help="write rupu work-units JSON array here")
    ap.add_argument("--urls", metavar="FILE",
                    help="write plain newline list of live URLs here")
    args = ap.parse_args()

    if args.jsonl == "-":
        endpoints = parse_stream(sys.stdin)
    else:
        with open(args.jsonl, "r", encoding="utf-8", errors="replace") as fh:
            endpoints = parse_stream(fh)

    normalized = json.dumps(endpoints, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(normalized + "\n")
        print("[parse_httpx] %d endpoints -> %s" % (len(endpoints),
                                                    args.output),
              file=sys.stderr)
    else:
        print(normalized)

    if args.work_units:
        units = to_work_units(endpoints)
        with open(args.work_units, "w", encoding="utf-8") as fh:
            # Must be a clean JSON array: first character '[' so rupu
            # for_each / a lead agent can parse and fan out.
            json.dump(units, fh, indent=2)
            fh.write("\n")
        print("[parse_httpx] %d work units -> %s" % (len(units),
                                                     args.work_units),
              file=sys.stderr)

    if args.urls:
        with open(args.urls, "w", encoding="utf-8") as fh:
            for ep in endpoints:
                fh.write(ep["url"] + "\n")
        print("[parse_httpx] %d urls -> %s" % (len(endpoints), args.urls),
              file=sys.stderr)


if __name__ == "__main__":
    main()
