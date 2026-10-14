#!/usr/bin/env python3
"""httpx_to_assets.py — turn normalized endpoints into rupu assets.mark payloads.

Reads the normalized endpoint JSON array produced by parse_httpx.py (or raw
httpx JSONL with --jsonl) and prints one assets.mark argument object per live
endpoint: kind web:site, coordinates [{"t":"url","v":<url>}], depth mapped,
label "<url> [status] <title> (<server>)".

Usage:
  python3 scripts/httpx_to_assets.py endpoints.json
  python3 scripts/httpx_to_assets.py --jsonl httpx.jsonl
  python3 scripts/httpx_to_assets.py endpoints.json --array -o assets.json
  cat endpoints.json | python3 scripts/httpx_to_assets.py -

Default output is one JSON object per line (feed each to the assets.mark
tool); --array wraps them in a single JSON array.

-- vulture (onyx-island)
"""

import argparse
import json
import sys


def load_endpoints(path, jsonl):
    if path == "-":
        data = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    if jsonl:
        endpoints = []
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("failed") is True or not obj.get("url"):
                continue
            endpoints.append(
                {
                    "url": obj["url"],
                    "status": obj.get("status_code"),
                    "title": obj.get("title") or "",
                    "server": obj.get("webserver") or "",
                    "tech": obj.get("tech") or [],
                }
            )
        return endpoints
    parsed = json.loads(data)
    if not isinstance(parsed, list):
        raise SystemExit("expected a JSON array (parse_httpx.py -o output)")
    return parsed


def make_label(ep):
    parts = [ep.get("url", "")]
    status = ep.get("status")
    if status is not None:
        parts.append("[%s]" % status)
    if ep.get("title"):
        parts.append(ep["title"])
    extras = []
    if ep.get("server"):
        extras.append(ep["server"])
    tech = ep.get("tech") or []
    if tech:
        extras.append(", ".join(tech[:5]))
    if extras:
        parts.append("(%s)" % "; ".join(extras))
    return " ".join(p for p in parts if p)


def to_asset(ep):
    return {
        "kind": "web:site",
        "coordinates": [{"t": "url", "v": ep["url"]}],
        "depth": "mapped",
        "label": make_label(ep),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Emit rupu assets.mark payloads (web:site @ mapped) for "
                    "live endpoints."
    )
    ap.add_argument("endpoints", nargs="?", default="-",
                    help="normalized endpoints JSON array from parse_httpx.py,"
                         " or '-' for stdin (default)")
    ap.add_argument("--jsonl", action="store_true",
                    help="input is raw httpx -json JSONL instead of the "
                         "normalized array")
    ap.add_argument("--array", action="store_true",
                    help="emit one JSON array instead of one object per line")
    ap.add_argument("-o", "--output",
                    help="write to file instead of stdout")
    args = ap.parse_args()

    endpoints = load_endpoints(args.endpoints, args.jsonl)
    assets = [to_asset(ep) for ep in endpoints if ep.get("url")]

    if args.array:
        text = json.dumps(assets, indent=2) + "\n"
    else:
        text = "".join(json.dumps(a) + "\n" for a in assets)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("[httpx_to_assets] %d assets.mark payloads -> %s"
              % (len(assets), args.output), file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
