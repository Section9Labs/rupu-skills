#!/usr/bin/env python3
"""merge_urls.py - merge, normalize, dedupe URL lists from crawlers/harvesters.

Accepts any mix of:
  * plain newline-delimited URL lists (waybackurls, gau, katana -silent, uro)
  * katana -jsonl        ({"request":{"endpoint":...}} or {"endpoint":...})
  * hakrawler -json      ({"Source":"href","URL":"..."})
  * gospider --json      ({"output":"...", "type":"url", ...})
  * gau --json           ({"url":"..."})

Normalizes (lowercase scheme/host, strip fragment, drop default ports),
dedupes, optionally reduces uro-style on (host, path, sorted param names),
and splits into: params / paths / static buckets + unique param-name list.

Usage:
  python3 scripts/merge_urls.py katana.jsonl gau.txt wayback.txt \
      --scope example.com --dedupe-params \
      --json merged.json --out-dir inventory/

Output merged.json:
  {"generated": "...", "counts": {...}, "hosts": {...},
   "params": [...], "paths": [...], "static": [...], "param_names": [...]}
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl

STATIC_EXTS = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "bmp", "webp", "avif",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "webm", "avi", "mov", "wav", "ogg",
    "pdf", "zip", "gz", "tar", "rar", "7z",
}
# .js intentionally NOT static: JS files are mined for endpoints downstream.

JSON_URL_KEYS = ("URL", "url", "output", "endpoint")


def extract_url(line):
    """Return URL string from a raw line (plain or any known JSONL dialect)."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            return None
        if not isinstance(obj, dict):
            return None
        # katana -jsonl nests under request.endpoint
        req = obj.get("request")
        if isinstance(req, dict) and req.get("endpoint"):
            return str(req["endpoint"])
        for key in JSON_URL_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and val:
                return val
        return None
    # gospider plain output: "[url] - [code-200] - https://..."
    if line.startswith("["):
        parts = line.split(" - ")
        line = parts[-1].strip()
    # waybackurls -dates: "2020-01-02T03:04:05Z https://..."
    if " http" in line and not line.startswith("http"):
        line = line.split()[-1]
    if line.startswith("http://") or line.startswith("https://"):
        return line
    return None


def normalize(url):
    """Normalize a URL; return None if unparsable."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    port = None
    try:
        port = parts.port
    except ValueError:
        return None
    default = {"http": 80, "https": 443}[parts.scheme]
    netloc = host if (port is None or port == default) else "%s:%d" % (host, port)
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def in_scope(url, scopes):
    if not scopes:
        return True
    host = urlsplit(url).hostname or ""
    for s in scopes:
        s = s.lower().lstrip("*.")
        if host == s or host.endswith("." + s):
            return True
    return False


def param_names(url):
    q = urlsplit(url).query
    if not q:
        return []
    return sorted({k for k, _ in parse_qsl(q, keep_blank_values=True)})


def ext_of(url):
    path = urlsplit(url).path
    base = path.rsplit("/", 1)[-1]
    if "." in base:
        return base.rsplit(".", 1)[-1].lower()
    return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="URL list / JSONL files")
    ap.add_argument("--scope", action="append", default=[],
                    help="in-scope domain (repeatable); subdomains included")
    ap.add_argument("--dedupe-params", action="store_true",
                    help="uro-style: keep one URL per (host, path, param-name set)")
    ap.add_argument("--json", dest="json_out", default="merged.json",
                    help="merged JSON output file (default merged.json)")
    ap.add_argument("--out-dir", default=None,
                    help="also write params.txt/paths.txt/static.txt/param_names.txt/all.txt")
    args = ap.parse_args()

    seen = set()
    urls = []
    read = 0
    for path in args.inputs:
        try:
            fh = sys.stdin if path == "-" else open(path, "r", errors="replace")
        except OSError as e:
            print("[!] skip %s: %s" % (path, e), file=sys.stderr)
            continue
        with fh:
            for line in fh:
                read += 1
                raw = extract_url(line)
                if not raw:
                    continue
                url = normalize(raw)
                if not url or url in seen:
                    continue
                if not in_scope(url, args.scope):
                    continue
                seen.add(url)
                urls.append(url)

    if args.dedupe_params:
        sig_seen, reduced = set(), []
        for url in urls:
            p = urlsplit(url)
            sig = (p.netloc, p.path, tuple(param_names(url)))
            if sig in sig_seen:
                continue
            sig_seen.add(sig)
            reduced.append(url)
        urls = reduced

    params, paths, static = [], [], []
    names = set()
    hosts = {}
    for url in urls:
        p = urlsplit(url)
        hosts.setdefault(p.netloc, 0)
        hosts[p.netloc] += 1
        pn = param_names(url)
        if pn:
            params.append(url)
            names.update(pn)
        elif ext_of(url) in STATIC_EXTS:
            static.append(url)
        else:
            paths.append(url)

    merged = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "lines_read": read,
            "unique_urls": len(urls),
            "params": len(params),
            "paths": len(paths),
            "static": len(static),
            "param_names": len(names),
            "hosts": len(hosts),
        },
        "hosts": {h: {"urls": c} for h, c in sorted(hosts.items())},
        "params": sorted(params),
        "paths": sorted(paths),
        "static": sorted(static),
        "param_names": sorted(names),
    }

    with open(args.json_out, "w") as f:
        json.dump(merged, f, indent=2)
    print("[+] wrote %s (%d unique urls, %d with params, %d param names)"
          % (args.json_out, len(urls), len(params), len(names)), file=sys.stderr)

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        for fname, data in (
            ("params.txt", merged["params"]),
            ("paths.txt", merged["paths"]),
            ("static.txt", merged["static"]),
            ("param_names.txt", merged["param_names"]),
            ("all.txt", sorted(urls)),
        ):
            out = os.path.join(args.out_dir, fname)
            with open(out, "w") as f:
                f.write("\n".join(data) + ("\n" if data else ""))
            print("[+] wrote %s (%d lines)" % (out, len(data)), file=sys.stderr)

    print("[>] next: python3 scripts/urls_to_work_units.py %s "
          "--work-units crawl-units.json --assets assets-marks.json"
          % args.json_out, file=sys.stderr)


if __name__ == "__main__":
    main()
