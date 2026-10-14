#!/usr/bin/env python3
"""parse_kr.py - normalize kiterunner output into endpoints + rupu work units.

Reads `kr scan`/`kr brute` output. Prefers `-o json` (one JSON object per
line; a JSON array also works) and falls back to parsing pretty/text lines:

    GET     403 [    218,   10,    1] https://api.example.com/v1/admin/users 0cc39f...

Emits:
  * --endpoints FILE : deduped JSON array of
        {"method","path","url","status","length","host"}
  * -o FILE          : JSON array of work units grouped per first path
        segment (resource), written atomically, suitable for a rupu
        `for_each: "{{ read_file('reports/api-units.json') }}"` fan-out:
        [{"id","title","targets","hints"}, ...]

Usage:
    python3 scripts/parse_kr.py kr-api.json -o reports/api-units.json \
        --endpoints reports/api-endpoints.json
    kr scan https://api.example.com -w routes-large.kite -o json | \
        python3 scripts/parse_kr.py - -o reports/api-units.json

Only Python 3 standard library is used.
"""

import argparse
import json
import os
import re
import sys
import tempfile
from urllib.parse import urlsplit

MAX_TARGET_LEN = 300      # cap raw strings inside unit targets
MAX_TARGETS_PER_UNIT = 50

PRETTY_RE = re.compile(
    r"^\s*(?P<method>[A-Z]+)\s+(?P<status>\d{3})\s+"
    r"\[\s*(?P<length>\d+),\s*\d+,\s*\d+\s*\]\s+"
    r"(?P<url>https?://\S+)"
)

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}


def _first(d, keys, default=None):
    """Return the first present, non-None value among possible key names."""
    for k in keys:
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return default


def _norm_record(method, url, status, length):
    try:
        parts = urlsplit(str(url))
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    path = parts.path or "/"
    method = str(method or "GET").upper()
    if method not in METHODS:
        method = "GET"
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0
    try:
        length = int(length)
    except (TypeError, ValueError):
        length = -1
    host = "%s://%s" % (parts.scheme, parts.netloc)
    return {
        "method": method,
        "path": path,
        "url": "%s%s" % (host, path),
        "status": status,
        "length": length,
        "host": host,
    }


def _from_json_obj(obj):
    """Map one kr JSON result object to a record; key names vary by release."""
    if not isinstance(obj, dict):
        return None
    url = _first(obj, ("url", "full_url", "target", "uri"))
    method = _first(obj, ("method", "verb", "http_method"), "GET")
    status = _first(obj, ("status", "status_code", "response_status", "code"), 0)
    length = _first(obj, ("length", "content_length", "response_length",
                          "body_length", "size"), -1)
    # Some releases nest route/host info.
    if url is None:
        route = obj.get("route") or {}
        host = _first(obj, ("host", "origin")) or _first(route, ("host",))
        path = _first(route, ("path", "route", "uri")) or _first(obj, ("path",))
        if host and path:
            if not str(host).startswith("http"):
                host = "https://" + str(host)
            url = str(host).rstrip("/") + "/" + str(path).lstrip("/")
            method = _first(route, ("method", "verb"), method)
    if url is None:
        return None
    return _norm_record(method, url, status, length)


def parse_stream(lines):
    records = []
    buf = []
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped:
            continue
        # Whole-array input: accumulate and try at the end.
        if stripped.startswith("[") or buf:
            buf.append(line)
            continue
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
            except ValueError:
                continue
            rec = _from_json_obj(obj)
            if rec:
                records.append(rec)
            continue
        m = PRETTY_RE.match(line)
        if m:
            rec = _norm_record(m.group("method"), m.group("url"),
                               m.group("status"), m.group("length"))
            if rec:
                records.append(rec)
    if buf:
        try:
            arr = json.loads("\n".join(buf))
            if isinstance(arr, list):
                for obj in arr:
                    rec = _from_json_obj(obj)
                    if rec:
                        records.append(rec)
        except ValueError:
            pass
    # Dedupe on (method, url), keep the first-seen status/length.
    seen = {}
    for rec in records:
        key = (rec["method"], rec["url"])
        if key not in seen:
            seen[key] = rec
    return list(seen.values())


def resource_key(path):
    segs = [s for s in path.split("/") if s]
    return segs[0] if segs else "root"


def build_units(records):
    groups = {}
    for rec in records:
        key = "%s %s" % (rec["host"], resource_key(rec["path"]))
        groups.setdefault(key, []).append(rec)
    units = []
    for idx, key in enumerate(sorted(groups), start=1):
        recs = groups[key]
        host, res = key.rsplit(" ", 1)
        targets = []
        statuses = set()
        for rec in sorted(recs, key=lambda r: (r["path"], r["method"])):
            t = "%s %s" % (rec["method"], rec["url"])
            targets.append(t[:MAX_TARGET_LEN])
            statuses.add(rec["status"])
            if len(targets) >= MAX_TARGETS_PER_UNIT:
                break
        # hints from a fixed vocabulary only -- never from response data
        hints = sorted("status:%d" % s for s in statuses)
        if any(s in (401, 403) for s in statuses):
            hints.append("probe-auth")
        if any(200 <= s < 300 for s in statuses):
            hints.append("fuzz-params")
        if 405 in statuses:
            hints.append("try-other-verbs")
        safe_res = re.sub(r"[^a-zA-Z0-9_-]", "-", res)[:40] or "root"
        units.append({
            "id": "api-ep-%03d" % idx,
            "title": "api resource: %s" % safe_res,
            "targets": targets,
            "hints": hints,
        })
    return units


def atomic_write_json(path, data):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main():
    ap = argparse.ArgumentParser(
        description="Normalize kiterunner output into endpoints and rupu "
                    "work units.")
    ap.add_argument("input", help="kr output file (json/text/pretty), or - "
                                  "for stdin")
    ap.add_argument("-o", "--output", default="reports/api-units.json",
                    help="work-units JSON array path (atomic write) "
                         "[default: %(default)s]")
    ap.add_argument("--endpoints", default=None,
                    help="also write a deduped normalized endpoint list here")
    args = ap.parse_args()

    if args.input == "-":
        records = parse_stream(sys.stdin)
    else:
        with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
            records = parse_stream(fh)

    if not records:
        print("[parse_kr] no results parsed from %s" % args.input,
              file=sys.stderr)

    if args.endpoints:
        atomic_write_json(args.endpoints, records)
        print("[parse_kr] %d endpoints -> %s" % (len(records), args.endpoints))

    units = build_units(records)
    atomic_write_json(args.output, units)
    print("[parse_kr] %d work units -> %s" % (len(units), args.output))

    # Summary to stderr for the operator.
    by_status = {}
    for rec in records:
        by_status[rec["status"]] = by_status.get(rec["status"], 0) + 1
    for status in sorted(by_status):
        print("[parse_kr]   status %s: %d" % (status, by_status[status]),
              file=sys.stderr)


if __name__ == "__main__":
    main()
