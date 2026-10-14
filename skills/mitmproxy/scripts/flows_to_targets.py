#!/usr/bin/env python3
"""flows_to_targets.py — normalize captured mitmproxy traffic into rupu outputs.

Pure Python 3 stdlib; runs standalone (no mitmproxy required).

Inputs (any mix, auto-detected per file; '-' = stdin treated as URL list):
  * harvest JSONL written by scripts/harvest_addon.py (one JSON object per line)
  * HAR files (mitmweb export, browser DevTools, `--set hardump=`)
  * plain newline-separated URL lists (gau/katana/waybackurls style)

Outputs:
  * -o endpoints.json   merged, deduplicated endpoint records
                        {"method","url","host","path","params",...}
  * --urls urls.txt     one full URL (with query) per endpoint — dalfox/ffuf food
  * --work-units wu.json  JSON ARRAY (first char '[') of work units
                        {"id","title","targets":[...],"hints":{...}} for rupu
                        for_each:/dispatch — hand to the `work-units` skill
  * --assets assets.json  JSON array of assets.mark payloads (web:site/web:route)
                        — record via the `coverage-assets` skill

Examples:
  python3 scripts/flows_to_targets.py harvest.jsonl -o endpoints.json \
      --work-units wu.json --assets assets.json --depth crawled
  python3 scripts/flows_to_targets.py capture.har urls.txt --urls all-urls.txt
  cat urls.txt | python3 scripts/flows_to_targets.py - --work-units wu.json --depth mapped

-- vulture (wine-crag)
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl, urlencode

STATIC_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map|mp4|webm)$", re.I
)


def norm_record(method, url, extra_params=None, status=None, ctype=None, req_ctype=None):
    """Build a normalized endpoint record from a method+URL (+ body params)."""
    try:
        sp = urlsplit(url.strip())
    except ValueError:
        return None
    if sp.scheme not in ("http", "https") or not sp.netloc:
        return None
    path = sp.path or "/"
    qparams = dict(parse_qsl(sp.query, keep_blank_values=True))
    params = dict(qparams)
    if extra_params:
        params.update(extra_params)
    host = sp.hostname or ""
    port = sp.port
    default = (sp.scheme == "http" and port in (None, 80)) or (
        sp.scheme == "https" and port in (None, 443)
    )
    netloc = host if default else "%s:%s" % (host, port)
    base = "%s://%s" % (sp.scheme, netloc)
    full = base + path + (("?" + urlencode(sorted(qparams.items()))) if qparams else "")
    return {
        "method": (method or "GET").upper(),
        "url": full,
        "site": base,
        "host": host,
        "scheme": sp.scheme,
        "path": path,
        "params": sorted(params.keys()),
        "query_params": sorted(qparams.keys()),
        "body_params": sorted((extra_params or {}).keys()),
        "example_values": {k: str(v)[:200] for k, v in params.items()},
        "status": status,
        "ctype": ctype,
        "req_ctype": req_ctype,
    }


def parse_harvest_line(obj):
    extra = {}
    extra.update(obj.get("form") or {})
    for k in obj.get("json_keys") or []:
        extra.setdefault(k, "")
    return norm_record(
        obj.get("method"), obj.get("url", ""), extra,
        status=obj.get("status"), ctype=obj.get("ctype"),
        req_ctype=obj.get("req_ctype"),
    )


def parse_har(doc):
    out = []
    for entry in (doc.get("log") or {}).get("entries", []):
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        extra = {}
        post = req.get("postData") or {}
        for p in post.get("params") or []:
            if p.get("name"):
                extra[p["name"]] = p.get("value", "")
        if not extra and "json" in (post.get("mimeType") or ""):
            try:
                body = json.loads(post.get("text") or "")
                if isinstance(body, dict):
                    extra = {k: "" for k in body}
            except ValueError:
                pass
        ctype = ""
        for h in resp.get("headers") or []:
            if h.get("name", "").lower() == "content-type":
                ctype = h.get("value", "").split(";")[0].strip()
        rec = norm_record(
            req.get("method"), req.get("url", ""), extra,
            status=resp.get("status"), ctype=ctype or None,
            req_ctype=(post.get("mimeType") or "").split(";")[0] or None,
        )
        if rec:
            out.append(rec)
    return out


def load_input(path):
    """Auto-detect harvest JSONL / HAR / URL list; return list of records."""
    data = sys.stdin.read() if path == "-" else open(path, encoding="utf-8", errors="replace").read()
    text = data.strip()
    if not text:
        return []
    # HAR: a single JSON document with log.entries
    if text[0] == "{":
        try:
            doc = json.loads(text)
            if isinstance(doc, dict) and "log" in doc:
                return parse_har(doc)
        except ValueError:
            pass
    recs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] == "{":
            try:
                rec = parse_harvest_line(json.loads(line))
            except ValueError:
                rec = None
        else:
            rec = norm_record("GET", line)
        if rec:
            recs.append(rec)
    return recs


def dedupe(records, drop_static=True):
    merged = {}
    for r in records:
        if r is None:
            continue
        if drop_static and STATIC_EXT.search(r["path"]) and not r["params"]:
            continue
        key = (r["method"], r["site"], r["path"], tuple(r["params"]))
        if key in merged:
            m = merged[key]
            if r.get("status") and not m.get("status"):
                m["status"] = r["status"]
            for k, v in r["example_values"].items():
                m["example_values"].setdefault(k, v)
        else:
            merged[key] = r
    return list(merged.values())


def slug(s, maxlen=80):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:maxlen] or "root"


def work_units(records):
    units, seen = [], set()
    for r in sorted(records, key=lambda x: (x["site"], x["path"], x["method"])):
        uid = slug("%s-%s-%s" % (r["method"], r["host"], r["path"]))
        n, base = 2, uid
        while uid in seen:
            uid, n = "%s-%d" % (base, n), n + 1
        seen.add(uid)
        ptxt = ",".join(r["params"])
        hints = {
            "method": r["method"],
            "host": r["host"],
            "path": r["path"],
            "params": ptxt,
            "source": "mitmproxy-harvest",
        }
        if r.get("req_ctype"):
            hints["content_type"] = str(r["req_ctype"])
        if r.get("status") is not None:
            hints["status_seen"] = str(r["status"])
        units.append({
            "id": uid,
            "title": "%s %s%s" % (r["method"], r["url"],
                                  " (params: %s)" % ptxt if ptxt else ""),
            "targets": [r["url"]],
            "hints": hints,
        })
    return units


def asset_payloads(records, depth):
    payloads, seen = [], set()
    for r in sorted(records, key=lambda x: (x["site"], x["path"])):
        if r["site"] not in seen:
            seen.add(r["site"])
            payloads.append({
                "kind": "web:site",
                "label": r["site"],
                "coordinates": [{"t": "url", "v": r["site"]}],
                "depth": depth,
            })
        params = r["params"] or [None]
        for p in params:
            coords = [{"t": "url", "v": r["site"]},
                      {"t": "http_route", "v": r["path"]}]
            label = "%s %s" % (r["method"], r["path"])
            rkey = (r["site"], r["path"], p)
            if rkey in seen:
                continue
            seen.add(rkey)
            if p:
                coords.append({"t": "param", "v": p})
                label += " (%s)" % p
            payloads.append({
                "kind": "web:route",
                "label": label,
                "coordinates": coords,
                "depth": depth,
            })
    return payloads


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("inputs", nargs="+",
                    help="harvest JSONL / HAR / URL-list files ('-' = stdin URL list)")
    ap.add_argument("-o", "--output", help="write merged endpoint records (JSON array)")
    ap.add_argument("--urls", help="write one full URL per endpoint (dalfox/ffuf input)")
    ap.add_argument("--work-units", dest="work_units",
                    help="write rupu work-units JSON array (for_each:/dispatch fan-out)")
    ap.add_argument("--assets", help="write assets.mark payloads JSON array")
    ap.add_argument("--depth", default="crawled",
                    choices=["mapped", "crawled", "tested", "exploited"],
                    help="asset depth rung actually reached (default: crawled)")
    ap.add_argument("--keep-static", action="store_true",
                    help="keep parameterless static-asset URLs (css/img/fonts)")
    args = ap.parse_args()

    records = []
    for path in args.inputs:
        try:
            records.extend(load_input(path))
        except OSError as e:
            sys.stderr.write("[!] %s: %s\n" % (path, e))
    merged = dedupe(records, drop_static=not args.keep_static)
    if not merged:
        sys.stderr.write("[!] no endpoints parsed\n")
        sys.exit(1)

    sites = sorted({r["site"] for r in merged})
    sys.stderr.write("[*] %d raw flows -> %d unique endpoints on %d site(s)\n"
                     % (len(records), len(merged), len(sites)))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(merged, f, indent=2)
        sys.stderr.write("[*] endpoints -> %s\n" % args.output)
    if args.urls:
        with open(args.urls, "w") as f:
            for r in sorted({x["url"] for x in merged}):
                f.write(r + "\n")
        sys.stderr.write("[*] url list -> %s\n" % args.urls)
    if args.work_units:
        with open(args.work_units, "w") as f:
            json.dump(work_units(merged), f, indent=2)
        sys.stderr.write("[*] work units -> %s (hand to the work-units skill)\n"
                         % args.work_units)
    if args.assets:
        payloads = asset_payloads(merged, args.depth)
        with open(args.assets, "w") as f:
            json.dump(payloads, f, indent=2)
        sys.stderr.write("[*] %d assets.mark payloads -> %s (coverage-assets skill)\n"
                         % (len(payloads), args.assets))
    if not (args.output or args.urls or args.work_units or args.assets):
        json.dump(merged, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
