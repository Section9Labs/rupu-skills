#!/usr/bin/env python3
"""parse_arjun.py - normalize parameter-discovery output for rupu.

Reads arjun JSON (-oJ), x8 JSON (-O json -o), and ffuf JSON (-o -of json)
result files, optionally mines query-string keys from a URL list, and merges
everything into one map of {url, method, params[]} per endpoint.

Emits:
  --merged      normalized JSON array of endpoints with their params
  --work-units  rupu work-units JSON array (first char '['), one unit per
                endpoint+method, ready for for_each:/dispatch fan-out
  --assets      JSON array of rupu assets.mark payloads (web:route, depth
                'tested', one per confirmed param; bare route mark when an
                endpoint was fuzzed but yielded no params)

Usage:
  python3 scripts/parse_arjun.py arjun-get.json x8-out.json ffuf-out.json \
      --urls all-crawled-urls.txt \
      --merged params-merged.json \
      --work-units param-work-units.json \
      --assets assets-mark.json

Python 3 standard library only. -- vulture (onyx-peak)
"""

import argparse
import hashlib
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl

# name-pattern -> downstream lead classification (see SKILL.md table)
LEAD_PATTERNS = [
    ("ssrf-redirect", re.compile(
        r"^(url|uri|dest|destination|redirect(_?ur[il])?|next|return(_?to|url)?"
        r"|callback|continue|feed|target|rurl|forward|host|domain|site|link|out)$", re.I)),
    ("idor", re.compile(
        r"^(id|[a-z_]*_?id|uid|user|userid|account(_?(id|ref|number))?|number"
        r"|order(_?id)?|doc(ument)?(_?id)?|key|ref|pid|gid|no)$", re.I)),
    ("lfi-ssti", re.compile(
        r"^(template|tpl|view|page|file(name|path)?|path|include|inc|dir"
        r"|folder|document|root|lang|locale|style|theme|layout)$", re.I)),
    ("debug-toggle", re.compile(
        r"^(debug|test(ing)?|admin|enable[d]?|show|env|trace|verbose|dev"
        r"|staging|internal|beta|preview|dry_?run)$", re.I)),
    ("cmdi", re.compile(
        r"^(cmd|exec(ute)?|command|run|func(tion)?|action|do|op|process"
        r"|daemon|ping|query_?cmd)$", re.I)),
    ("injection", re.compile(
        r"^(q|s|search|query|keyword[s]?|name|sort|order(_?by)?|filter"
        r"|where|group|having|select|field[s]?|column|table)$", re.I)),
]


def classify(param):
    for lead, rx in LEAD_PATTERNS:
        if rx.match(param):
            return lead
    return "none"


def base_url(url):
    """Strip query/fragment; keep scheme://host/path."""
    p = urlsplit(url)
    scheme = p.scheme or "http"
    return "{}://{}{}".format(scheme, p.netloc, p.path or "/")


class Merger:
    def __init__(self):
        # key: (url, method) -> {"params": {name: set(sources)}}
        self.endpoints = {}

    def add(self, url, method, params, source):
        url = base_url(url)
        method = (method or "GET").upper()
        ep = self.endpoints.setdefault((url, method), {})
        for name in params:
            name = name.strip()
            if not name:
                continue
            ep.setdefault(name, set()).add(source)

    def touch(self, url, method, source):
        """Record that an endpoint was fuzzed even if nothing was found."""
        url = base_url(url)
        method = (method or "GET").upper()
        self.endpoints.setdefault((url, method), {})


# ---------------------------------------------------------------- loaders

def load_json(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read().strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # maybe JSON Lines
        objs = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                return None
        return objs or None


def ingest_arjun(data, merger, path):
    """arjun -oJ: {url: {"params": [...], "method": "GET", ...}}
    or legacy  : {url: ["p1", "p2"]}"""
    hit = False
    if not isinstance(data, dict):
        return False
    for url, val in data.items():
        if not url.startswith(("http://", "https://")):
            return False
        if isinstance(val, dict):
            params = val.get("params") or []
            method = val.get("method", "GET")
        elif isinstance(val, list):
            params, method = [str(x) for x in val], "GET"
        else:
            continue
        merger.add(url, method, [str(p) for p in params], "arjun")
        merger.touch(url, method, "arjun")
        hit = True
    if hit:
        sys.stderr.write("[parse_arjun] %s: parsed as arjun output\n" % path)
    return hit


def ingest_x8(data, merger, path):
    """x8 -O json: [{"method","url","found_params":[{"name":...}|"name"]}]"""
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return False
    hit = False
    for entry in data:
        if not isinstance(entry, dict) or "found_params" not in entry:
            continue
        url = entry.get("url", "")
        method = entry.get("method", "GET")
        names = []
        for fp in entry.get("found_params") or []:
            if isinstance(fp, dict):
                name = fp.get("name") or fp.get("param") or ""
            else:
                # strings may look like "name=value"
                name = str(fp).split("=", 1)[0]
            if name:
                names.append(name)
        merger.add(url, method, names, "x8")
        merger.touch(url, method, "x8")
        hit = True
    if hit:
        sys.stderr.write("[parse_arjun] %s: parsed as x8 output\n" % path)
    return hit


def ingest_ffuf(data, merger, path):
    """ffuf -of json: {"config": {...}, "results": [{"input": {"FUZZ": name},
    "url": ..., "status": ...}]}"""
    if not isinstance(data, dict) or "results" not in data:
        return False
    config = data.get("config") or {}
    cfg_url = config.get("url", "")
    method = config.get("method", "GET")
    hit = False
    for res in data.get("results") or []:
        if not isinstance(res, dict):
            continue
        inp = res.get("input") or {}
        name = inp.get("FUZZ") or next(iter(inp.values()), "")
        if not name:
            continue
        url = res.get("url") or cfg_url
        # drop the injected FUZZ pair / keyword from the endpoint identity
        url = url.replace("FUZZ", "")
        merger.add(url, method, [str(name)], "ffuf")
        hit = True
    if cfg_url:
        merger.touch(cfg_url.replace("FUZZ", ""), method, "ffuf")
    if hit or cfg_url:
        sys.stderr.write("[parse_arjun] %s: parsed as ffuf output\n" % path)
    return bool(hit or cfg_url)


def ingest_urls(path, merger):
    """Mine query keys from a newline URL list (crawl/gau/wayback output)."""
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            url = line.strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            query = urlsplit(url).query
            if not query:
                continue
            keys = [k for k, _ in parse_qsl(query, keep_blank_values=True) if k]
            if keys:
                merger.add(url, "GET", keys, "mined-url")
                count += len(keys)
    sys.stderr.write("[parse_arjun] %s: mined %d query keys\n" % (path, count))


# ---------------------------------------------------------------- emitters

def build_merged(merger):
    out = []
    for (url, method), params in sorted(merger.endpoints.items()):
        out.append({
            "url": url,
            "method": method,
            "params": sorted(params.keys()),
            "sources": {name: sorted(srcs) for name, srcs in sorted(params.items())},
        })
    return out


def unit_id(url, method):
    h = hashlib.sha1(("%s %s" % (method, url)).encode()).hexdigest()[:8]
    return "param-" + h


def build_work_units(merged):
    units = []
    for ep in merged:
        if not ep["params"]:
            continue  # nothing to test downstream
        units.append({
            "id": unit_id(ep["url"], ep["method"]),
            "title": "%s [%s] %d params" % (ep["url"], ep["method"], len(ep["params"])),
            "targets": [ep["url"]],
            "hints": {
                "method": ep["method"],
                "params": ep["params"],
                "lead": {p: classify(p) for p in ep["params"]},
                "source": ",".join(sorted({s for v in ep["sources"].values() for s in v})),
            },
        })
    return units


def build_assets(merged):
    payloads = []
    for ep in merged:
        route = urlsplit(ep["url"]).path or "/"
        if ep["params"]:
            for p in ep["params"]:
                payloads.append({
                    "kind": "web:route",
                    "label": "%s?%s (%s)" % (route, p, ep["method"]),
                    "coordinates": [
                        {"t": "url", "v": ep["url"]},
                        {"t": "http_route", "v": route},
                        {"t": "param", "v": p},
                    ],
                    "depth": "tested",
                })
        else:
            payloads.append({
                "kind": "web:route",
                "label": "%s (%s)" % (route, ep["method"]),
                "coordinates": [
                    {"t": "url", "v": ep["url"]},
                    {"t": "http_route", "v": route},
                ],
                "depth": "tested",
            })
    return payloads


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    sys.stderr.write("[parse_arjun] wrote %s\n" % path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="*",
                    help="arjun/x8/ffuf JSON result files (auto-detected)")
    ap.add_argument("--urls", help="newline URL list; mine query keys and merge")
    ap.add_argument("--merged", help="write merged endpoint->params JSON array")
    ap.add_argument("--work-units", dest="work_units",
                    help="write rupu work-units JSON array")
    ap.add_argument("--assets", help="write assets.mark payloads JSON array")
    args = ap.parse_args()

    if not args.inputs and not args.urls:
        ap.error("no inputs: give result files and/or --urls")

    merger = Merger()
    for path in args.inputs:
        data = load_json(path)
        if data is None:
            sys.stderr.write("[parse_arjun] %s: not JSON, skipped\n" % path)
            continue
        if ingest_ffuf(data, merger, path):
            continue
        if ingest_x8(data, merger, path):
            continue
        if ingest_arjun(data, merger, path):
            continue
        sys.stderr.write("[parse_arjun] %s: unrecognized format, skipped\n" % path)

    if args.urls:
        ingest_urls(args.urls, merger)

    merged = build_merged(merger)
    sys.stderr.write("[parse_arjun] %d endpoints, %d params total\n"
                     % (len(merged), sum(len(e["params"]) for e in merged)))

    if args.merged:
        write_json(args.merged, merged)
    if args.work_units:
        write_json(args.work_units, build_work_units(merged))
    if args.assets:
        write_json(args.assets, build_assets(merged))
    if not (args.merged or args.work_units or args.assets):
        json.dump(merged, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
