#!/usr/bin/env python3
"""merge_inventory.py - web-testing umbrella glue.

Merge per-phase recon outputs (http-probing live sites, web-crawling /
content-discovery routes, parameter-discovery param sets) into ONE normalized
engagement inventory, and emit:

  (a) --inventory  : merged inventory JSON {"sites": [...], "routes": [...], "tech": [...]}
  (b) --work-units : master routes-to-test work-units ARRAY (first char '[')
                     for rupu for_each: / lead-agent dispatch
  (c) --assets     : assets.mark payloads (web:site / web:route) at the right depth

Accepted input formats (auto-detected per file):
  * work-units JSON array: [{"id","title","targets":[...],"hints":{...}}, ...]
  * plain JSON array of URL strings
  * JSON object with a "sites"/"routes"/"urls" list (previous inventory)
  * newline-delimited URL list (anything that is not valid JSON)

Usage:
  python3 scripts/merge_inventory.py out/live-sites.json out/routes-*.json \
      --inventory out/inventory.json \
      --work-units out/routes-to-test.json \
      --assets out/assets-mark.json
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl

DEPTH_ORDER = {"mapped": 0, "crawled": 1, "tested": 2, "exploited": 3}


def slug(text, maxlen=72):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen] or "item"


def split_csv(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def norm_url(raw):
    """Return (site, path, params:list) or None. site = scheme://host[:port]."""
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlsplit(raw)
    except ValueError:
        return None
    if not u.hostname:
        return None
    netloc = u.hostname.lower()
    if u.port and not (
        (u.scheme == "http" and u.port == 80)
        or (u.scheme == "https" and u.port == 443)
    ):
        netloc += ":%d" % u.port
    site = "%s://%s" % (u.scheme or "http", netloc)
    path = u.path or "/"
    params = [k for k, _ in parse_qsl(u.query, keep_blank_values=True)]
    return site, path, params


def load_records(path):
    """Yield dicts {url, params, methods, tech, waf, classes, depth, source}."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print("[!] cannot read %s: %s" % (path, exc), file=sys.stderr)
        return
    text = text.strip()
    if not text:
        return
    data = None
    try:
        data = json.loads(text)
    except ValueError:
        for line in text.splitlines():  # newline-delimited URLs
            line = line.strip()
            if line and not line.startswith("#"):
                yield {"url": line, "source": path}
        return
    if isinstance(data, dict):
        items = []
        for key in ("sites", "routes", "urls", "work_units"):
            value = data.get(key)
            if isinstance(value, list):
                items.extend(value)
        data = items
    if not isinstance(data, list):
        return
    for item in data:
        if isinstance(item, str):
            yield {"url": item, "source": path}
            continue
        if not isinstance(item, dict):
            continue
        hints = item.get("hints") or {}
        if not isinstance(hints, dict):
            hints = {}
        targets = item.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        if not targets and item.get("url"):
            targets = [item["url"]]
        for target in targets:
            yield {
                "url": str(target),
                "params": split_csv(hints.get("params") or item.get("params")),
                "methods": split_csv(hints.get("methods") or item.get("methods")),
                "tech": split_csv(hints.get("tech") or item.get("tech")),
                "waf": str(hints.get("waf") or item.get("waf") or ""),
                "classes": split_csv(hints.get("classes") or item.get("classes")),
                "depth": str(hints.get("depth") or item.get("depth") or ""),
                "source": str(hints.get("source") or item.get("source") or path),
            }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="recon output files to merge")
    ap.add_argument("--inventory", help="write merged inventory JSON here")
    ap.add_argument("--work-units", dest="work_units",
                    help="write master routes-to-test work-units array here")
    ap.add_argument("--assets", help="write assets.mark payloads JSON here")
    ap.add_argument("--default-depth", default=None,
                    help="override depth for all emitted assets "
                         "(mapped|crawled|tested|exploited)")
    args = ap.parse_args()

    sites = {}   # site -> {"url", "tech": set, "waf": set, "sources": set, "depth"}
    routes = {}  # (site, path) -> {... "params": set, "methods": set, ...}

    for path in args.inputs:
        for rec in load_records(path):
            parsed = norm_url(rec.get("url", ""))
            if not parsed:
                continue
            site_url, route_path, url_params = parsed
            depth = rec.get("depth") or ""
            source = rec.get("source") or path

            site = sites.setdefault(site_url, {
                "url": site_url, "tech": set(), "waf": set(),
                "sources": set(), "depth": "mapped"})
            site["tech"].update(rec.get("tech") or [])
            if rec.get("waf") and rec["waf"].lower() not in ("", "none", "false"):
                site["waf"].add(rec["waf"])
            site["sources"].add(source)

            # A bare "/" with no params from a site-list file is just the site.
            is_route = route_path != "/" or url_params or rec.get("params")
            if not is_route:
                continue

            key = (site_url, route_path)
            route = routes.setdefault(key, {
                "site": site_url, "path": route_path,
                "url": site_url + route_path,
                "params": set(), "methods": set(), "classes": set(),
                "sources": set(), "depth": "crawled"})
            route["params"].update(url_params)
            route["params"].update(rec.get("params") or [])
            route["methods"].update(m.upper() for m in rec.get("methods") or [])
            route["classes"].update(rec.get("classes") or [])
            route["sources"].add(source)
            if depth in DEPTH_ORDER and \
                    DEPTH_ORDER[depth] > DEPTH_ORDER[route["depth"]]:
                route["depth"] = depth

    # ---- (a) merged inventory -------------------------------------------
    all_tech = sorted({t for s in sites.values() for t in s["tech"]})
    inventory = {
        "sites": [
            {"url": s["url"], "tech": sorted(s["tech"]),
             "waf": sorted(s["waf"]), "sources": sorted(s["sources"])}
            for s in sorted(sites.values(), key=lambda x: x["url"])],
        "routes": [
            {"url": r["url"], "site": r["site"], "path": r["path"],
             "params": sorted(r["params"]), "methods": sorted(r["methods"]),
             "depth": r["depth"], "sources": sorted(r["sources"])}
            for r in sorted(routes.values(), key=lambda x: x["url"])],
        "tech": all_tech,
    }

    # ---- (b) master work-units array ------------------------------------
    units = []
    seen_ids = set()
    for r in sorted(routes.values(), key=lambda x: x["url"]):
        uid = slug("route-" + r["site"].split("://", 1)[1] + "-" + r["path"])
        n = 2
        base = uid
        while uid in seen_ids:
            uid = "%s-%d" % (base, n)
            n += 1
        seen_ids.add(uid)
        site_tech = sorted(sites.get(r["site"], {}).get("tech", []))
        site_waf = sorted(sites.get(r["site"], {}).get("waf", []))
        params = sorted(r["params"])
        title = "Test %s" % r["url"]
        if params:
            title += " (params: %s)" % ", ".join(params)
        units.append({
            "id": uid,
            "title": title,
            "targets": [r["url"]],
            "hints": {
                "site": r["site"],
                "path": r["path"],
                "params": ",".join(params),
                "methods": ",".join(sorted(r["methods"]) or ["GET"]),
                "tech": ",".join(site_tech),
                "waf": ",".join(site_waf) or "none",
                "classes": ",".join(sorted(r["classes"])),
                "source": ",".join(sorted(r["sources"]))[:200],
            },
        })

    # ---- (c) assets.mark payloads ----------------------------------------
    assets = []
    for s in sorted(sites.values(), key=lambda x: x["url"]):
        label = s["url"]
        if s["tech"]:
            label += " (%s)" % ", ".join(sorted(s["tech"])[:6])
        assets.append({
            "kind": "web:site",
            "label": label,
            "coordinates": [{"t": "url", "v": s["url"]}],
            "depth": args.default_depth or "mapped",
        })
    for r in sorted(routes.values(), key=lambda x: x["url"]):
        coords = [{"t": "url", "v": r["site"]},
                  {"t": "http_route", "v": r["path"]}]
        params = sorted(r["params"])
        if params:
            coords.append({"t": "param", "v": params[0]})
        label = r["url"]
        if params:
            label += " [%s]" % ",".join(params)
        assets.append({
            "kind": "web:route",
            "label": label,
            "coordinates": coords,
            "depth": args.default_depth or r["depth"],
        })

    def dump(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
            fh.write("\n")
        print("[+] wrote %s" % path, file=sys.stderr)

    if args.inventory:
        dump(args.inventory, inventory)
    if args.work_units:
        dump(args.work_units, units)   # JSON array: first char is '['
    if args.assets:
        dump(args.assets, assets)
    if not (args.inventory or args.work_units or args.assets):
        json.dump(inventory, sys.stdout, indent=2)
        print()

    print("[*] merged %d site(s), %d route(s), %d work unit(s), %d asset payload(s)"
          % (len(sites), len(routes), len(units), len(assets)), file=sys.stderr)


if __name__ == "__main__":
    main()
