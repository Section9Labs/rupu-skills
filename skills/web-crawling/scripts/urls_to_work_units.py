#!/usr/bin/env python3
"""urls_to_work_units.py - turn a merged URL inventory into rupu outputs.

Reads merged.json from merge_urls.py (or a plain URL list) and emits:
  * --work-units FILE : clean JSON ARRAY (first char '[') of work units
        {"id","title","targets":[...],"hints":{...}}
    for rupu `for_each:` fan-out or lead-agent dispatch (see the
    `work-units` skill and references/rupu.md).
  * --assets FILE     : JSON array of ready `assets.mark` payloads
    (web:site + web:route, depth "crawled").

Grouping:
  --group host   one unit per host (default)
  --group route  one unit per distinct (host, path) that has parameters

Usage:
  python3 scripts/urls_to_work_units.py merged.json --group host \
      --work-units crawl-units.json --assets assets-marks.json
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl


def load_inventory(path):
    """Return (all_urls, param_urls). Accepts merged.json or a plain list."""
    with open(path, "r", errors="replace") as f:
        head = f.read(1)
        f.seek(0)
        if head == "{":
            merged = json.load(f)
            params = list(merged.get("params", []))
            all_urls = params + list(merged.get("paths", [])) \
                + list(merged.get("static", []))
            return all_urls, params
        urls = [ln.strip() for ln in f if ln.strip().startswith("http")]
    params = [u for u in urls if urlsplit(u).query]
    return urls, params


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unit"


def pnames(url):
    return sorted({k for k, _ in
                   parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def base_of(url):
    p = urlsplit(url)
    return "%s://%s" % (p.scheme, p.netloc)


def units_by_host(all_urls, param_urls):
    by_host = {}
    for url in all_urls:
        by_host.setdefault(urlsplit(url).netloc, []).append(url)
    units = []
    for host, urls in sorted(by_host.items()):
        p_urls = [u for u in urls if urlsplit(u).query]
        names = sorted({n for u in p_urls for n in pnames(u)})
        targets = p_urls if p_urls else urls
        units.append({
            "id": "crawl-%s" % slug(host),
            "title": "Test crawled surface of %s (%d URLs, %d with params)"
                     % (host, len(urls), len(p_urls)),
            "targets": sorted(targets),
            "hints": {
                "host": host,
                "params": names,
                "url_count": str(len(urls)),
                "source": "web-crawling",
            },
        })
    return units


def units_by_route(all_urls, param_urls):
    by_route = {}
    for url in param_urls:
        p = urlsplit(url)
        by_route.setdefault((p.netloc, p.path), []).append(url)
    units = []
    for (host, path), urls in sorted(by_route.items()):
        names = sorted({n for u in urls for n in pnames(u)})
        units.append({
            "id": "route-%s-%s" % (slug(host), slug(path)),
            "title": "Fuzz %s%s (params: %s)" % (host, path, ",".join(names)),
            "targets": sorted(set(urls)),
            "hints": {
                "host": host,
                "path": path,
                "params": names,
                "source": "web-crawling",
            },
        })
    return units


def asset_payloads(all_urls):
    """assets.mark payloads: web:site per base, web:route per (base, path)."""
    payloads = []
    sites = sorted({base_of(u) for u in all_urls})
    for site in sites:
        payloads.append({
            "kind": "web:site",
            "coordinates": [{"t": "url", "v": site}],
            "label": site,
            "depth": "crawled",
        })
    routes = {}
    for url in all_urls:
        p = urlsplit(url)
        key = (base_of(url), p.path or "/")
        routes.setdefault(key, set()).update(pnames(url))
    for (site, path), names in sorted(routes.items()):
        coords = [{"t": "url", "v": site}, {"t": "http_route", "v": path}]
        for name in sorted(names):
            coords.append({"t": "param", "v": name})
        label = path + ("?" + "&".join(n + "=" for n in sorted(names))
                        if names else "")
        payloads.append({
            "kind": "web:route",
            "coordinates": coords,
            "label": label,
            "depth": "crawled",
        })
    return payloads


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inventory", help="merged.json from merge_urls.py, or a plain URL list")
    ap.add_argument("--group", choices=("host", "route"), default="host",
                    help="work-unit granularity (default: host)")
    ap.add_argument("--work-units", default="crawl-units.json",
                    help="work-units JSON array output file")
    ap.add_argument("--assets", default=None,
                    help="also write assets.mark payloads JSON array here")
    ap.add_argument("--max-targets", type=int, default=200,
                    help="cap targets per unit; overflow spills to -partN units")
    args = ap.parse_args()

    all_urls, param_urls = load_inventory(args.inventory)
    if not all_urls:
        print("[!] no URLs in %s" % args.inventory, file=sys.stderr)
        sys.exit(1)

    build = units_by_host if args.group == "host" else units_by_route
    units = build(all_urls, param_urls)

    # split oversized units so each stays dispatchable
    final = []
    for u in units:
        t = u["targets"]
        if len(t) <= args.max_targets:
            final.append(u)
            continue
        for i in range(0, len(t), args.max_targets):
            part = dict(u)
            n = i // args.max_targets + 1
            part["id"] = "%s-part%d" % (u["id"], n)
            part["title"] = "%s [part %d]" % (u["title"], n)
            part["targets"] = t[i:i + args.max_targets]
            final.append(part)

    with open(args.work_units, "w") as f:
        json.dump(final, f, indent=2)
    print("[+] wrote %s (%d work units; first char '[', for_each-ready)"
          % (args.work_units, len(final)), file=sys.stderr)

    if args.assets:
        payloads = asset_payloads(all_urls)
        with open(args.assets, "w") as f:
            json.dump(payloads, f, indent=2)
        print("[+] wrote %s (%d assets.mark payloads, depth=crawled)"
              % (args.assets, len(payloads)), file=sys.stderr)

    print("[>] hand %s to the work-units skill for dispatch; "
          "mark assets via coverage-assets; see references/rupu.md"
          % args.work_units, file=sys.stderr)


if __name__ == "__main__":
    main()
