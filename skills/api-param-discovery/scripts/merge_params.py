#!/usr/bin/env python3
"""merge_params.py - merge arjun-discovered params into the normalized
request set and emit a rupu work-unit array for fan-out.

Inputs:
  --request-set  api-spec-discovery normalized request set (JSON list of
                 operations, or {"operations": [...]}). Each operation:
                 {"method","url" (or "base_url"+"path"),"params":[{"name","in",...}]}
  --arjun        one or more results files: run_arjun.py combined output,
                 or raw arjun -oJ files (both shapes handled).

Outputs:
  --merged-out   request set with new params appended
                 ({"name","in","source":"arjun","class":...}) - atomic.
  -o/--output    work-unit JSON array (one unit per endpoint with new
                 params), schema per the imported work-units skill:
                 [{"id","title","targets","hints"}] - atomic. Titles and
                 hints come from a fixed vocabulary; input-derived strings
                 appear only in targets, length-capped.

Example:
    python3 scripts/merge_params.py \
        --request-set reports/api-spec-requestset.json \
        --arjun reports/arjun-results.json \
        --merged-out reports/api-param-requestset.json \
        -o reports/api-param-units.json

Stdlib only.
"""

import argparse
import json
import os
import re
import sys
import tempfile
from urllib.parse import urlsplit

TARGET_CAP = 256

# Fixed classification vocabulary: (class tag, route hint, name regex).
CLASS_RULES = [
    ("class:bola-id", "route:api-authorization",
     re.compile(r"(^|_)(id|uid|guid|uuid|user|users|account|acct|customer|member|"
                r"owner|org|tenant|team|group|order|invoice|doc|file|key)($|_?id$|_)",
                re.I)),
    ("class:privilege-toggle", "route:api-authorization",
     re.compile(r"^(is_?)?(admin|root|superuser|staff|role|roles|debug|test|dev|"
                r"internal|verified|approved|enabled|active|premium|plan|level|"
                r"permission|perms|scope|access)$", re.I)),
    ("class:ssrf-sink", "route:api-ssrf",
     re.compile(r"(^|_)(url|uri|link|src|dest|destination|target|host|domain|"
                r"callback_?url|webhook|redirect|return_?url|next|continue|"
                r"feed|fetch|proxy|image_?url)($|_)", re.I)),
    ("class:jsonp", "route:api-injection",
     re.compile(r"^(callback|jsonp|cb)$", re.I)),
    ("class:response-shaping", "route:api-authorization",
     re.compile(r"^(fields?|include|includes|expand|embed|select|format|output|"
                r"view|projection|attrs|attributes|columns|filter)$", re.I)),
    ("class:injection-sink", "route:api-injection",
     re.compile(r"^(q|query|search|keyword|sort|sort_?by|order|order_?by|where|"
                r"name|title|comment|message|email|template|lang|locale|path|"
                r"page|limit|offset|count)$", re.I)),
]
FALLBACK = ("class:unclassified", "route:api-injection")


def classify(name):
    for tag, route, rx in CLASS_RULES:
        if rx.search(name):
            return tag, route
    return FALLBACK


def atomic_write_json(path, obj):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".merge-", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cap(s):
    s = str(s)
    return s if len(s) <= TARGET_CAP else s[:TARGET_CAP]


def norm_url(url):
    """Normalize for matching: scheme://host/path (no query, no trailing /)."""
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    path = (p.path or "/").rstrip("/") or "/"
    return "%s://%s%s" % (p.scheme.lower(), p.netloc.lower(), path)


ARJUN_TO_HTTP = {"GET": "GET", "POST": "POST", "JSON": "POST", "XML": "POST"}
ARJUN_TO_IN = {"GET": "query", "POST": "body", "JSON": "body", "XML": "body"}


def load_arjun_results(paths):
    """Yield (url, arjun_method, [param names]) from combined or raw files."""
    out = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            # run_arjun.py combined shape
            for r in data["results"]:
                if isinstance(r, dict) and r.get("url"):
                    out.append((r["url"], str(r.get("method", "GET")).upper(),
                                [str(p) for p in r.get("params", [])]))
        elif isinstance(data, dict):
            # raw arjun -oJ: {url: {params:[...], method:...}} or {url: [...]}
            for url, entry in data.items():
                if isinstance(entry, dict):
                    out.append((url, str(entry.get("method", "GET")).upper(),
                                [str(p) for p in entry.get("params", [])]))
                elif isinstance(entry, list):
                    out.append((url, "GET", [str(p) for p in entry]))
        else:
            print("warning: unrecognized shape in %s, skipped" % path, file=sys.stderr)
    return out


def op_url(op):
    url = op.get("url")
    if not url:
        base = (op.get("base_url") or "").rstrip("/")
        path = op.get("path") or ""
        if base and path:
            url = base + "/" + path.lstrip("/")
    return url


def main():
    ap = argparse.ArgumentParser(description="Merge arjun params into the request set.")
    ap.add_argument("--request-set", required=True)
    ap.add_argument("--arjun", required=True, nargs="+",
                    help="run_arjun.py combined output and/or raw arjun -oJ files")
    ap.add_argument("--merged-out", required=True, help="enriched request set path")
    ap.add_argument("-o", "--output", required=True, help="work-unit array path")
    args = ap.parse_args()

    with open(args.request_set, encoding="utf-8") as fh:
        rs = json.load(fh)
    wrapped = isinstance(rs, dict)
    ops = rs.get("operations", []) if wrapped else rs
    if not isinstance(ops, list):
        sys.exit("unrecognized request-set shape in %s" % args.request_set)

    # Index operations by (normalized url, http method); also by url alone.
    by_url_method = {}
    by_url = {}
    for op in ops:
        if not isinstance(op, dict):
            continue
        url = op_url(op)
        if not url:
            continue
        n = norm_url(url)
        m = str(op.get("method", "GET")).upper()
        by_url_method.setdefault((n, m), op)
        by_url.setdefault(n, op)

    # endpoint key -> {"op": op-or-None, "url", "route", "new": {name: (in, class, route)}, "methods": set}
    endpoints = {}
    for url, arjun_method, params in load_arjun_results(args.arjun):
        if not params:
            continue
        n = norm_url(url)
        http_m = ARJUN_TO_HTTP.get(arjun_method, "GET")
        op = by_url_method.get((n, http_m)) or by_url.get(n)
        if op is not None:
            existing = {str(p.get("name", p)).lower()
                        for p in op.get("params", []) if p}
            match_url = op_url(op)
            route = "%s %s" % (str(op.get("method", http_m)).upper(),
                               urlsplit(match_url).path or "/")
        else:
            existing = set()
            match_url = url
            route = "%s %s" % (http_m, urlsplit(url).path or "/")
        ep = endpoints.setdefault(n + " " + route, {
            "op": op, "url": match_url, "route": route, "new": {}, "methods": set()})
        ep["methods"].add(arjun_method)
        for name in params:
            if name.lower() in existing or name in ep["new"]:
                continue
            tag, route_hint = classify(name)
            ep["new"][name] = (ARJUN_TO_IN.get(arjun_method, "query"), tag, route_hint)

    # Merge into operations (create synthetic ops for unmatched endpoints).
    new_param_total = 0
    for ep in endpoints.values():
        if not ep["new"]:
            continue
        op = ep["op"]
        if op is None:
            op = {"method": ep["route"].split(" ", 1)[0], "url": ep["url"],
                  "params": [], "source": "arjun"}
            ops.append(op)
        op.setdefault("params", [])
        for name, (loc, tag, _route) in sorted(ep["new"].items()):
            op["params"].append({"name": name, "in": loc,
                                 "source": "arjun", "class": tag})
            new_param_total += 1

    merged = rs if wrapped else ops
    if wrapped:
        rs["operations"] = ops
    atomic_write_json(args.merged_out, merged)

    # Build work units: one per endpoint with new params.
    units = []
    idx = 0
    for key in sorted(endpoints):
        ep = endpoints[key]
        if not ep["new"]:
            continue
        idx += 1
        targets = [cap(ep["route"]), cap(ep["url"])]
        hints = set()
        for name, (_loc, tag, route_hint) in sorted(ep["new"].items()):
            targets.append(cap("param:" + name))
            hints.add(tag)
            hints.add(route_hint)
        for m in sorted(ep["methods"]):
            hints.add("method:" + m)
        if any(m != "GET" for m in ep["methods"]):
            hints.add("caution:state-changing")
        units.append({
            "id": "param-%03d" % idx,
            "title": "arjun-new-params",
            "targets": targets,
            "hints": sorted(hints),
        })

    atomic_write_json(args.output, units)
    print("merged %d new param(s) across %d endpoint(s); wrote %s and %s"
          % (new_param_total, len(units), args.merged_out, args.output),
          file=sys.stderr)


if __name__ == "__main__":
    main()
