#!/usr/bin/env python3
"""sqlmap_req.py - build a saved raw-request file for `sqlmap -r`.

Takes a normalized operation JSON and writes a raw HTTP request with sqlmap's
`*` injection marker on the chosen parameters (query string, JSON body values,
or a path segment).

Operation JSON shape:

  {"method": "POST",
   "url": "https://api.example.com/v1/orders/search?sort=name",
   "headers": {"Authorization": "Bearer eyJ...",
               "Content-Type": "application/json"},
   "body": {"q": "widgets", "limit": 10},
   "params": ["q"]}

`body` may be an object (serialized as JSON) or a pre-serialized string.
`params` in the file is used when neither --param nor --all is given.

Usage:
  python3 scripts/sqlmap_req.py op.json --param q --param sort --out request.txt
  python3 scripts/sqlmap_req.py op.json --all --out request.txt
  python3 scripts/sqlmap_req.py op.json --path-seg 3 --out request.txt

Then:
  sqlmap -r request.txt --batch --level 2 --risk 2 --proxy http://127.0.0.1:8080
  (add --force-ssl when the request file came from an https URL on a
   non-443 port)

stdlib only.
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl, urlencode, quote

MARKER = "*"


def mark_query(query, params, mark_all):
    pairs = parse_qsl(query, keep_blank_values=True)
    out, marked = [], []
    for k, v in pairs:
        if mark_all or k in params:
            out.append((k, v + MARKER))
            marked.append("query:" + k)
        else:
            out.append((k, v))
    # quote_via=quote keeps the * marker literal (default quote_plus would too,
    # since * is unreserved, but be explicit about spaces)
    return urlencode(out, quote_via=quote, safe=MARKER), marked


def mark_json_body(body_str, params, mark_all):
    """Append the marker inside string values and after numeric/bool values
    for the named keys (or all leaf keys with --all). Regex-based on the
    serialized body so nesting works without re-ordering keys."""
    marked = []

    def key_pattern(name):
        return re.escape(name) if name is not None else r"[A-Za-z0-9_.\-]+"

    names = [None] if mark_all else list(params)
    for name in names:
        kp = key_pattern(name)
        # string values: "key": "value"  -> "key": "value*"
        pat_s = re.compile(r'("(%s)"\s*:\s*")((?:[^"\\]|\\.)*)(")' % kp)

        def sub_s(m):
            marked.append("json:" + m.group(2))
            return m.group(1) + m.group(3) + MARKER + m.group(4)

        body_str = pat_s.sub(sub_s, body_str)
        # numeric / bool / null values: "key": 10 -> "key": 10*
        pat_n = re.compile(
            r'("(%s)"\s*:\s*)(-?\d+(?:\.\d+)?|true|false|null)(?=[,}\]\s])' % kp)

        def sub_n(m):
            marked.append("json:" + m.group(2))
            return m.group(1) + m.group(3) + MARKER

        body_str = pat_n.sub(sub_n, body_str)
    return body_str, marked


def mark_path(path, seg_index):
    segs = path.split("/")
    # count non-empty segments; seg_index is 1-based over them
    idx = [i for i, s in enumerate(segs) if s]
    if seg_index < 1 or seg_index > len(idx):
        sys.exit("[!] --path-seg %d out of range (path has %d segments)"
                 % (seg_index, len(idx)))
    i = idx[seg_index - 1]
    segs[i] = segs[i] + MARKER
    return "/".join(segs), ["path:segment-%d" % seg_index]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("op", help="normalized operation JSON file")
    ap.add_argument("--param", action="append", default=[],
                    help="parameter name to mark (repeatable)")
    ap.add_argument("--all", action="store_true",
                    help="mark every query param and JSON leaf value")
    ap.add_argument("--path-seg", type=int, default=None,
                    help="1-based path segment to mark (e.g. the id in /v1/users/42)")
    ap.add_argument("--out", default="request.txt")
    args = ap.parse_args()

    with open(args.op, "r", encoding="utf-8") as f:
        op = json.load(f)

    method = op.get("method", "GET").upper()
    url = op["url"]
    headers = dict(op.get("headers") or {})
    body = op.get("body")
    params = args.param or op.get("params") or []
    if not params and not args.all and args.path_seg is None:
        sys.exit("[!] nothing to mark: give --param/--all/--path-seg "
                 "or put \"params\" in the op file")

    parts = urlsplit(url)
    path = parts.path or "/"
    query = parts.query
    marked = []

    if args.path_seg is not None:
        path, mk = mark_path(path, args.path_seg)
        marked += mk
    if query:
        query, mk = mark_query(query, set(params), args.all)
        marked += mk

    body_str = ""
    if body is not None:
        body_str = body if isinstance(body, str) else json.dumps(body)
        is_json = body_str.lstrip()[:1] in ("{", "[")
        if is_json:
            body_str, mk = mark_json_body(body_str, params, args.all)
            marked += mk
            headers.setdefault("Content-Type", "application/json")
        else:
            # form-encoded body: reuse the query marker logic
            body_str, mk = mark_query(body_str, set(params), args.all)
            marked += ["body:" + m.split(":", 1)[1] for m in mk]
            headers.setdefault("Content-Type",
                               "application/x-www-form-urlencoded")

    if not marked:
        print("[!] warning: no parameter matched; request written unmarked "
              "(sqlmap will test all params itself)", file=sys.stderr)

    target = path + ("?" + query if query else "")
    host = parts.netloc
    lines = ["%s %s HTTP/1.1" % (method, target), "Host: %s" % host]
    for k, v in headers.items():
        if k.lower() in ("host", "content-length"):
            continue
        lines.append("%s: %s" % (k, v))
    if body_str:
        # sqlmap recomputes Content-Length after stripping markers
        lines.append("Content-Length: %d" % len(body_str.encode("utf-8")))
    raw = "\r\n".join(lines) + "\r\n\r\n" + body_str

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        f.write(raw)

    print("[*] wrote %s (%d marker(s): %s)"
          % (args.out, len(marked), ", ".join(marked) or "none"))
    cmd = "sqlmap -r %s --batch --level 2 --risk 2" % args.out
    if parts.scheme == "https" and parts.port not in (None, 443):
        cmd += " --force-ssl"
    print("[*] next: %s --proxy http://127.0.0.1:8080" % cmd)


if __name__ == "__main__":
    main()
