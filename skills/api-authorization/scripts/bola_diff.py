#!/usr/bin/env python3
"""bola_diff.py - multi-identity differential replay for BOLA/IDOR testing.

Replays a request template once per (object id x identity), including an
implicit unauthenticated identity, and diffs status / body length / body
hash across identities. Flags cross-identity 2xx responses and identical
bodies (same data served to the wrong identity).

Usage:
  python3 scripts/bola_diff.py \
      --url 'https://api.example.com/v1/orders/{ID}' \
      --method GET \
      --ids ids-orders.txt \
      --identity A 'Authorization: Bearer eyJ...A' \
      --identity B 'Authorization: Bearer eyJ...B' \
      --owner A \
      --out reports/bola-orders.json

Notes:
  - '{ID}' is substituted into the URL, body, and all header values, so ids
    carried in query/body/header are tested the same way.
  - --body takes an inline string or @file. --header adds base headers sent
    for every identity. Repeat --identity for each account; the first one
    (or --owner NAME) is treated as the object owner / baseline.
  - Unauthenticated replay is on by default; disable with --no-unauth.
  - Output JSON (written atomically) holds every cell plus a 'flags' list;
    lift flagged rows into finding evidence per references/rupu.md.

Stdlib only. (vulture / cyan-loom)
"""

import argparse
import hashlib
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request

PLACEHOLDER = "{ID}"


def load_arg_or_file(value):
    if value and value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return value


def parse_header_line(line):
    if ":" not in line:
        raise ValueError("header must be 'Name: value', got: %r" % line)
    name, _, val = line.partition(":")
    return name.strip(), val.strip()


def build_context(insecure):
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send(method, url, body, headers, timeout, ctx):
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method)
    for name, val in headers.items():
        req.add_header(name, val)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw = resp.read()
        status = resp.status
    except urllib.error.HTTPError as err:
        raw = err.read()
        status = err.code
    except (urllib.error.URLError, OSError) as err:
        return {"status": 0, "length": 0, "hash": "-", "error": str(err),
                "snippet": ""}
    return {
        "status": status,
        "length": len(raw),
        "hash": hashlib.sha256(raw).hexdigest()[:12],
        "error": None,
        "snippet": raw[:200].decode("utf-8", errors="replace"),
    }


def substitute(template, oid):
    return template.replace(PLACEHOLDER, oid) if template else template


def atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main():
    ap = argparse.ArgumentParser(
        description="BOLA differential matrix: object ids x identities")
    ap.add_argument("--url", required=True,
                    help="URL template; '{ID}' marks the object id")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--body", default=None,
                    help="body template (inline or @file); '{ID}' substituted")
    ap.add_argument("--header", action="append", default=[],
                    help="base header 'Name: value', repeatable")
    ap.add_argument("--ids", default=None,
                    help="file of object ids, one per line")
    ap.add_argument("--id", dest="id_list", action="append", default=[],
                    help="single object id, repeatable")
    ap.add_argument("--identity", nargs=2, action="append", default=[],
                    metavar=("NAME", "HEADER"),
                    help="identity name + its auth header, repeatable")
    ap.add_argument("--owner", default=None,
                    help="identity name treated as object owner "
                         "(default: first --identity)")
    ap.add_argument("--no-unauth", action="store_true",
                    help="skip the unauthenticated replay")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--out", default=None,
                    help="write full JSON results here (atomic)")
    args = ap.parse_args()

    if not args.identity:
        ap.error("at least one --identity NAME 'Header: value' is required")

    ids = list(args.id_list)
    if args.ids:
        with open(args.ids, "r", encoding="utf-8", errors="replace") as fh:
            ids.extend(line.strip() for line in fh if line.strip())
    if not ids:
        ap.error("no object ids given (--ids file or --id)")

    base_headers = dict(parse_header_line(h) for h in args.header)
    body_template = load_arg_or_file(args.body)

    identities = []
    for name, hline in args.identity:
        hdrs = dict(base_headers)
        hname, hval = parse_header_line(hline)
        hdrs[hname] = hval
        identities.append((name, hdrs))
    if not args.no_unauth:
        identities.append(("unauth", dict(base_headers)))

    owner = args.owner or args.identity[0][0]
    ident_names = [n for n, _ in identities]
    if owner not in ident_names:
        ap.error("--owner %r is not a declared identity" % owner)

    ctx = build_context(args.insecure)
    results = []
    flags = []

    col = max(len(n) for n in ident_names) + 2
    header_row = "id".ljust(24) + "".join(n.ljust(col + 18) for n in ident_names)
    print(header_row)
    print("-" * len(header_row))

    for oid in ids:
        row = {"id": oid, "cells": {}}
        for name, hdrs in identities:
            final_headers = {k: substitute(v, oid) for k, v in hdrs.items()}
            res = send(args.method, substitute(args.url, oid),
                       substitute(body_template, oid), final_headers,
                       args.timeout, ctx)
            row["cells"][name] = res
        results.append(row)

        owner_cell = row["cells"][owner]
        line = oid.ljust(24)
        for name in ident_names:
            cell = row["cells"][name]
            line += ("%s/%s/%s" % (cell["status"], cell["length"],
                                   cell["hash"])).ljust(col + 18)
        print(line)

        for name in ident_names:
            if name == owner:
                continue
            cell = row["cells"][name]
            if not 200 <= cell["status"] < 300:
                continue
            if name == "unauth":
                flag = {"id": oid, "identity": name, "type": "UNAUTH-2xx",
                        "detail": "success with no credential"}
            elif (200 <= owner_cell["status"] < 300
                  and cell["hash"] == owner_cell["hash"]):
                flag = {"id": oid, "identity": name, "type": "IDENTICAL-BODY",
                        "detail": "non-owner body identical to owner's "
                                  "(confirmed same object data)"}
            else:
                flag = {"id": oid, "identity": name, "type": "CROSS-IDENT-2xx",
                        "detail": "non-owner success; verify body is owner's "
                                  "data, not an empty/own-scope result"}
            flags.append(flag)
            print("  !! %-16s id=%s identity=%s  %s"
                  % (flag["type"], oid, name, flag["detail"]))

    print()
    print("flags: %d  (IDENTICAL-BODY = confirmed; CROSS-IDENT-2xx = verify "
          "body; UNAUTH-2xx = missing authentication)" % len(flags))

    if args.out:
        atomic_write_json(args.out, {
            "tool": "bola_diff",
            "url_template": args.url,
            "method": args.method,
            "owner": owner,
            "identities": ident_names,
            "results": results,
            "flags": flags,
        })
        print("wrote %s" % args.out)

    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
