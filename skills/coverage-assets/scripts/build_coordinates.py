#!/usr/bin/env python3
"""build_coordinates.py — print the exact rupu coordinate JSON for a thing.

rupu encodes every coordinate as {"t": <tag>, "v": <value>} and derives asset
ids from the kind plus the sorted locator, so a mis-encoded coordinate either
errors or silently forks the asset. This helper emits the canonical encodings
so an agent never hand-writes one wrong.

Usage (each subcommand prints a JSON array of coordinates to stdout):

  python3 scripts/build_coordinates.py host 198.51.100.20
  python3 scripts/build_coordinates.py service 198.51.100.20 8443 --proto tcp
  python3 scripts/build_coordinates.py url https://shop.example.com
  python3 scripts/build_coordinates.py route https://shop.example.com POST /cart/apply --param coupon
  python3 scripts/build_coordinates.py resource arn:aws:s3:::acme-logs
  python3 scripts/build_coordinates.py resource pkg:npm/lodash@4.17.20
  python3 scripts/build_coordinates.py resource dc-dump-ntds --scheme objective
  python3 scripts/build_coordinates.py file src/auth/login.py --start 88 --end 131 \
      --symbol verify_token --commit 9fceb02d --sha256 <64hex>

Importable as a library:
  from build_coordinates import host, service, url, http_route, param, \
      resource_id, path, line_range, symbol, commit, sha256, offset, address
Each function returns a single {"t","v"} dict.
"""

import argparse
import json
import sys
from urllib.parse import urlsplit

PROTOS = ("tcp", "udp", "other")

# ---------------------------------------------------------------------------
# One function per coordinate type — the 13 canonical encodings.
# ---------------------------------------------------------------------------


def path(p):
    return {"t": "path", "v": str(p)}


def line_range(start, end=None):
    start = int(start)
    end = int(end) if end is not None else start
    if end < start:
        raise ValueError("line_range end < start")
    return {"t": "line_range", "v": {"start": start, "end": end}}


def symbol(name):
    return {"t": "symbol", "v": str(name)}


def commit(rev):
    return {"t": "commit", "v": str(rev)}


def sha256(digest):
    d = str(digest).lower()
    if len(d) != 64 or any(c not in "0123456789abcdef" for c in d):
        raise ValueError("sha256 must be 64 hex chars, got %r" % digest)
    return {"t": "sha256", "v": d}


def offset(n):
    return {"t": "offset", "v": int(str(n), 0)}


def address(n):
    # Accepts 0x-prefixed hex or decimal; emits a decimal integer, as rupu expects.
    return {"t": "address", "v": int(str(n), 0)}


def host(h):
    return {"t": "host", "v": str(h)}


def port(number, proto="tcp"):
    proto = str(proto).lower()
    if proto not in PROTOS:
        raise ValueError("proto must be one of %s, got %r" % ("/".join(PROTOS), proto))
    number = int(number)
    if not 0 < number < 65536:
        raise ValueError("port out of range: %d" % number)
    return {"t": "port", "v": {"number": number, "proto": proto}}


def url(u):
    return {"t": "url", "v": str(u)}


def http_route(method, route_path):
    return {"t": "http_route", "v": {"method": str(method).upper(), "path": str(route_path)}}


def param(name):
    return {"t": "param", "v": str(name)}


def resource_id(scheme, rid):
    return {"t": "resource_id", "v": {"scheme": str(scheme), "id": str(rid)}}


# ---------------------------------------------------------------------------
# Helpers shared with assets_from_inventory.py (kept duplicated there so each
# script stays self-contained).
# ---------------------------------------------------------------------------

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ssh": 22, "ldap": 389, "ldaps": 636}


def origin_of(u):
    """Canonical site/service URL: scheme + host (+ non-default port), no path."""
    parts = urlsplit(u)
    if not parts.scheme or not parts.hostname:
        raise ValueError("not an absolute URL: %r" % u)
    netloc = parts.hostname
    if parts.port and parts.port != DEFAULT_PORTS.get(parts.scheme):
        netloc = "%s:%d" % (parts.hostname, parts.port)
    return "%s://%s" % (parts.scheme, netloc)


def guess_resource_scheme(rid):
    rid = str(rid)
    if rid.startswith("arn:"):
        return "arn"
    if rid.startswith("pkg:"):
        return "purl"
    if rid.startswith("//") or rid.startswith("projects/"):
        return "gcp"
    if rid.startswith("/subscriptions/"):
        return "azure"
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Print a rupu `coordinates` JSON array for a host, service, "
        "url, route, cloud resource, or file."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_host = sub.add_parser("host", help="a hostname or IP -> [host]")
    p_host.add_argument("host")

    p_svc = sub.add_parser("service", help="host + port -> [host, port]")
    p_svc.add_argument("host")
    p_svc.add_argument("port", type=int)
    p_svc.add_argument("--proto", default="tcp", choices=PROTOS)

    p_url = sub.add_parser("url", help="a URL -> [url] (canonicalized to its origin)")
    p_url.add_argument("url")
    p_url.add_argument(
        "--raw", action="store_true", help="emit the URL verbatim instead of its origin"
    )

    p_route = sub.add_parser(
        "route", help="site url + method + path -> [url, http_route(, param...)]"
    )
    p_route.add_argument("url", help="site/service URL; canonicalized to its origin")
    p_route.add_argument("method", help="HTTP method, e.g. GET or POST")
    p_route.add_argument("path", help="route path, templated, e.g. /v1/users/{id}")
    p_route.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="NAME",
        help="append a param coordinate (repeatable)",
    )

    p_res = sub.add_parser("resource", help="a cloud resource / purl / id -> [resource_id]")
    p_res.add_argument("id", help="e.g. arn:aws:s3:::acme-logs or pkg:npm/lodash@4.17.20")
    p_res.add_argument(
        "--scheme", help="override scheme (default: inferred — arn/purl/gcp/azure)"
    )

    p_file = sub.add_parser(
        "file", help="a file (+ optional lines/symbol/commit/sha256) -> [path, ...]"
    )
    p_file.add_argument("path")
    p_file.add_argument("--start", type=int, help="first line (enables line_range)")
    p_file.add_argument("--end", type=int, help="last line (defaults to --start)")
    p_file.add_argument("--symbol", help="append a symbol coordinate")
    p_file.add_argument("--commit", help="append a commit coordinate")
    p_file.add_argument("--sha256", help="append a sha256 coordinate")

    args = ap.parse_args(argv)
    coords = []

    if args.cmd == "host":
        coords = [host(args.host)]
    elif args.cmd == "service":
        coords = [host(args.host), port(args.port, args.proto)]
    elif args.cmd == "url":
        coords = [url(args.url if args.raw else origin_of(args.url))]
    elif args.cmd == "route":
        coords = [url(origin_of(args.url)), http_route(args.method, args.path)]
        coords += [param(p) for p in args.param]
    elif args.cmd == "resource":
        scheme = args.scheme or guess_resource_scheme(args.id)
        if not scheme:
            ap.error(
                "cannot infer scheme for %r — pass --scheme (e.g. arn, purl, gcp, azure, objective)"
                % args.id
            )
        coords = [resource_id(scheme, args.id)]
    elif args.cmd == "file":
        coords = [path(args.path)]
        if args.start is not None:
            coords.append(line_range(args.start, args.end))
        elif args.end is not None:
            ap.error("--end requires --start")
        if args.symbol:
            coords.append(symbol(args.symbol))
        if args.commit:
            coords.append(commit(args.commit))
        if args.sha256:
            coords.append(sha256(args.sha256))

    json.dump(coords, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(2)
