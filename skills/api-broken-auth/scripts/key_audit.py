#!/usr/bin/env python3
"""key_audit.py - API key enforcement and placement audit (api-broken-auth).

Given one captured request that authenticates with an API key, replays it
with the key removed, blanked, randomized, truncated, case-flipped, and
moved between header/query/cookie/Authorization-Bearer placements. Reports
every variant the server still accepts, writes a JSON report and a
rupu-ingestible work-unit file (atomic writes).

Examples:
  python3 scripts/key_audit.py \
      --url https://api.example.com/v1/orders --method GET \
      --key 9f3b2a7c41d6e8f0 --placement header --header-name X-API-Key

  python3 scripts/key_audit.py \
      --url 'https://api.example.com/v1/orders?api_key=9f3b2a7c41d6e8f0' \
      --key 9f3b2a7c41d6e8f0 --placement query --query-name api_key \
      --method POST --data '{"q":1}' --content-type application/json \
      --out reports/api-broken-auth-key-audit.json \
      --units-out reports/api-broken-auth-key-units.json
"""

import argparse
import json
import os
import random
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

TITLE_HINTS = {
    "api-key-not-enforced": ["request accepted with no API key",
                             "confirm data exposure, mark endpoint exploited",
                             "report via finding-report with http_exchange"],
    "api-key-not-validated": ["mutated key accepted (blank/random/truncated/case)",
                              "key comparison is weak; attempt key brute force"],
    "api-key-accepted-in-query": ["key accepted as query parameter",
                                  "logs/history/referer exposure; hunt leaked keys"],
    "api-key-placement-flexible": ["key accepted in alternate placement",
                                   "informational; widens leakage surface"],
    "baseline-rejected": ["baseline keyed request was not accepted",
                          "verify the key and placement before trusting results"],
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def atomic_write(path, obj):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def strip_query_param(url, name):
    parts = urllib.parse.urlsplit(url)
    q = [(k, v) for k, v in
         urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
         if k != name]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))


def add_query_param(url, name, value):
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q.append((name, value))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))


def send(url, method, headers, body, timeout, insecure):
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    data = body.encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read() or b""
        status = e.code
    except Exception as e:
        return {"status": None, "length": 0,
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                "error": str(e)[:200], "snippet": ""}
    return {"status": status, "length": len(raw),
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
            "snippet": raw[:160].decode("utf-8", "replace")}


def build_request(args, base_headers, base_cookies, placement, key):
    """placement in {header, query, cookie, bearer, none}; key None = absent."""
    url = strip_query_param(args.url, args.query_name)
    headers = dict(base_headers)
    cookies = dict(base_cookies)
    headers.pop(args.header_name, None)
    cookies.pop(args.cookie_name, None)
    if key is not None and placement != "none":
        if placement == "header":
            headers[args.header_name] = key
        elif placement == "query":
            url = add_query_param(url, args.query_name, key)
        elif placement == "cookie":
            cookies[args.cookie_name] = key
        elif placement == "bearer":
            headers["Authorization"] = "Bearer " + key
    if cookies:
        headers["Cookie"] = "; ".join("%s=%s" % kv for kv in cookies.items())
    if args.data is not None and args.content_type:
        headers["Content-Type"] = args.content_type
    return url, headers


def accepted(result):
    s = result.get("status")
    return s is not None and 200 <= s < 300


def main():
    ap = argparse.ArgumentParser(description="API key enforcement/placement audit")
    ap.add_argument("--url", required=True, help="full request URL (include the query key if placement=query)")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--key", required=True, help="the valid API key value")
    ap.add_argument("--placement", default="header", choices=["header", "query", "cookie"],
                    help="where the key normally travels")
    ap.add_argument("--header-name", default="X-API-Key")
    ap.add_argument("--query-name", default="api_key")
    ap.add_argument("--cookie-name", default="api_key")
    ap.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                    help="extra non-auth header, repeatable")
    ap.add_argument("--cookie", action="append", default=[], metavar="name=value",
                    help="extra cookie, repeatable")
    ap.add_argument("--data", default=None, help="request body")
    ap.add_argument("--content-type", default=None)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between variants")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--out", default="reports/api-broken-auth-key-audit.json")
    ap.add_argument("--units-out", default="reports/api-broken-auth-key-units.json")
    args = ap.parse_args()

    base_headers = {}
    for h in args.header:
        name, _, val = h.partition(":")
        base_headers[name.strip()] = val.strip()
    base_cookies = {}
    for c in args.cookie:
        name, _, val = c.partition("=")
        base_cookies[name.strip()] = val

    rand_key = "".join(random.choices("0123456789abcdef", k=max(len(args.key), 8)))
    variants = [
        ("baseline", args.placement, args.key),
        ("key-removed", "none", None),
        ("key-blank", args.placement, ""),
        ("key-random", args.placement, rand_key),
        ("key-truncated", args.placement, args.key[:-1]),
    ]
    if args.key.swapcase() != args.key:
        variants.append(("key-case-flipped", args.placement, args.key.swapcase()))
    for p in ("header", "query", "cookie"):
        if p != args.placement:
            variants.append(("moved-to-" + p, p, args.key))
    variants.append(("authorization-bearer", "bearer", args.key))

    results = []
    print("%-22s %-6s %-8s %-9s" % ("variant", "status", "length", "ms"))
    for name, placement, key in variants:
        url, headers = build_request(args, base_headers, base_cookies, placement, key)
        res = send(url, args.method, headers, args.data, args.timeout, args.insecure)
        res.update({"variant": name, "placement": placement, "url": url,
                    "accepted": accepted(res)})
        results.append(res)
        print("%-22s %-6s %-8s %-9s %s" % (
            name, res.get("status"), res.get("length"),
            res.get("elapsed_ms"), "ACCEPTED" if res["accepted"] else ""))
        if args.delay:
            time.sleep(args.delay)

    by_name = {r["variant"]: r for r in results}
    findings = []
    if not by_name["baseline"]["accepted"]:
        findings.append("baseline-rejected")
    if by_name.get("key-removed", {}).get("accepted"):
        findings.append("api-key-not-enforced")
    weak = [v for v in ("key-blank", "key-random", "key-truncated", "key-case-flipped")
            if by_name.get(v, {}).get("accepted")]
    if weak:
        findings.append("api-key-not-validated")
    if by_name.get("moved-to-query", {}).get("accepted"):
        findings.append("api-key-accepted-in-query")
    flex = [v for v in ("moved-to-header", "moved-to-cookie", "authorization-bearer")
            if by_name.get(v, {}).get("accepted")]
    if flex:
        findings.append("api-key-placement-flexible")

    target = ("%s %s" % (args.method.upper(), args.url))[:512]
    units = []
    for i, title in enumerate(findings, 1):
        extra = []
        if title == "api-key-not-validated":
            extra = ["accepted variants: " + ",".join(weak)]
        if title == "api-key-placement-flexible":
            extra = ["accepted variants: " + ",".join(flex)]
        units.append({"id": "kau-%03d" % i, "title": title,
                      "targets": [target] + [e[:256] for e in extra],
                      "hints": TITLE_HINTS[title]})

    report = {"tool": "key_audit", "method": args.method.upper(), "url": args.url,
              "placement": args.placement, "results": results, "findings": findings}
    atomic_write(args.out, report)
    atomic_write(args.units_out, units)
    print("\nfindings: %s" % (", ".join(findings) or "none"))
    print("report: %s\nunits:  %s" % (args.out, args.units_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
