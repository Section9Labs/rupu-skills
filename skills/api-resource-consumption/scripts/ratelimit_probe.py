#!/usr/bin/env python3
"""ratelimit_probe.py - burst-probe an API endpoint for rate limiting (API4:2023).

Sends a configurable burst of a request template, records status/latency and
rate-limit headers per request, reports the first throttle event (or its
absence), and optionally runs a limiter-bypass pass rotating client-IP headers
and path variants.

Examples:
  python3 scripts/ratelimit_probe.py --url https://api.example.com/v1/login \
      --method POST --header 'Content-Type: application/json' \
      --body '{"email":"probe@example.net","password":"wrong-{{i}}"}' \
      --count 60 --concurrency 5 --bypass \
      --out reports/rl-login.json --units reports/rl-login-units.json
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import ssl
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

THROTTLE_STATUSES = {429, 503, 420}

RL_HEADER_NAMES = [
    "retry-after",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
]

IP_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP",
    "X-Originating-IP", "CF-Connecting-IP", "X-Remote-IP", "X-Remote-Addr",
    "Client-IP",
]


def rand_ip():
    return "{}.{}.{}.{}".format(
        random.randint(1, 223), random.randint(0, 255),
        random.randint(0, 255), random.randint(1, 254))


def parse_headers(pairs):
    headers = {}
    for pair in pairs or []:
        if ":" not in pair:
            raise SystemExit("bad --header (want 'Name: value'): %r" % pair)
        name, _, value = pair.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def substitute(template, n):
    if template is None:
        return None
    out = template.replace("{{i}}", str(n))
    out = out.replace("{{rand}}", "".join(
        random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8)))
    out = out.replace("{{uuid}}", str(uuid.uuid4()))
    out = out.replace("{{ts}}", str(int(time.time())))
    return out


def send_one(url, method, headers, body, timeout, ctx, n):
    data = None
    b = substitute(body, n)
    if b is not None:
        data = b.encode()
    req = urllib.request.Request(url, data=data, method=method)
    for name, value in headers.items():
        req.add_header(name, substitute(value, n))
    start = time.monotonic()
    status, resp_headers, length = 0, {}, 0
    err = None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload = resp.read()
            status = resp.status
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            length = len(payload)
    except urllib.error.HTTPError as e:
        payload = e.read()
        status = e.code
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        length = len(payload)
    except Exception as e:  # noqa: BLE001 - network errors are data here
        err = type(e).__name__
    ms = round((time.monotonic() - start) * 1000.0, 1)
    rl = {h: resp_headers[h] for h in RL_HEADER_NAMES if h in resp_headers}
    return {"n": n, "status": status, "ms": ms, "bytes": length,
            "rl_headers": rl, "error": err}


def is_throttled(result):
    if result["status"] in THROTTLE_STATUSES:
        return True
    if "retry-after" in result["rl_headers"]:
        return True
    return False


def run_burst(args, ctx, headers, count, extra_headers_fn=None, url=None,
              start_n=0):
    """Send `count` requests; return ordered result list."""
    url = url or args.url
    results = []

    def task(n):
        hdrs = dict(headers)
        if extra_headers_fn:
            hdrs.update(extra_headers_fn(n))
        return send_one(url, args.method, hdrs, args.body,
                        args.timeout, ctx, n)

    if args.concurrency <= 1:
        for n in range(start_n, start_n + count):
            results.append(task(n))
            if args.delay:
                time.sleep(args.delay)
    else:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.concurrency) as pool:
            futures = {pool.submit(task, n): n
                       for n in range(start_n, start_n + count)}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())
        results.sort(key=lambda r: r["n"])
    return results


def analyze(baseline, timeline):
    first_throttle = None
    for r in timeline:
        if is_throttled(r):
            first_throttle = r["n"]
            break
    base_ms = statistics.median(r["ms"] for r in baseline) if baseline else 0.0
    ok = [r for r in timeline if r["status"] and not is_throttled(r)]
    tail = [r["ms"] for r in timeline[-5:]]
    tarpit = (first_throttle is None and base_ms > 0 and tail
              and statistics.median(tail) > 5 * base_ms)
    if first_throttle is not None:
        verdict = "throttled"
    elif tarpit:
        verdict = "possible-tarpit"
    else:
        verdict = "no-limit-observed"
    counts = {}
    for r in timeline:
        key = str(r["status"]) if r["status"] else (r["error"] or "error")
        counts[key] = counts.get(key, 0) + 1
    return {
        "verdict": verdict,
        "first_throttle_index": first_throttle,
        "baseline_median_ms": base_ms,
        "tail_median_ms": statistics.median(tail) if tail else None,
        "ok_count": len(ok),
        "status_counts": counts,
        "rl_headers_seen": sorted({h for r in timeline
                                   for h in r["rl_headers"]}),
    }


def path_variants(url):
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    variants = []

    def rebuild(new_path, new_query=None):
        q = parsed.query if new_query is None else new_query
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, new_path, q, parsed.fragment))

    variants.append(("trailing-slash", rebuild(path.rstrip("/") + "/")))
    segs = path.rstrip("/").split("/")
    if segs and segs[-1]:
        swapped = segs[:-1] + [segs[-1].swapcase()]
        variants.append(("case-swap", rebuild("/".join(swapped))))
        dotted = segs[:-1] + ["%2e", segs[-1]]
        variants.append(("dot-segment", rebuild("/".join(dotted))))
    inner = path.lstrip("/")
    if "/" in inner:
        variants.append(("double-slash",
                         rebuild("/" + inner.replace("/", "//", 1))))
    variants.append(("encoded-null", rebuild(path + "%00")))
    extra = "cb=" + uuid.uuid4().hex[:8]
    q = (parsed.query + "&" + extra) if parsed.query else extra
    variants.append(("junk-query", rebuild(path, q)))
    return variants


def bypass_pass(args, ctx, headers, probe_count):
    """After a throttle has fired, try each bypass technique with a short
    burst and report which ones restore non-throttled responses."""
    attempts = []

    def summarize(name, results):
        ok = sum(1 for r in results
                 if r["status"] and not is_throttled(r) and r["status"] < 400)
        throttled = sum(1 for r in results if is_throttled(r))
        return {"technique": name, "sent": len(results), "ok": ok,
                "throttled": throttled,
                "works": ok >= max(1, probe_count // 2) and throttled == 0}

    # 1. rotating client-IP headers
    for hdr in IP_HEADERS:
        results = run_burst(args, ctx, headers, probe_count,
                            extra_headers_fn=lambda n, h=hdr: {h: rand_ip()})
        attempts.append(summarize("ip-header:" + hdr, results))
    results = run_burst(
        args, ctx, headers, probe_count,
        extra_headers_fn=lambda n: {"Forwarded": "for=" + rand_ip()})
    attempts.append(summarize("ip-header:Forwarded", results))

    # 2. path variants
    for name, vurl in path_variants(args.url):
        results = run_burst(args, ctx, headers, probe_count, url=vurl)
        attempts.append(summarize("path:" + name, results))

    # 3. alternate token
    if args.alt_token:
        alt = dict(headers)
        alt["Authorization"] = args.alt_token
        results = run_burst(args, ctx, alt, probe_count)
        attempts.append(summarize("token-rotation", results))

    return attempts


def write_atomic(path, obj):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def build_units(args, analysis, bypass):
    route = "%s %s" % (args.method, urllib.parse.urlsplit(args.url).path)
    units = []
    hints = []
    if args.hint:
        hints.extend(args.hint)
    working = [b["technique"] for b in bypass if b.get("works")]
    if analysis["verdict"] == "no-limit-observed":
        title = "missing-rate-limit"
        hints.append("handoff:api-broken-auth")
    elif working:
        title = "rate-limit-bypass"
        for tech in working:
            if tech.startswith("ip-header"):
                hints.append("bypass:ip-header")
            elif tech.startswith("path"):
                hints.append("bypass:path-variant")
            elif tech == "token-rotation":
                hints.append("bypass:token-rotation")
        hints.append("handoff:api-broken-auth")
    elif analysis["verdict"] == "possible-tarpit":
        title = "possible-tarpit"
    else:
        return units  # throttled, no bypass: nothing to fan out
    units.append({
        "id": slugify("rl-" + route),
        "title": title,
        "targets": [args.url[:200], route[:200]],
        "hints": sorted(set(hints)),
    })
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--header", action="append", default=[],
                    help="request header 'Name: value' (repeatable; "
                         "{{i}}/{{rand}}/{{uuid}}/{{ts}} substituted)")
    ap.add_argument("--body", default=None,
                    help="request body template ({{i}} etc. substituted); "
                         "prefix @ to read from file")
    ap.add_argument("--count", type=int, default=60,
                    help="burst size (default 60)")
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between sequential requests")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--bypass", action="store_true",
                    help="after the burst, run the limiter-bypass pass")
    ap.add_argument("--bypass-count", type=int, default=8,
                    help="requests per bypass technique (default 8)")
    ap.add_argument("--alt-token", default=None,
                    help="alternate Authorization header value for the "
                         "token-rotation bypass test")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--hint", action="append", default=[],
                    help="extra fixed-vocabulary hint for emitted units, "
                         "e.g. --hint auth-endpoint --hint costly-op")
    ap.add_argument("--out", default=None, help="write JSON report here")
    ap.add_argument("--units", default=None,
                    help="write rupu work-unit JSON array here")
    args = ap.parse_args()

    if args.body and args.body.startswith("@"):
        with open(args.body[1:]) as fh:
            args.body = fh.read()

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    headers = parse_headers(args.header)

    # baseline: 3 spaced requests
    baseline = []
    for n in range(3):
        baseline.append(send_one(args.url, args.method, headers, args.body,
                                 args.timeout, ctx, n))
        time.sleep(1.0)

    timeline = run_burst(args, ctx, headers, args.count, start_n=3)
    analysis = analyze(baseline, timeline)

    bypass = []
    if args.bypass:
        if analysis["verdict"] == "throttled":
            bypass = bypass_pass(args, ctx, headers, args.bypass_count)
        else:
            print("[*] no throttle observed; skipping bypass pass "
                  "(nothing to bypass)", file=sys.stderr)

    report = {
        "tool": "ratelimit_probe",
        "url": args.url,
        "method": args.method,
        "count": args.count,
        "concurrency": args.concurrency,
        "baseline": baseline,
        "timeline": timeline,
        "analysis": analysis,
        "bypass": bypass,
    }

    if args.out:
        write_atomic(args.out, report)
        print("[+] report: %s" % args.out, file=sys.stderr)
    if args.units:
        units = build_units(args, analysis, bypass)
        write_atomic(args.units, units)
        print("[+] units: %s (%d)" % (args.units, len(units)),
              file=sys.stderr)

    print(json.dumps({"verdict": analysis["verdict"],
                      "first_throttle_index":
                          analysis["first_throttle_index"],
                      "ok_count": analysis["ok_count"],
                      "status_counts": analysis["status_counts"],
                      "working_bypasses": [b["technique"] for b in bypass
                                           if b.get("works")]},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
