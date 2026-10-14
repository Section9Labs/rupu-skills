#!/usr/bin/env python3
"""introspect.py - GraphQL introspection dumper and operation mapper.

Sends the full introspection query to a GraphQL endpoint. On success it
saves the raw schema JSON, emits a flat operation map (every query /
mutation / subscription with argument types), and writes rupu work units
for fan-out. If introspection is disabled it probes for field-suggestion
leakage ("Did you mean ...") and emits a single schema-recovery unit.

Usage:
  python3 scripts/introspect.py https://api.example.com/graphql \
      -H 'Authorization: Bearer eyJ...' -o reports/

Outputs (written atomically):
  <out>/graphql-schema.json          raw introspection result (InQL/Voyager-ready)
  <out>/graphql-operations.json      normalized operation map (work-units input)
  <out>/graphql-testing-units.json   rupu work-unit array (for_each / dispatch)

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

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name isDeprecated }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name
    ofType { kind name ofType { kind name ofType { kind name
      ofType { kind name } } } } } } }
}
"""

MINIMAL_QUERY = "{__schema{types{name}}}"

# typo'd field probes used to detect field-suggestion leakage
SUGGESTION_PROBES = ["{usr{id}}", "{logn}", "{viewr{id}}", "{nodee{id}}"]

TARGET_CAP = 300  # cap target-derived strings in work units


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


def post_query(opener, url, query, headers, timeout):
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
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


def render_type(t):
    """Render an introspection type ref (ofType chain) as SDL, e.g. [User!]!"""
    if t is None:
        return "?"
    kind = t.get("kind")
    if kind == "NON_NULL":
        return render_type(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + render_type(t.get("ofType")) + "]"
    return t.get("name") or "?"


def extract_operations(schema):
    """Flatten queryType/mutationType/subscriptionType fields."""
    types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    ops = []
    for root_key, op_kind in (
        ("queryType", "query"),
        ("mutationType", "mutation"),
        ("subscriptionType", "subscription"),
    ):
        root = schema.get(root_key)
        if not root or not root.get("name"):
            continue
        root_type = types.get(root["name"])
        if not root_type:
            continue
        for field in root_type.get("fields") or []:
            args = [
                {"name": a["name"], "type": render_type(a.get("type"))}
                for a in field.get("args") or []
            ]
            arg_sig = ", ".join("%s: %s" % (a["name"], a["type"]) for a in args)
            sig = "%s %s(%s): %s" % (
                op_kind,
                field["name"],
                arg_sig,
                render_type(field.get("type")),
            )
            ops.append(
                {
                    "kind": op_kind,
                    "name": field["name"],
                    "args": args,
                    "returns": render_type(field.get("type")),
                    "deprecated": bool(field.get("isDeprecated")),
                    "signature": sig,
                }
            )
    return ops


def build_units(url, ops):
    units = []
    for i, op in enumerate(ops, 1):
        hints = ["authz", "injection"]
        if op["kind"] == "mutation":
            hints.append("batching")
        units.append(
            {
                "id": "gql-%03d" % i,
                "title": "graphql-" + op["kind"],
                "targets": [url[:TARGET_CAP], op["signature"][:TARGET_CAP]],
                "hints": hints,
            }
        )
    return units


def probe_suggestions(opener, url, headers, timeout):
    """Return (enabled, sample_error) for field-suggestion leakage."""
    for probe in SUGGESTION_PROBES:
        status, body = post_query(opener, url, probe, headers, timeout)
        if body is None or status is None:
            continue
        try:
            data = json.loads(body)
        except ValueError:
            continue
        for err in data.get("errors") or []:
            msg = err.get("message", "")
            if "Did you mean" in msg:
                return True, msg
    return False, None


def parse_header(raw):
    if ":" not in raw:
        raise argparse.ArgumentTypeError("header must be 'Name: value'")
    name, _, value = raw.partition(":")
    return name.strip(), value.strip()


def main():
    ap = argparse.ArgumentParser(description="GraphQL introspection dumper")
    ap.add_argument("url", help="GraphQL endpoint, e.g. https://api.example.com/graphql")
    ap.add_argument("-H", "--header", action="append", type=parse_header,
                    default=[], metavar="'Name: value'", help="extra header, repeatable")
    ap.add_argument("-o", "--out", default="reports", help="output directory (default: reports)")
    ap.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--timeout", type=float, default=15.0, help="request timeout seconds")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    args = ap.parse_args()

    opener = build_opener(args.proxy, args.insecure)

    # 1. full introspection, POST
    status, body = post_query(opener, args.url, INTROSPECTION_QUERY, args.header, args.timeout)
    schema = None
    if body:
        try:
            parsed = json.loads(body)
            schema = (parsed.get("data") or {}).get("__schema")
        except ValueError:
            parsed = None

    # 2. fallback: minimal query (some filters only match the full document)
    if schema is None:
        status2, body2 = post_query(opener, args.url, MINIMAL_QUERY, args.header, args.timeout)
        if body2:
            try:
                parsed2 = json.loads(body2)
                schema = (parsed2.get("data") or {}).get("__schema")
                if schema is not None:
                    body = body2
            except ValueError:
                pass

    out = args.out
    if schema is not None:
        atomic_write(os.path.join(out, "graphql-schema.json"), json.loads(body))
        ops = extract_operations(schema)
        atomic_write(
            os.path.join(out, "graphql-operations.json"),
            {"url": args.url, "introspection": True, "operations": ops},
        )
        units = build_units(args.url, ops)
        atomic_write(os.path.join(out, "graphql-testing-units.json"), units)
        print("[+] introspection ENABLED (%d operations)" % len(ops))
        for op in ops:
            print("    " + op["signature"])
        print("[+] wrote %s/graphql-schema.json" % out)
        print("[+] wrote %s/graphql-operations.json" % out)
        print("[+] wrote %s/graphql-testing-units.json (%d units)" % (out, len(units)))
        return 0

    # 3. introspection disabled: probe field suggestions
    print("[-] introspection DISABLED (status=%s)" % status)
    enabled, sample = probe_suggestions(opener, args.url, args.header, args.timeout)
    if enabled:
        print("[+] field suggestions ENABLED -> clairvoyance will work")
        print("    sample: %s" % sample)
    else:
        print("[-] field suggestions not observed; blind recovery will be hard")
    atomic_write(
        os.path.join(out, "graphql-operations.json"),
        {
            "url": args.url,
            "introspection": False,
            "field_suggestions": enabled,
            "suggestion_sample": (sample or "")[:TARGET_CAP],
            "operations": [],
        },
    )
    units = [
        {
            "id": "gql-001",
            "title": "graphql-recon",
            "targets": [args.url[:TARGET_CAP]],
            "hints": ["schema-recovery"] + (["batching", "dos"] if enabled else []),
        }
    ]
    atomic_write(os.path.join(out, "graphql-testing-units.json"), units)
    print("[+] wrote %s/graphql-operations.json" % out)
    print("[+] wrote %s/graphql-testing-units.json (schema-recovery unit)" % out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
