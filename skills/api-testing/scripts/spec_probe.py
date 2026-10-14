#!/usr/bin/env python3
"""spec_probe.py - quick first-pass probe for API spec/doc locations.

Part of the api-testing umbrella skill. Checks a base URL for common
OpenAPI/Swagger/Postman/GraphQL documentation locations and writes a
machine-readable summary. The deep hunt (JS bundles, Swagger UI configs,
Postman workspaces) belongs to the api-spec-discovery sub-skill; this script
just answers "is there an obvious spec?" fast.

Usage:
    python3 scripts/spec_probe.py https://api.example.com \
        [-o reports/spec-probe.json] [-H "Authorization: Bearer <tok>"] \
        [-x http://127.0.0.1:8080] [--timeout 10] [--insecure]

Output JSON:
    {"base": "...", "hits": [{"path", "url", "status", "content_type",
                              "kind", "size", "snippet"}, ...],
     "misses": ["/path", ...]}

Exit code 0 if at least one hit, 1 if none, 2 on usage error.
"""

import argparse
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request

SPEC_PATHS = [
    # OpenAPI / Swagger JSON+YAML
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/openapi.json", "/api/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    # springdoc / springfox
    "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/v3/api-docs/swagger-config",
    # well-known
    "/.well-known/openapi.json", "/.well-known/openapi.yaml",
    "/.well-known/schema-discovery",
    # Swagger / docs UIs
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
    "/swagger/", "/docs", "/docs/", "/redoc", "/api/docs",
    "/apidocs", "/apidoc", "/documentation",
    # FastAPI defaults
    "/openapi.json?format=json", "/docs/oauth2-redirect",
    # misc exports
    "/postman.json", "/collection.json", "/api/postman",
    # GraphQL presence (introspection itself is graphql-testing's job)
    "/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
]

MARKERS = [
    ("openapi-3", '"openapi"'),
    ("openapi-3", "openapi:"),
    ("swagger-2", '"swagger"'),
    ("swagger-2", "swagger:"),
    ("swagger-ui", "swagger-ui"),
    ("swagger-ui", "SwaggerUIBundle"),
    ("redoc", "redoc"),
    ("postman", '"_postman_id"'),
    ("graphql", '"errors"'),
    ("graphql", "GraphQL"),
    ("graphiql", "graphiql"),
]


def classify(body, content_type):
    low = body[:4096].lower() if body else ""
    for kind, marker in MARKERS:
        if marker.lower() in low:
            return kind
    if "json" in (content_type or "") and low.strip().startswith("{"):
        return "json-unknown"
    return "unknown"


def fetch(url, headers, timeout, ctx, proxy):
    req = urllib.request.Request(url, headers=headers, method="GET")
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy}))
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(262144)  # 256 KiB is enough to classify
            return (resp.status,
                    resp.headers.get("Content-Type", ""),
                    body.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", body
    except Exception as e:
        return None, "", str(e)


def main():
    ap = argparse.ArgumentParser(description="Probe common API spec locations.")
    ap.add_argument("base", help="Base URL, e.g. https://api.example.com")
    ap.add_argument("-o", "--output", default="reports/spec-probe.json")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="Extra header 'Name: value' (repeatable)")
    ap.add_argument("-x", "--proxy", default=None,
                    help="HTTP proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--insecure", action="store_true",
                    help="Skip TLS certificate verification")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    if not base.startswith(("http://", "https://")):
        print("error: base must start with http:// or https://",
              file=sys.stderr)
        return 2

    headers = {"User-Agent": "spec-probe/1.0", "Accept": "*/*"}
    for h in args.header:
        if ":" not in h:
            print("error: bad header %r" % h, file=sys.stderr)
            return 2
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    ctx = ssl.create_default_context()
    if args.insecure or args.proxy:
        # An intercepting proxy presents its own cert; accept it.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    hits, misses = [], []
    for path in SPEC_PATHS:
        url = base + path
        status, ctype, body = fetch(url, headers, args.timeout, ctx,
                                    args.proxy)
        if status is None:
            misses.append(path)
            continue
        kind = classify(body, ctype)
        interesting = (
            status in (200, 401, 403, 405) and
            (kind != "unknown" or status in (401, 403, 405))
        )
        if status == 200 and kind == "unknown" and len(body) < 64:
            interesting = False
        if interesting:
            hits.append({
                "path": path,
                "url": url,
                "status": status,
                "content_type": ctype.split(";")[0].strip(),
                "kind": kind,
                "size": len(body),
                "snippet": body[:200],
            })
            print("[+] %-40s %s %-12s %s" % (path, status, kind,
                                             ctype.split(";")[0]))
        else:
            misses.append(path)

    result = {"base": base, "hits": hits, "misses": misses}

    outdir = os.path.dirname(args.output) or "."
    os.makedirs(outdir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".spec-probe-", dir=outdir)
    with os.fdopen(fd, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    os.replace(tmp, args.output)  # atomic hand-off for workflow readers

    print("\n%d hit(s), %d miss(es). Written to %s"
          % (len(hits), len(misses), args.output))
    if hits:
        print("Next: load api-spec-discovery to fetch/normalize the spec "
              "into reports/openapi.json, then work-units split.py openapi.")
        return 0
    print("No obvious spec. Next: load api-endpoint-brute (kiterunner).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
