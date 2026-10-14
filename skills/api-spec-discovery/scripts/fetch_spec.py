#!/usr/bin/env python3
"""Probe common API specification locations on a base URL and classify hits.

Usage:
  python3 scripts/fetch_spec.py https://api.example.com
  python3 scripts/fetch_spec.py https://api.example.com \
      -H "Authorization: Bearer TOKEN" -H "X-Api-Key: k" \
      --save reports/spec-raw.json -o reports/spec-probe.json

Python 3 standard library only. Follows redirects. Classifies each response as
OpenAPI 2.0/3.x JSON, OpenAPI YAML, Postman collection, springdoc
swagger-config, Swagger-UI/Redoc HTML (extracting the spec URLs it loads),
OIDC discovery metadata, or a live GraphQL endpoint.
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; api-spec-discovery/1.0)"

PROBE_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/v2/api-docs", "/v2/swagger.json",
    "/v3/api-docs", "/v3/api-docs.yaml", "/v3/api-docs/swagger-config",
    "/api-docs", "/api-docs.json", "/api/api-docs",
    "/api/openapi.json", "/api/swagger.json",
    "/api/v1/openapi.json", "/api/v1/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger-resources", "/swagger-ui.html",
    "/swagger-ui/", "/swagger-ui/index.html",
    "/docs", "/docs/openapi.json", "/docs/swagger.json", "/redoc",
    "/api-json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/graphql", "/graphql/schema", "/graphiql", "/api/graphql",
]

SPEC_KINDS = ("swagger-2.0", "openapi-3", "postman-collection")


def build_opener(insecure):
    handlers = []
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url, headers, timeout, method="GET", data=None):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
    for k, v in headers:
        req.add_header(k, v)
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.getcode(), resp.geturl(), resp.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2 * 1024 * 1024)
        except Exception:
            body = b""
        return e.code, url, body
    except Exception as e:
        return None, url, repr(e).encode()


def extract_ui_spec_urls(text):
    """Pull spec URLs out of Swagger-UI / Redoc init blocks."""
    urls = []
    # SwaggerUIBundle({ url: "...", urls: [{url: "...", name: "..."}] })
    for m in re.finditer(r"""[\s{,]urls?\s*:\s*["']([^"']+)["']""", text):
        urls.append(m.group(1))
    for m in re.finditer(r'"url"\s*:\s*"([^"]+)"', text):
        urls.append(m.group(1))
    # Redoc: <redoc spec-url="..."> or Redoc.init('...')
    for m in re.finditer(r"""spec-url\s*=\s*["']([^"']+)["']""", text):
        urls.append(m.group(1))
    for m in re.finditer(r"""Redoc\.init\(\s*["']([^"']+)["']""", text):
        urls.append(m.group(1))
    out, seen = [], set()
    for u in urls:
        if u not in seen and not u.startswith("data:"):
            seen.add(u)
            out.append(u)
    return out


def classify(path, body, status):
    """Return (kind, extra) for a response body."""
    text = body[:300000].decode("utf-8", "replace")
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            doc = json.loads(stripped)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            if str(doc.get("swagger", "")).startswith("2"):
                return "swagger-2.0", None
            if str(doc.get("openapi", "")).startswith("3"):
                return "openapi-3", str(doc.get("openapi"))
            info = doc.get("info")
            if isinstance(info, dict) and "collection/v2" in str(info.get("schema", "")):
                return "postman-collection", str(info.get("schema"))
            if "urls" in doc or "configUrl" in doc:
                urls = [u.get("url") for u in doc.get("urls", []) if isinstance(u, dict)]
                return "swagger-config", urls
            if "issuer" in doc and ("token_endpoint" in doc or "authorization_endpoint" in doc):
                keys = [k for k in ("issuer", "authorization_endpoint", "token_endpoint",
                                    "jwks_uri", "registration_endpoint") if k in doc]
                return "oidc-discovery", {k: doc[k] for k in keys}
            if "errors" in doc or "data" in doc:
                return "graphql-endpoint", None
        if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "swaggerVersion" in doc[0]:
            return "swagger-resources", [d.get("location") for d in doc]
    if re.search(r"^(openapi|swagger)\s*:", text, re.M):
        return "openapi-yaml", "convert with: yq -o=json <file>"
    low = text.lower()
    if "<html" in low or "<!doctype" in low:
        if "swagger-ui" in low or "swaggeruibundle" in low:
            return "swagger-ui", extract_ui_spec_urls(text)
        if "redoc" in low:
            return "redoc", extract_ui_spec_urls(text)
        return "html", None
    if "must provide query string" in low or "graphql" in low and "query" in low:
        return "graphql-endpoint", None
    return "unknown", None


def main():
    ap = argparse.ArgumentParser(description="Probe common API spec locations.")
    ap.add_argument("base", help="Base URL, e.g. https://api.example.com")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help='Extra header, "Name: value" (repeatable)')
    ap.add_argument("-p", "--path", action="append", default=[],
                    help="Extra path to probe (repeatable)")
    ap.add_argument("--paths-file", help="File with one extra path per line")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Skip TLS certificate verification")
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("--save", help="Save the first real spec body to this file")
    ap.add_argument("-o", "--output", help="Write JSON probe report here")
    args = ap.parse_args()

    headers = []
    for h in args.header:
        name, _, val = h.partition(":")
        headers.append((name.strip(), val.strip()))

    paths = list(PROBE_PATHS) + args.path
    if args.paths_file:
        with open(args.paths_file, encoding="utf-8") as f:
            paths += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    base = args.base.rstrip("/")
    opener = build_opener(args.insecure)
    results = []
    saved = False

    for path in paths:
        url = base + path
        status, final_url, body = fetch(opener, url, headers, args.timeout)
        if status is None:
            results.append({"path": path, "url": url, "status": None,
                            "kind": "error", "extra": body.decode("utf-8", "replace")})
            print("ERR  %-45s %s" % (path, body.decode("utf-8", "replace")[:80]))
            continue
        kind, extra = classify(path, body, status)
        hit = status < 400 and kind not in ("unknown", "html")
        results.append({"path": path, "url": final_url, "status": status,
                        "kind": kind, "bytes": len(body), "extra": extra})
        marker = "HIT " if hit else "    "
        line = "%s %3d  %-45s %s" % (marker, status, path, kind)
        if extra:
            line += "  -> %s" % json.dumps(extra)[:120]
        print(line)
        if hit and args.save and not saved and kind in SPEC_KINDS:
            with open(args.save, "wb") as f:
                f.write(body)
            print("saved %s (%s) -> %s" % (path, kind, args.save))
            saved = True

    hits = [r for r in results if r.get("status") and r["status"] < 400
            and r["kind"] not in ("unknown", "html", "error")]
    report = {"base": base, "probed": len(paths), "hits": hits, "all": results}
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("report -> %s" % args.output)
    print("\n%d/%d paths classified as spec/metadata material" % (len(hits), len(paths)))
    if not hits:
        print("no direct hit: scrape JS bundles / HTML per references/discovery.md")
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
