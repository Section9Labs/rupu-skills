#!/usr/bin/env python3
"""Normalize an OpenAPI 2.0 / 3.x or Postman Collection v2.1 JSON document
into a request set: one JSON record per operation with a ready-to-send
request template.

Usage:
  python3 scripts/parse_spec.py reports/spec-raw.json -o reports/api-request-set.json
  python3 scripts/parse_spec.py collection.json --base https://api.example.com
  python3 scripts/parse_spec.py collection.json --env postman_environment.json

YAML specs: convert first with `yq -o=json spec.yaml > spec.json`.
Only local `#/...` $refs are resolved; external refs are listed in
`unresolved_refs` and never fetched. Python 3 standard library only.
"""

import argparse
import json
import re
import sys

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
MAX_DEPTH = 10


# ---------------------------------------------------------------- $ref / schema

def json_pointer_get(root, pointer):
    """Resolve a local JSON Pointer like #/components/schemas/Order."""
    node = root
    for raw in pointer[2:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def deref(node, root, unresolved):
    """Follow a chain of top-level $refs (local only, cycle-guarded)."""
    seen = set()
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            unresolved.add(str(ref))
            return {}
        if ref in seen:
            return {}
        seen.add(ref)
        target = json_pointer_get(root, ref)
        if target is None:
            unresolved.add(ref)
            return {}
        node = target
    return node if isinstance(node, dict) else {}


FORMAT_EXAMPLES = {
    "date-time": "2024-01-01T00:00:00Z",
    "date": "2024-01-01",
    "time": "00:00:00Z",
    "email": "user@example.com",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "uri": "https://example.com/",
    "url": "https://example.com/",
    "hostname": "example.com",
    "ipv4": "192.0.2.10",
    "ipv6": "2001:db8::1",
    "byte": "ZGF0YQ==",
    "binary": "data",
    "password": "Passw0rd!",
}


def synth(schema, root, unresolved, depth=0):
    """Synthesize an example value from a JSON Schema fragment."""
    if depth > MAX_DEPTH or not isinstance(schema, dict):
        return None
    if "$ref" in schema:
        return synth(deref(schema, root, unresolved), root, unresolved, depth + 1)
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    ex = schema.get("examples")
    if isinstance(ex, list) and ex:
        return ex[0]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    if "allOf" in schema:
        merged = {}
        scalar = None
        for sub in schema["allOf"]:
            v = synth(sub, root, unresolved, depth + 1)
            if isinstance(v, dict):
                merged.update(v)
            elif v is not None:
                scalar = v
        return merged if merged else scalar
    for key in ("oneOf", "anyOf"):
        if isinstance(schema.get(key), list) and schema[key]:
            return synth(schema[key][0], root, unresolved, depth + 1)
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    if t is None:
        if "properties" in schema:
            t = "object"
        elif "items" in schema:
            t = "array"
    if t == "object" or t is None and schema.get("additionalProperties"):
        out = {}
        for name, sub in (schema.get("properties") or {}).items():
            out[name] = synth(sub, root, unresolved, depth + 1)
        return out
    if t == "array":
        item = synth(schema.get("items") or {}, root, unresolved, depth + 1)
        return [item] if item is not None else []
    if t == "string":
        return FORMAT_EXAMPLES.get(schema.get("format", ""), "string")
    if t == "integer":
        return schema.get("minimum", 1)
    if t == "number":
        return schema.get("minimum", 1.0)
    if t == "boolean":
        return True
    return None


def resource_of(path):
    segs = [s for s in path.split("/")
            if s and not s.startswith("{") and not s.startswith(":")]
    for s in segs:
        if s.lower() != "api" and not re.fullmatch(r"v\d+(\.\d+)?", s, re.I):
            return s
    return segs[0] if segs else "root"


# ---------------------------------------------------------------- OpenAPI

def base_url_openapi(doc, override):
    if override:
        return override.rstrip("/")
    if "swagger" in doc:
        schemes = doc.get("schemes") or ["https"]
        host = doc.get("host") or "SET-BASE-URL"
        return (schemes[0] + "://" + host + doc.get("basePath", "")).rstrip("/")
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", "/"))
        for name, var in (servers[0].get("variables") or {}).items():
            url = url.replace("{%s}" % name, str(var.get("default", name)))
        return url.rstrip("/")
    return "SET-BASE-URL"


def security_schemes(doc):
    if "swagger" in doc:
        return doc.get("securityDefinitions") or {}
    return (doc.get("components") or {}).get("securitySchemes") or {}


def describe_security(sec_req, schemes):
    """Map a security requirement list to descriptor dicts."""
    out = []
    for req in sec_req or []:
        if not isinstance(req, dict):
            continue
        for name, scopes in req.items():
            d = schemes.get(name) or {}
            out.append({
                "name": name,
                "type": d.get("type", "unknown"),
                "scheme": d.get("scheme"),
                "in": d.get("in"),
                "param": d.get("name"),
                "scopes": scopes or [],
            })
    return out


def param_value(param, root, unresolved):
    if "example" in param:
        return param["example"]
    if "schema" in param:
        return synth(param["schema"], root, unresolved)
    mini = {k: param[k] for k in ("type", "format", "enum", "default", "items")
            if k in param}
    return synth(mini, root, unresolved) if mini else "value"


def pick_media(content):
    if not isinstance(content, dict) or not content:
        return None, None
    for ct in ("application/json", "application/x-www-form-urlencoded",
               "multipart/form-data"):
        if ct in content:
            return ct, content[ct]
    ct = sorted(content)[0]
    return ct, content[ct]


def normalize_openapi(doc, base_override):
    is_v2 = "swagger" in doc
    base = base_url_openapi(doc, base_override)
    schemes = security_schemes(doc)
    root_sec = doc.get("security")
    records = []

    for path, raw_item in sorted((doc.get("paths") or {}).items()):
        unresolved_item = set()
        item = deref(raw_item, doc, unresolved_item)
        shared_params = item.get("parameters") or []
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            unresolved = set(unresolved_item)
            params = [deref(p, doc, unresolved)
                      for p in shared_params + (op.get("parameters") or [])]
            path_p, query_p, header_p = [], [], []
            body, content_type, form = None, None, {}
            for p in params:
                loc = p.get("in")
                entry = {"name": p.get("name"),
                         "required": bool(p.get("required")),
                         "example": param_value(p, doc, unresolved)}
                if loc == "path":
                    path_p.append(entry)
                elif loc == "query":
                    query_p.append(entry)
                elif loc == "header":
                    header_p.append(entry)
                elif loc == "formData":
                    form[p.get("name")] = entry["example"]
                elif loc == "body":
                    body = synth(p.get("schema") or {}, doc, unresolved)
                    content_type = "application/json"
            if form:
                body = form
                consumes = op.get("consumes") or doc.get("consumes") or []
                content_type = ("multipart/form-data"
                                if "multipart/form-data" in consumes
                                else "application/x-www-form-urlencoded")
            if not is_v2 and "requestBody" in op:
                rb = deref(op["requestBody"], doc, unresolved)
                ct, media = pick_media(rb.get("content"))
                if media is not None:
                    content_type = ct
                    if "example" in media:
                        body = media["example"]
                    elif isinstance(media.get("examples"), dict) and media["examples"]:
                        first = media["examples"][sorted(media["examples"])[0]]
                        body = deref(first, doc, unresolved).get("value")
                    else:
                        body = synth(media.get("schema") or {}, doc, unresolved)

            sec_req = op.get("security", root_sec)
            security = describe_security(sec_req, schemes)
            headers = {"Accept": "application/json"}
            if content_type:
                headers["Content-Type"] = content_type
            for h in header_p:
                headers[h["name"]] = str(h["example"])

            url_example = base + path
            for p in path_p:
                v = p["example"]
                url_example = url_example.replace(
                    "{%s}" % p["name"], str(v if v is not None else 1))

            records.append({
                "id": "op-%04d" % (len(records) + 1),
                "operation_id": op.get("operationId"),
                "method": method.upper(),
                "path": path,
                "url": base + path,
                "url_example": url_example,
                "resource": resource_of(path),
                "path_params": path_p,
                "query_params": query_p,
                "header_params": header_p,
                "headers": headers,
                "body": body,
                "content_type": content_type,
                "security": security,
                "no_auth": not security,
                "unresolved_refs": sorted(unresolved),
                "tags": op.get("tags") or [],
                "source": "swagger2" if is_v2 else "openapi3",
            })
    return records


# ---------------------------------------------------------------- Postman

VAR_RE = re.compile(r"\{\{([^}]+)\}\}")


def pm_substitute(text, variables):
    def repl(m):
        return str(variables.get(m.group(1).strip(), m.group(0)))
    return VAR_RE.sub(repl, text) if isinstance(text, str) else text


def pm_collect(items, out, folder=""):
    for it in items or []:
        if not isinstance(it, dict):
            continue
        if "item" in it:
            pm_collect(it["item"], out, folder + "/" + str(it.get("name", "")))
        elif "request" in it:
            out.append((folder, it))


def pm_url(url, variables):
    """Return (full_url, path, query_params, path_params)."""
    if isinstance(url, str):
        full = pm_substitute(url, variables)
        no_q = full.split("?")[0]
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+(/.*)?$", no_q)
        path = (m.group(1) or "/") if m else no_q
        return full, path, [], []
    url = url or {}
    raw = url.get("raw")
    host = url.get("host")
    if isinstance(host, list):
        host = ".".join(str(h) for h in host)
    segs = url.get("path") or []
    if isinstance(segs, str):
        segs = segs.strip("/").split("/")
    path = "/" + "/".join(str(s) for s in segs)
    if raw:
        full = pm_substitute(str(raw).split("?")[0], variables)
    else:
        proto = url.get("protocol") or "https"
        port = (":" + str(url["port"])) if url.get("port") else ""
        full = pm_substitute("%s://%s%s%s" % (proto, host or "example.com", port, path),
                             variables)
    query = [{"name": q.get("key"), "required": False,
              "example": pm_substitute(q.get("value", ""), variables)}
             for q in url.get("query") or [] if not q.get("disabled")]
    path_vars = [{"name": v.get("key"), "required": True,
                  "example": pm_substitute(v.get("value", "1"), variables)}
                 for v in url.get("variable") or []]
    return full, path, query, path_vars


def pm_body(body, variables):
    if not isinstance(body, dict):
        return None, None
    mode = body.get("mode")
    if mode == "raw":
        raw = pm_substitute(body.get("raw", ""), variables)
        lang = ((body.get("options") or {}).get("raw") or {}).get("language", "json")
        try:
            return json.loads(raw), "application/json"
        except ValueError:
            return raw, "application/json" if lang == "json" else "text/plain"
    if mode == "urlencoded":
        data = {p.get("key"): pm_substitute(p.get("value", ""), variables)
                for p in body.get("urlencoded") or [] if not p.get("disabled")}
        return data, "application/x-www-form-urlencoded"
    if mode == "formdata":
        data = {p.get("key"): pm_substitute(p.get("value", p.get("src", "")), variables)
                for p in body.get("formdata") or [] if not p.get("disabled")}
        return data, "multipart/form-data"
    if mode == "graphql":
        gq = body.get("graphql") or {}
        return {"query": gq.get("query"), "variables": gq.get("variables")}, \
            "application/json"
    if mode == "file":
        return "<file: %s>" % (body.get("file") or {}).get("src"), \
            "application/octet-stream"
    return None, None


def normalize_postman(doc, base_override, env_vars):
    variables = {}
    for v in doc.get("variable") or []:
        if isinstance(v, dict) and v.get("key") is not None:
            variables[v["key"]] = v.get("value", "")
    variables.update(env_vars)
    if base_override:
        variables.setdefault("baseUrl", base_override)
        variables.setdefault("base_url", base_override)
    coll_auth = doc.get("auth")
    flat = []
    pm_collect(doc.get("item"), flat)
    records = []
    for folder, it in flat:
        req = it.get("request") or {}
        if isinstance(req, str):
            req = {"method": "GET", "url": req}
        method = str(req.get("method", "GET")).upper()
        full, path, query_p, path_p = pm_url(req.get("url"), variables)
        headers = {}
        header_p = []
        for h in req.get("header") or []:
            if h.get("disabled"):
                continue
            val = pm_substitute(str(h.get("value", "")), variables)
            headers[h.get("key")] = val
            header_p.append({"name": h.get("key"), "required": False, "example": val})
        body, content_type = pm_body(req.get("body"), variables)
        if content_type and "Content-Type" not in headers:
            headers["Content-Type"] = content_type
        auth = req.get("auth") or coll_auth
        atype = (auth or {}).get("type", "noauth")
        security = [] if atype in ("noauth", None) else \
            [{"name": atype, "type": "postman-auth", "scheme": atype,
              "in": None, "param": None, "scopes": []}]
        url_example = full
        for p in path_p:
            url_example = url_example.replace(":" + str(p["name"]), str(p["example"]))
        records.append({
            "id": "op-%04d" % (len(records) + 1),
            "operation_id": (folder + "/" + str(it.get("name", ""))).strip("/"),
            "method": method,
            "path": path,
            "url": full,
            "url_example": url_example,
            "resource": resource_of(path),
            "path_params": path_p,
            "query_params": query_p,
            "header_params": header_p,
            "headers": headers,
            "body": body,
            "content_type": content_type,
            "security": security,
            "no_auth": not security,
            "unresolved_refs": sorted(set(VAR_RE.findall(json.dumps(full)))),
            "tags": [folder.strip("/")] if folder.strip("/") else [],
            "source": "postman-2.1",
        })
    return records


# ---------------------------------------------------------------- main

def load_env(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    out = {}
    for v in doc.get("values") or []:
        if isinstance(v, dict) and v.get("enabled", True) and v.get("key"):
            out[v["key"]] = v.get("value", "")
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Normalize OpenAPI/Swagger or Postman v2.1 JSON into a request set.")
    ap.add_argument("spec", help="Path to the spec/collection JSON file")
    ap.add_argument("--base", help="Override/supply the base URL "
                                   "(required when servers[].url is relative)")
    ap.add_argument("--env", help="Postman environment export JSON (values[])")
    ap.add_argument("-o", "--output", help="Write the request set here "
                                           "(default: stdout)")
    args = ap.parse_args()

    with open(args.spec, encoding="utf-8") as f:
        doc = json.load(f)

    env_vars = load_env(args.env) if args.env else {}

    if isinstance(doc, dict) and (
            "swagger" in doc or "openapi" in doc):
        records = normalize_openapi(doc, args.base)
    elif isinstance(doc, dict) and "collection/v2" in str(
            (doc.get("info") or {}).get("schema", "")):
        records = normalize_postman(doc, args.base, env_vars)
    else:
        sys.stderr.write("error: not OpenAPI 2/3 JSON or Postman v2.x JSON "
                         "(YAML? convert with: yq -o=json)\n")
        return 2

    out = json.dumps(records, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)

    no_auth = [r for r in records if r["no_auth"]]
    unresolved = sorted({u for r in records for u in r["unresolved_refs"]})
    by_method = {}
    for r in records:
        by_method[r["method"]] = by_method.get(r["method"], 0) + 1
    sys.stderr.write("operations: %d  (%s)\n" % (
        len(records), ", ".join("%s=%d" % kv for kv in sorted(by_method.items()))))
    sys.stderr.write("no-auth operations: %d\n" % len(no_auth))
    for r in no_auth[:25]:
        sys.stderr.write("  !! %s %s\n" % (r["method"], r["path"]))
    if unresolved:
        sys.stderr.write("unresolved refs/vars (%d): %s\n"
                         % (len(unresolved), ", ".join(unresolved[:10])))
    if args.output:
        sys.stderr.write("request set -> %s\n" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
