#!/usr/bin/env python3
"""split.py -- normalize one tool's output into a clean JSON array of work units.

Usage:
    python3 scripts/split.py <kind> [INPUT] [-o OUT] [kind options]

Kinds: nmap, naabu, httpx, openapi, sarif, prowler, json
INPUT defaults to stdin ("-"), OUT defaults to stdout.

Output contract: exactly one JSON array of {"id","title","targets","hints"}
objects on stdout / OUT. All diagnostics go to stderr. Reading is forgiving
(bad JSONL lines are skipped with a note), writing is strict.

Stdlib only. Each unit id is derived deterministically from the unit's
tool-agnostic identity so re-runs are stable and merge.py can dedup across
tools.
"""

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
CWE_RE = re.compile(r"(?i)\bCWE[-_: ]?(\d+)\b")


# ---------------------------------------------------------------- plumbing

def note(msg):
    sys.stderr.write("split: %s\n" % msg)


def unit_id(*parts):
    """Deterministic slug-safe id: slug(identity)[:48] + '-' + sha1(identity)[:8]."""
    identity = "|".join("" if p is None else str(p) for p in parts)
    slug = re.sub(r"[^a-z0-9]+", "-", identity.lower()).strip("-")[:48].rstrip("-")
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:8]
    return "%s-%s" % (slug, digest) if slug else digest


def clean(d):
    """Drop empty values from a dict (keeps 0 and False)."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def make_unit(id_parts, title, targets, hints):
    return {
        "id": unit_id(*id_parts),
        "title": title,
        "targets": [clean(t) for t in targets],
        "hints": clean(hints),
    }


def read_input(path):
    if path in (None, "-"):
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def iter_records(text):
    """Yield dicts from a JSON array, a single JSON object, or JSONL.

    Forgiving: malformed JSONL lines are skipped with a stderr note; a run is
    never aborted because one line is broken.
    """
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(text)
        except ValueError as exc:
            note("input looks like a JSON array but failed to parse: %s" % exc)
            return
        for obj in data:
            if isinstance(obj, dict):
                yield obj
            else:
                note("skipping non-object array element")
        return
    if stripped.startswith("{"):
        # Could be one big JSON object or JSONL of objects; try whole-doc first.
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                yield obj
                return
        except ValueError:
            pass
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            note("skipping malformed JSONL line %d" % lineno)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            note("skipping non-object JSONL line %d" % lineno)


def merge_hints(base, extra):
    for k, v in extra.items():
        if k not in base:
            base[k] = v
        elif isinstance(base[k], list) and isinstance(v, list):
            for item in v:
                if item not in base[k]:
                    base[k].append(item)
        # conflicting scalars: first one wins
    return base


def finalize(units):
    """Collapse duplicate ids inside one run (same host:port seen twice, etc.)."""
    by_id, order = {}, []
    for u in units:
        uid = u["id"]
        if uid not in by_id:
            by_id[uid] = u
            order.append(uid)
            continue
        kept = by_id[uid]
        for t in u["targets"]:
            if t not in kept["targets"]:
                kept["targets"].append(t)
        merge_hints(kept["hints"], u["hints"])
    return [by_id[uid] for uid in order]


def write_output(units, out):
    text = json.dumps(units, indent=2, sort_keys=False) + "\n"
    if out in (None, "-"):
        sys.stdout.write(text)
    else:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
    note("wrote %d work units%s" % (len(units), "" if out in (None, "-") else " to %s" % out))


# ---------------------------------------------------------------- kind: nmap

def kind_nmap(text, args):
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        note("nmap XML parse error: %s" % exc)
        return []
    units = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None
        addr = addr or hostname
        if not addr:
            continue
        services = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")

            def sattr(key):
                return svc.get(key) if svc is not None else None

            scripts = {}
            for script in port.findall("script"):
                out = (script.get("output") or "").strip()
                scripts[script.get("id")] = out[:400]
            services.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol", "tcp"),
                "service": sattr("name"),
                "product": sattr("product"),
                "version": sattr("version"),
                "extrainfo": sattr("extrainfo"),
                "tunnel": sattr("tunnel"),
                "scripts": scripts,
            })
        if not services:
            continue
        if args.group_by_host:
            targets = [{"type": "host", "value": addr}]
            summary = []
            for s in services:
                targets.append({
                    "type": "service", "value": "%s:%d" % (addr, s["port"]),
                    "host": addr, "port": s["port"], "protocol": s["protocol"],
                })
                summary.append(clean({
                    "port": s["port"], "protocol": s["protocol"],
                    "service": s["service"], "product": s["product"],
                    "version": s["version"],
                }))
            units.append(make_unit(
                ("host", addr),
                "%s (%d open services)" % (addr, len(services)),
                targets,
                {"hostname": hostname, "services": summary, "source": "nmap"},
            ))
            continue
        for s in services:
            hostport = "%s:%d" % (addr, s["port"])
            title = "%s/%s %s" % (hostport, s["protocol"], s["service"] or "unknown")
            if s["product"]:
                title += " (%s%s)" % (s["product"], " " + s["version"] if s["version"] else "")
            units.append(make_unit(
                ("service", addr, s["port"], s["protocol"]),
                title,
                [
                    {"type": "host", "value": addr},
                    {"type": "service", "value": hostport, "host": addr,
                     "port": s["port"], "protocol": s["protocol"]},
                ],
                {
                    "service": s["service"], "product": s["product"],
                    "version": s["version"], "extrainfo": s["extrainfo"],
                    "tunnel": s["tunnel"], "hostname": hostname,
                    "scripts": s["scripts"], "source": "nmap",
                },
            ))
    return units


# ---------------------------------------------------------------- kind: naabu

def kind_naabu(text, args):
    units = []
    for rec in iter_records(text):
        port = rec.get("port")
        if isinstance(port, dict):  # older naabu: {"Port": 80, "Protocol": "tcp"}
            proto = (port.get("Protocol") or "tcp").lower()
            port = port.get("Port")
        else:
            proto = (rec.get("protocol") or "tcp").lower()
        host = rec.get("host")
        ip = rec.get("ip") or host
        if ip is None or port is None:
            note("skipping naabu record without ip/port: %r" % (rec,))
            continue
        hostport = "%s:%s" % (ip, port)
        units.append(make_unit(
            ("service", ip, port, proto),
            "%s/%s" % (hostport, proto),
            [
                {"type": "host", "value": ip},
                {"type": "service", "value": hostport, "host": ip,
                 "port": int(port), "protocol": proto},
            ],
            {"hostname": host if host != ip else None,
             "tls": rec.get("tls"), "source": "naabu"},
        ))
    return units


# ---------------------------------------------------------------- kind: httpx

def kind_httpx(text, args):
    units = []
    for rec in iter_records(text):
        url = rec.get("url") or rec.get("final_url") or rec.get("final-url")
        if not url:
            note("skipping httpx record without url")
            continue
        host = rec.get("host")
        port = rec.get("port")
        targets = [{"type": "url", "value": url}]
        if host:
            targets.append({"type": "host", "value": host})
        if host and port:
            targets.append({
                "type": "service", "value": "%s:%s" % (host, port),
                "host": host, "port": int(port), "protocol": "tcp",
            })
        bits = [url]
        if rec.get("status_code") is not None:
            bits.append("[%s]" % rec["status_code"])
        if rec.get("title"):
            bits.append("%r" % rec["title"])
        if rec.get("webserver"):
            bits.append("(%s)" % rec["webserver"])
        units.append(make_unit(
            ("url", url),
            " ".join(bits),
            targets,
            {
                "scheme": rec.get("scheme"),
                "status_code": rec.get("status_code"),
                "title": rec.get("title"),
                "webserver": rec.get("webserver"),
                "tech": rec.get("tech"),
                "content_type": rec.get("content_type"),
                "content_length": rec.get("content_length"),
                "location": rec.get("location"),
                "final_url": rec.get("final_url") or rec.get("final-url"),
                "ips": rec.get("a"),
                "cnames": rec.get("cname"),
                "cdn_name": rec.get("cdn_name"),
                "input": rec.get("input"),
                "source": "httpx",
            },
        ))
    return units


# ---------------------------------------------------------------- kind: openapi

def kind_openapi(text, args):
    try:
        doc = json.loads(text)
    except ValueError as exc:
        note("OpenAPI parse error: %s -- YAML specs must be converted to JSON "
             "first (the Python stdlib has no YAML parser)" % exc)
        return []
    base = args.base_url
    if not base:
        servers = doc.get("servers") or []
        if servers and isinstance(servers[0], dict):
            base = servers[0].get("url", "")
        elif doc.get("host"):  # Swagger 2
            scheme = (doc.get("schemes") or ["https"])[0]
            base = "%s://%s%s" % (scheme, doc["host"], doc.get("basePath", ""))
        else:
            base = ""
    base = (base or "").rstrip("/")
    api_host = urlsplit(base).netloc or doc.get("host") or "unknown-host"
    doc_security = doc.get("security")
    units = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters") or []
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = []
            for p in list(shared_params) + list(op.get("parameters") or []):
                if not isinstance(p, dict):
                    continue
                if "$ref" in p:
                    params.append({"ref": p["$ref"]})
                else:
                    params.append(clean({
                        "name": p.get("name"), "in": p.get("in"),
                        "required": bool(p.get("required")),
                    }))
            body = op.get("requestBody")
            body_types = sorted((body.get("content") or {}).keys()) \
                if isinstance(body, dict) else None
            m = method.upper()
            targets = [{"type": "http_route", "value": "%s %s" % (m, path),
                        "method": m, "path": path}]
            if base:
                targets.insert(0, {"type": "url", "value": base + path})
            security = op.get("security", doc_security)
            units.append(make_unit(
                ("route", m, path, base),
                "%s %s — %s" % (m, path, api_host),
                targets,
                {
                    "operation_id": op.get("operationId"),
                    "summary": op.get("summary"),
                    "tags": op.get("tags"),
                    "security": security,
                    "unauthenticated": True if security == [] else None,
                    "parameters": params,
                    "request_body_types": body_types,
                    "consumes": op.get("consumes"),  # Swagger 2
                    "deprecated": True if op.get("deprecated") else None,
                    "source": "openapi",
                },
            ))
    return units


# ---------------------------------------------------------------- kind: sarif

def kind_sarif(text, args):
    try:
        doc = json.loads(text)
    except ValueError as exc:
        note("SARIF parse error: %s" % exc)
        return []
    units = []
    for run in doc.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name")
        rule_list = driver.get("rules") or []
        rules_by_id = {r.get("id"): r for r in rule_list if r.get("id")}
        for res in run.get("results") or []:
            rule_id = res.get("ruleId")
            rule = rules_by_id.get(rule_id) or {}
            if not rule and isinstance(res.get("ruleIndex"), int) \
                    and 0 <= res["ruleIndex"] < len(rule_list):
                rule = rule_list[res["ruleIndex"]]
                rule_id = rule_id or rule.get("id")
            props = rule.get("properties") or {}
            tags = props.get("tags") or []
            cwes = sorted({"CWE-%s" % m.group(1) for m in (
                [CWE_RE.search(t) for t in tags if isinstance(t, str)]
                + [CWE_RE.search(str(props.get("cwe", "")))]) if m})
            message = ((res.get("message") or {}).get("text") or "").strip()
            level = res.get("level") \
                or (rule.get("defaultConfiguration") or {}).get("level") \
                or "warning"
            targets, first = [], (None, None, None)
            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri")
                region = phys.get("region") or {}
                if not uri:
                    continue
                if first[0] is None:
                    first = (uri, region.get("startLine"), region.get("startColumn"))
                targets.append({
                    "type": "file", "value": uri,
                    "start_line": region.get("startLine"),
                    "end_line": region.get("endLine"),
                    "start_column": region.get("startColumn"),
                    "snippet": ((region.get("snippet") or {}).get("text") or "")[:200] or None,
                })
            uri, line, col = first
            loc_label = ("%s:%s" % (uri, line)) if line else (uri or "<no location>")
            units.append(make_unit(
                ("code", rule_id, uri, line, col),
                "%s — %s" % (rule_id or "result", loc_label),
                targets or [{"type": "file", "value": "<no location>"}],
                {
                    "rule_id": rule_id,
                    "level": level,
                    "message": message[:500],
                    "rule_name": rule.get("name"),
                    "cwe": cwes,
                    "tags": tags,
                    "security_severity": props.get("security-severity"),
                    "fingerprints": res.get("partialFingerprints"),
                    "tool": tool_name,
                    "source": "sarif",
                },
            ))
    return units


# ---------------------------------------------------------------- kind: prowler

def kind_prowler(text, args):
    units = []
    for rec in iter_records(text):
        fi = rec.get("finding_info") or {}
        meta = rec.get("metadata") or {}
        cloud = rec.get("cloud") or {}
        status = rec.get("status_code") or rec.get("status")
        if args.fail_only and str(status).upper() != "FAIL":
            continue
        check_id = meta.get("event_code")
        if not check_id and not fi:
            note("skipping record that does not look like an OCSF finding")
            continue
        resources = rec.get("resources") or []
        targets = []
        for r in resources:
            targets.append({
                "type": "cloud_resource",
                "value": r.get("uid") or r.get("name"),
                "name": r.get("name"),
                "resource_type": r.get("type"),
                "region": r.get("region"),
            })
        res_name = resources[0].get("name") if resources else None
        title = fi.get("title") or check_id or "finding"
        if res_name:
            title = "%s — %s" % (title, res_name)
        account = (cloud.get("account") or {}).get("uid")
        unmapped = rec.get("unmapped") or {}
        identity = ("finding", fi.get("uid")) if fi.get("uid") else \
            ("finding", check_id, resources[0].get("uid") if resources else None)
        units.append(make_unit(
            identity,
            title,
            targets or [{"type": "cloud_resource", "value": account or "unknown"}],
            {
                "check_id": check_id,
                "check_title": fi.get("title"),
                "status": status,
                "status_detail": rec.get("status_detail"),
                "severity": rec.get("severity"),
                "provider": cloud.get("provider"),
                "region": cloud.get("region"),
                "account": account,
                "compliance": unmapped.get("compliance"),
                "related_url": unmapped.get("related_url"),
                "remediation": ((rec.get("remediation") or {}).get("desc") or "")[:300] or None,
                "risk": (rec.get("risk_details") or "")[:300] or None,
                "finding_uid": fi.get("uid"),
                "types": fi.get("types"),
                "source": "prowler",
            },
        ))
    return units


# ---------------------------------------------------------------- kind: json

TARGET_FIELDS = ("targets", "target", "url", "host", "ip", "endpoint", "asset", "path")
ID_FIELDS = ("id", "uid", "key", "name")
TITLE_FIELDS = ("title", "name", "summary", "message", "description")
TYPE_BY_FIELD = {"url": "url", "host": "host", "ip": "host", "path": "file",
                 "endpoint": "url", "asset": "host", "target": "target",
                 "targets": "target"}


def _coerce_target(value, field):
    ttype = TYPE_BY_FIELD.get(field, "target")
    if isinstance(value, dict):
        if "value" in value:
            return clean(dict({"type": value.get("type", ttype)}, **value))
        return {"type": ttype, "value": json.dumps(value, sort_keys=True)}
    return {"type": ttype, "value": str(value)}


def kind_json(text, args):
    units = []
    for rec in iter_records(text):
        consumed = set()
        rid = None
        if args.id_field:
            rid = rec.get(args.id_field)
            consumed.add(args.id_field)
        if rid is None:
            for k in ID_FIELDS:
                if rec.get(k) not in (None, ""):
                    rid, _ = rec[k], consumed.add(k)
                    break
        title = None
        if args.title_field:
            title = rec.get(args.title_field)
            consumed.add(args.title_field)
        if title is None:
            for k in TITLE_FIELDS:
                if rec.get(k) not in (None, ""):
                    title, _ = str(rec[k]), consumed.add(k)
                    break
        targets = []
        tfields = [args.target_field] if args.target_field else list(TARGET_FIELDS)
        for f in tfields:
            if f not in rec or rec[f] in (None, "", []):
                continue
            consumed.add(f)
            value = rec[f]
            if isinstance(value, list):
                targets.extend(_coerce_target(v, f) for v in value)
            else:
                targets.append(_coerce_target(value, f))
        hints = {k: v for k, v in rec.items() if k not in consumed}
        hints["source"] = hints.get("source", "json")
        if title is None:
            title = targets[0]["value"] if targets else (str(rid) if rid else "record")
        if rid is not None:
            identity = ("json", rid)
        else:
            identity = ("json", hashlib.sha1(
                json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest())
        units.append(make_unit(identity, title,
                               targets or [{"type": "target", "value": str(rid or title)}],
                               hints))
    return units


# ---------------------------------------------------------------- CLI

KINDS = {
    "nmap": kind_nmap,
    "naabu": kind_naabu,
    "httpx": kind_httpx,
    "openapi": kind_openapi,
    "sarif": kind_sarif,
    "prowler": kind_prowler,
    "json": kind_json,
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="split.py",
        description="Normalize tool output into a JSON array of work units.")
    sub = parser.add_subparsers(dest="kind", required=True)
    for kind in KINDS:
        sp = sub.add_parser(kind)
        sp.add_argument("input", nargs="?", default="-",
                        help="input file (default: stdin)")
        sp.add_argument("-o", "--out", default="-",
                        help="output file (default: stdout)")
        if kind == "nmap":
            sp.add_argument("--group-by-host", action="store_true",
                            help="one unit per host instead of per open service")
        if kind == "openapi":
            sp.add_argument("--base-url", default=None,
                            help="override the API server base URL")
        if kind == "prowler":
            sp.add_argument("--fail-only", action="store_true",
                            help="keep only status_code=FAIL findings")
        if kind == "json":
            sp.add_argument("--id-field", default=None)
            sp.add_argument("--title-field", default=None)
            sp.add_argument("--target-field", default=None)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    text = read_input(args.input)
    units = finalize(KINDS[args.kind](text, args))
    write_output(units, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
