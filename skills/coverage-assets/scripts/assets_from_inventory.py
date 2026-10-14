#!/usr/bin/env python3
"""assets_from_inventory.py — turn a work-units inventory into assets.mark payloads.

Chains the `work-units` skill into `coverage-assets`: reads the normalized
inventory the splitter emits (a JSON array of {id,title,targets,hints} work
units, or a plain array of target strings / simple objects) and emits a JSON
array of ready-to-send `assets.mark` payloads:

    [ { "kind": "...", "coordinates": [{"t":...,"v":...}, ...],
        "depth": "...", "label": "..." }, ... ]

The agent (or a workflow `for_each` step) then calls `assets.mark` once per
payload, exactly as written, seeding the asset ledger with the whole scope at
the first rung before any work starts.

Usage:
  python3 scripts/assets_from_inventory.py --profile network reports/units.json -o reports/marks.json
  cat reports/units.json | python3 scripts/assets_from_inventory.py --profile web --depth mapped
  python3 scripts/assets_from_inventory.py --profile cloud arns.json
  python3 scripts/assets_from_inventory.py --profile api --depth mapped endpoints.json

Accepted item shapes inside the input array:
  "198.51.100.20"                                   bare host/IP
  "198.51.100.0/28"                                 IPv4 CIDR (expanded, <=1024 hosts)
  "198.51.100.20:8443" / "198.51.100.20:53/udp"     host:port[/proto]
  "https://shop.example.com/cart/apply"             URL (origin + route split)
  "arn:aws:s3:::acme-logs" / "pkg:npm/x@1.0.0"      resource ids
  "src/auth/login.py:88-131"                        path[:start-end]
  {"id":"u1","title":"...","targets":[...],"hints":{...}}   work unit
  {"host":"...","port":8443,"proto":"tcp"}          explicit service
  {"host":"...","ports":[80,443]}                   host with ports
  {"url":"...","method":"POST","path":"/x","params":["q"]}  explicit route
  {"scheme":"arn","id":"arn:aws:..."}               explicit resource
  {"path":"...","start":10,"end":24}                file slice
  {"sha256":"<64 hex>"}                             binary/image/package hash

Hints honored (unit-level `hints` dict or per-object keys): proto, method,
params, scheme.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from urllib.parse import urlsplit, parse_qsl

# --------------------------------------------------------------------------
# Profile knowledge: depth ladders and kind names (from rupu's built-ins).
# --------------------------------------------------------------------------

LADDERS = {
    "network": ["discovered", "enumerated", "tested", "exploited"],
    "web": ["mapped", "crawled", "tested", "exploited"],
    "api": ["mapped", "tested", "exploited"],
    "cloud": ["inventoried", "policy-evaluated", "validated"],
    "code": ["unreviewed", "reviewed"],
    "binary": ["located", "disassembled", "analyzed"],
    "firmware": ["acquired", "extracted", "unpacked", "analyzed"],
    "container": ["inventoried", "scanned", "triaged"],
    "sca": ["inventoried", "resolved", "triaged"],
    "iac": ["mapped", "reviewed"],
    "secrets": ["scanned", "triaged", "confirmed"],
    "redteam": ["planned", "executed", "validated"],
}

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ssh": 22, "ldap": 389, "ldaps": 636}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HOSTPORT_RE = re.compile(
    r"^(?P<host>\[?[0-9A-Za-z_.:\-]+\]?):(?P<port>\d{1,5})(?:/(?P<proto>tcp|udp|other))?$"
)
PATHLINES_RE = re.compile(r"^(?P<path>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")
CIDR_EXPAND_LIMIT = 1024

# --- coordinate constructors (duplicated from build_coordinates.py so this
# --- script stays self-contained) ---


def c_path(p):
    return {"t": "path", "v": str(p)}


def c_lines(start, end=None):
    start = int(start)
    return {"t": "line_range", "v": {"start": start, "end": int(end) if end else start}}


def c_sha256(d):
    return {"t": "sha256", "v": str(d).lower()}


def c_host(h):
    return {"t": "host", "v": str(h).strip("[]")}


def c_port(number, proto="tcp"):
    return {"t": "port", "v": {"number": int(number), "proto": str(proto).lower()}}


def c_url(u):
    return {"t": "url", "v": str(u)}


def c_route(method, path):
    return {"t": "http_route", "v": {"method": str(method).upper(), "path": str(path)}}


def c_param(p):
    return {"t": "param", "v": str(p)}


def c_resource(scheme, rid):
    return {"t": "resource_id", "v": {"scheme": str(scheme), "id": str(rid)}}


def origin_of(parts):
    netloc = parts.hostname or ""
    if parts.port and parts.port != DEFAULT_PORTS.get(parts.scheme):
        netloc = "%s:%d" % (parts.hostname, parts.port)
    return "%s://%s" % (parts.scheme, netloc)


def guess_scheme(rid):
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


def warn(msg):
    print("warning: %s" % msg, file=sys.stderr)


def is_url(s):
    return "://" in s


def is_cidr(s):
    try:
        net = ipaddress.ip_network(s, strict=False)
        return "/" in s and net is not None
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Per-profile target classification. Each returns a list of (kind, coords,
# label-suffix) tuples for one target.
# --------------------------------------------------------------------------


def network_assets(target, hints, kind_prefix="network"):
    proto = hints.get("proto", "tcp")
    if is_url(target):
        p = urlsplit(target)
        if not p.hostname:
            warn("unparseable URL target skipped: %r" % target)
            return []
        number = p.port or DEFAULT_PORTS.get(p.scheme)
        if number:
            return [("%s:service" % kind_prefix, [c_host(p.hostname), c_port(number, "tcp")], target)]
        return [("%s:host" % kind_prefix, [c_host(p.hostname)], p.hostname)]
    if is_cidr(target):
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > CIDR_EXPAND_LIMIT:
            warn("%s has %d addresses (> %d); split it upstream with work-units — "
                 "emitting the network address only" % (target, net.num_addresses, CIDR_EXPAND_LIMIT))
            return [("%s:host" % kind_prefix, [c_host(str(net.network_address))], target)]
        hosts = list(net.hosts()) or [net.network_address]
        return [("%s:host" % kind_prefix, [c_host(str(h))], str(h)) for h in hosts]
    m = HOSTPORT_RE.match(target)
    if m and not m.group("host").endswith(":"):  # guard: bare IPv6 is a host, not host:port
        return [("%s:service" % kind_prefix,
                 [c_host(m.group("host")), c_port(m.group("port"), m.group("proto") or proto)],
                 target)]
    return [("%s:host" % kind_prefix, [c_host(target)], target)]


def web_assets(target, hints, include_params, profile="web"):
    site_kind = "%s:%s" % (profile, "site" if profile == "web" else "service")
    route_kind = "%s:%s" % (profile, "route" if profile == "web" else "endpoint")
    if not is_url(target):
        target = "https://" + target  # bare host -> assume https site
    p = urlsplit(target)
    if not p.hostname:
        warn("unparseable URL target skipped: %r" % target)
        return []
    origin = origin_of(p)
    method = hints.get("method", "GET")
    if p.path in ("", "/") and not p.query:
        return [(site_kind, [c_url(origin)], origin)]
    coords = [c_url(origin), c_route(method, p.path or "/")]
    params = list(hints.get("params") or [])
    if include_params:
        params += [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
    seen = set()
    for name in params:
        if name not in seen:
            coords.append(c_param(name))
            seen.add(name)
    return [(route_kind, coords, "%s %s" % (method.upper(), p.path or "/"))]


def cloud_assets(target, hints):
    scheme = hints.get("scheme") or guess_scheme(target)
    if not scheme:
        warn("cannot infer resource scheme for %r; using scheme 'id' — "
             "pass hints.scheme to override" % target)
        scheme = "id"
    return [("cloud:resource", [c_resource(scheme, target)], target)]


def file_assets(target, kind):
    m = PATHLINES_RE.match(target)
    if m and not os.path.exists(target):
        coords = [c_path(m.group("path")), c_lines(m.group("start"), m.group("end"))]
        return [(kind, coords, target)]
    return [(kind, [c_path(target)], target)]


def hash_assets(target, kind):
    if SHA256_RE.match(target):
        return [(kind, [c_sha256(target)], target[:16] + "…")]
    if os.path.isfile(target):
        h = hashlib.sha256()
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return [(kind, [c_sha256(h.hexdigest())], target)]
    warn("profile needs a sha256 and %r is neither 64-hex nor a readable file; skipped" % target)
    return []


def classify(profile, target, hints, include_params):
    if profile == "network":
        return network_assets(target, hints)
    if profile == "redteam":
        # redteam kinds are host-only; collapse services onto their host
        out = network_assets(target, hints, kind_prefix="redteam")
        return [("redteam:host", [c for c in coords if c["t"] == "host"], lbl)
                for _, coords, lbl in out]
    if profile in ("web", "api"):
        return web_assets(target, hints, include_params, profile=profile)
    if profile == "cloud":
        return cloud_assets(target, hints)
    if profile == "code":
        if target.endswith("/"):
            return [("code:repo", [c_path(target.rstrip("/"))], target)]
        return file_assets(target, "code:file")
    if profile in ("secrets", "sca", "iac"):
        if profile == "iac" and PATHLINES_RE.match(target) and not os.path.exists(target):
            return file_assets(target, "iac:resource")
        if profile == "sca" and target.startswith("pkg:"):
            return [("sca:dependency", [c_resource("purl", target)], target)]
        return [("%s:repo" % profile, [c_path(target.rstrip("/"))], target)]
    if profile == "binary":
        return hash_assets(target, "binary:binary")
    if profile == "firmware":
        return hash_assets(target, "firmware:image")
    if profile == "container":
        if target.startswith("pkg:"):
            return [("container:package", [c_resource("purl", target)], target)]
        return hash_assets(target, "container:image")
    raise SystemExit("unsupported profile: %s" % profile)


def object_to_targets(obj, hints):
    """Normalize a simple object item into (target-string, merged-hints) pairs."""
    merged = dict(hints)
    for k in ("proto", "method", "scheme"):
        if k in obj:
            merged[k] = obj[k]
    if "params" in obj:
        merged["params"] = obj["params"]
    if "sha256" in obj:
        return [(obj["sha256"], merged)]
    if "url" in obj:
        u = obj["url"]
        if "path" in obj:
            p = urlsplit(u if is_url(u) else "https://" + u)
            u = origin_of(p) + obj["path"]
        return [(u, merged)]
    if "host" in obj:
        if "ports" in obj:
            return [("%s:%s" % (obj["host"], p), merged) for p in obj["ports"]]
        if "port" in obj:
            return [("%s:%s" % (obj["host"], obj["port"]), merged)]
        return [(obj["host"], merged)]
    if "id" in obj and "scheme" in obj:
        return [(obj["id"], merged)]
    if "arn" in obj:
        return [(obj["arn"], dict(merged, scheme="arn"))]
    if "path" in obj:
        t = obj["path"]
        if "start" in obj:
            t = "%s:%s-%s" % (t, obj["start"], obj.get("end", obj["start"]))
        return [(t, merged)]
    return []


def split_targets_for_profile(profile, targets):
    """Pick the split.py {"type","value",...} targets a profile cares about and
    return them as object_to_targets-friendly dicts (or plain strings).

    split.py (the work-units skill) emits typed targets — host/service, url/
    http_route, cloud_resource, file. Each profile consumes only the types it
    owns, so a web unit's incidental host/service targets don't become stray
    sites and a network unit's targets stay services. For web/api an
    http_route's method is folded onto the sibling url so the result is one
    route/endpoint asset with the right verb. Targets that already lack a
    "type"/"value" shape (a service dict carrying host/port keys, a plain
    object or string item) are passed through unchanged.
    """
    dicts = [t for t in targets if isinstance(t, dict)]
    def typed(name):
        return [t for t in dicts if t.get("type") == name]
    passthrough = [t for t in targets
                   if not (isinstance(t, dict) and "type" in t and "value" in t)]
    out = list(passthrough)

    if profile in ("network", "redteam"):
        if typed("service"):
            pass  # service dicts carry host/port and pass through above
        else:
            out += [{"host": t.get("value")} for t in typed("host")]
    elif profile in ("web", "api"):
        urls, routes = typed("url"), typed("http_route")
        method = next((r.get("method") for r in routes if r.get("method")), None)
        if urls:
            for u in urls:
                o = {"url": u.get("value")}
                if method:
                    o["method"] = method
                out.append(o)
        else:
            for r in routes:
                o = {"url": r.get("value"), "path": r.get("path")}
                if r.get("method"):
                    o["method"] = r["method"]
                out.append(o)
    elif profile == "cloud":
        for t in typed("cloud_resource"):
            v = t.get("value")
            out.append({"arn": v} if str(v).startswith("arn:")
                       else {"id": v, "scheme": guess_scheme(v) or "id"})
    else:
        # file-oriented profiles (code/secrets/sca/iac/binary/firmware/container)
        for t in typed("file"):
            o = {"path": t.get("value")}
            for k in ("start", "end"):
                if k in t:
                    o[k] = t[k]
            out.append(o)

    # Last resort: nothing matched this profile's types — fall back to every
    # typed target's bare value so the unit is never silently dropped.
    if not out:
        out = [t.get("value") for t in dicts if "value" in t]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Emit assets.mark payloads from a work-units inventory.")
    ap.add_argument("input", nargs="?", help="inventory JSON file (default: stdin)")
    ap.add_argument("--profile", required=True, choices=sorted(LADDERS),
                    help="engagement profile whose kinds/ladder to emit")
    ap.add_argument("--depth", help="depth rung (default: the profile's first rung)")
    ap.add_argument("--include-params", action="store_true",
                    help="web/api: add a param coordinate per query-string key")
    ap.add_argument("-o", "--output", help="write payload array here (default: stdout)")
    args = ap.parse_args(argv)

    ladder = LADDERS[args.profile]
    depth = args.depth or ladder[0]
    if depth not in ladder:
        ap.error("depth %r is not on the %s ladder: %s"
                 % (depth, args.profile, " -> ".join(ladder)))

    raw = open(args.input, encoding="utf-8").read() if args.input else sys.stdin.read()
    data = json.loads(raw)
    if not isinstance(data, list):
        raise SystemExit("input must be a JSON array (work units or targets)")

    payloads, seen = [], set()
    for item in data:
        if isinstance(item, str):
            pairs, title = [(item, {})], None
        elif isinstance(item, dict) and "targets" in item:  # work unit
            hints = item.get("hints") or {}
            if not isinstance(hints, dict):
                hints = {}
            title = item.get("title") or item.get("id")
            pairs = []
            for t in split_targets_for_profile(args.profile, item.get("targets") or []):
                if isinstance(t, dict):
                    pairs.extend(object_to_targets(t, hints))
                else:
                    pairs.append((str(t), hints))
        elif isinstance(item, dict):
            pairs, title = object_to_targets(item, {}), None
            if not pairs:
                warn("unrecognized object item skipped: %s" % json.dumps(item))
                continue
        else:
            warn("unrecognized item skipped: %r" % (item,))
            continue

        for target, hints in pairs:
            for kind, coords, lbl in classify(args.profile, str(target), hints,
                                              args.include_params):
                label = "%s — %s" % (title, lbl) if title else lbl
                payload = {"kind": kind, "coordinates": coords,
                           "depth": depth, "label": label}
                key = json.dumps({"kind": kind, "coordinates": coords}, sort_keys=True)
                if key not in seen:  # same kind + locator = same asset; mark once
                    seen.add(key)
                    payloads.append(payload)

    out = json.dumps(payloads, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out)
    print("emitted %d assets.mark payload(s) [profile=%s depth=%s]"
          % (len(payloads), args.profile, depth), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
