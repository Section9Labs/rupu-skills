#!/usr/bin/env python3
"""authz_matrix.py — multi-identity request replay & diff (IDOR/BOLA/BFLA matrix).

Replays every captured request under every identity (auth material swapped,
redirects NOT followed), records status/length/body-sha256 per cell, and
classifies non-owner cells:

  CONFIRMED  2xx, body hash identical to the owner's 2xx baseline
  CANDIDATE  2xx, body length within --tolerance (default 10%) of baseline
  REVIEW     2xx, substantially different body
  ENFORCED   401/403/3xx (or non-2xx generally)
  ERROR      transport failure

Inputs (shapes in references/rupu.md):
  --requests   JSON array: {"id","method","url","headers",{"body"},"identity"}
  --identities JSON object: name -> {"priv": int, "headers": {...}, "cookies": {...}}

Outputs:
  --out         full matrix JSON
  --work-units  rupu work-units array (one unit per flagged cell), first char '['
  --findings    ready findings.report payloads for CONFIRMED cells
  --assets      assets.mark payloads (web:route, depth tested/exploited)

Example:
  python3 scripts/authz_matrix.py --requests requests.json \
      --identities identities.json --out matrix.json \
      --work-units wu.json --findings findings.json --assets assets.json
"""

import argparse
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# Auth material we strip from the captured request before overlaying the
# replay identity's own material.
AUTH_HEADERS = {
    "cookie", "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token", "api-key", "token",
}

SUCCESS = range(200, 300)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(insecure, proxy):
    handlers = [NoRedirect()]
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def identity_headers(ident):
    """Merge an identity's headers + cookies dict into a header dict."""
    hdrs = dict(ident.get("headers") or {})
    cookies = ident.get("cookies") or {}
    if cookies:
        jar = "; ".join(f"{k}={v}" for k, v in cookies.items())
        existing = None
        for k in list(hdrs):
            if k.lower() == "cookie":
                existing = hdrs.pop(k)
        hdrs["Cookie"] = f"{existing}; {jar}" if existing else jar
    return hdrs


def send(opener, req_spec, ident, timeout):
    """Replay one request under one identity. Returns a cell dict."""
    url = req_spec["url"]
    method = (req_spec.get("method") or "GET").upper()
    body = req_spec.get("body")
    data = body.encode("utf-8", "replace") if isinstance(body, str) else body

    headers = {}
    for k, v in (req_spec.get("headers") or {}).items():
        if k.lower() in AUTH_HEADERS or k.lower() in ("content-length", "host"):
            continue
        headers[k] = v
    headers.update(identity_headers(ident))

    r = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        r.add_header(k, v)

    cell = {"status": None, "length": 0, "sha256": None, "snippet": "", "error": None,
            "location": None}
    try:
        resp = opener.open(r, timeout=timeout)
        raw = resp.read()
        cell["status"] = resp.status
        cell["resp_headers"] = dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        cell["status"] = e.code
        cell["resp_headers"] = dict(e.headers)
        cell["location"] = e.headers.get("Location")
    except Exception as e:  # URLError, timeout, ...
        cell["error"] = f"{type(e).__name__}: {e}"
        return cell
    cell["length"] = len(raw)
    cell["sha256"] = hashlib.sha256(raw).hexdigest()
    cell["snippet"] = raw[:400].decode("utf-8", "replace")
    if cell.get("resp_headers"):
        cell["location"] = cell["resp_headers"].get("Location") or cell["location"]
    return cell


def classify(owner_cell, cell, tolerance):
    if cell.get("error"):
        return "ERROR"
    st = cell["status"]
    if st not in SUCCESS:
        return "ENFORCED"
    if not owner_cell or owner_cell.get("error") or owner_cell["status"] not in SUCCESS:
        # No clean baseline: 2xx by a non-owner still deserves eyes.
        return "REVIEW"
    if cell["sha256"] == owner_cell["sha256"]:
        return "CONFIRMED"
    base = max(owner_cell["length"], 1)
    if abs(cell["length"] - base) / base <= tolerance:
        return "CANDIDATE"
    return "REVIEW"


def exchange_text(req_spec, ident_name, ident, cell):
    """Human-readable HTTP exchange for evidence."""
    u = urllib.parse.urlsplit(req_spec["url"])
    path = u.path + (f"?{u.query}" if u.query else "")
    lines = [f"{(req_spec.get('method') or 'GET').upper()} {path or '/'} HTTP/1.1",
             f"Host: {u.netloc}"]
    for k, v in identity_headers(ident).items():
        lines.append(f"{k}: {v}")
    for k, v in (req_spec.get("headers") or {}).items():
        if k.lower() not in AUTH_HEADERS and k.lower() not in ("content-length", "host"):
            lines.append(f"{k}: {v}")
    body = req_spec.get("body") or ""
    reqtxt = "\n".join(lines) + ("\n\n" + body if body else "\n")
    resptxt = (f"HTTP/1.1 {cell.get('status')}\n"
               f"Content-Length: {cell.get('length')}\n\n{cell.get('snippet', '')}")
    return f"--- request (as {ident_name}) ---\n{reqtxt}\n--- response ---\n{resptxt}"


def guess_param(url):
    """Pick a likely object-reference param name from the URL for assets.mark."""
    q = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)
    for k, v in q:
        if re.search(r"id|user|acc|doc|file|order|key|ref", k, re.I):
            return k
    if q:
        return q[0][0]
    return None


def main():
    ap = argparse.ArgumentParser(description="Authorization matrix replayer")
    ap.add_argument("--requests", required=True, help="requests.json (array)")
    ap.add_argument("--identities", required=True, help="identities.json (object)")
    ap.add_argument("--out", help="write full matrix JSON here")
    ap.add_argument("--work-units", help="write rupu work-units array here")
    ap.add_argument("--findings", help="write findings.report payloads here")
    ap.add_argument("--assets", help="write assets.mark payloads here")
    ap.add_argument("--tolerance", type=float, default=0.10,
                    help="length delta ratio for CANDIDATE (default 0.10)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--proxy", help="http proxy, e.g. http://127.0.0.1:8080")
    args = ap.parse_args()

    with open(args.requests) as f:
        requests_in = json.load(f)
    with open(args.identities) as f:
        identities = json.load(f)

    opener = build_opener(args.insecure, args.proxy)
    matrix, flagged = [], []

    for i, req_spec in enumerate(requests_in):
        rid = req_spec.get("id") or f"req{i}"
        owner = req_spec.get("identity")
        method = (req_spec.get("method") or "GET").upper()
        url = req_spec["url"]
        row = {"id": rid, "method": method, "url": url, "owner": owner, "cells": {}}

        # Fresh owner baseline first (never trust the stale capture).
        owner_cell = None
        if owner in identities:
            owner_cell = send(opener, req_spec, identities[owner], args.timeout)
            owner_cell["verdict"] = "BASELINE"
            row["cells"][owner] = owner_cell

        for name, ident in identities.items():
            if name == owner:
                continue
            cell = send(opener, req_spec, ident, args.timeout)
            cell["verdict"] = classify(owner_cell, cell, args.tolerance)
            row["cells"][name] = cell
            if cell["verdict"] in ("CONFIRMED", "CANDIDATE", "REVIEW"):
                flagged.append((req_spec, rid, owner, owner_cell, name, ident, cell))
        matrix.append(row)
        sys.stderr.write(f"[{i + 1}/{len(requests_in)}] {method} {url} -> "
                         + ", ".join(f"{n}:{c['verdict']}({c['status']})"
                                     for n, c in row["cells"].items()) + "\n")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(matrix, f, indent=2)

    # ---- rupu work units (fan-out) -------------------------------------
    units = []
    for req_spec, rid, owner, oc, name, ident, cell in flagged:
        kind = ("BFLA/vertical" if identities.get(name, {}).get("priv", 0)
                < identities.get(owner, {}).get("priv", 0) else "IDOR/horizontal")
        wstg = "WSTG-ATHZ-02" if kind.startswith("BFLA") else "WSTG-ATHZ-04"
        cwe = "CWE-285" if kind.startswith("BFLA") else "CWE-639"
        if identities.get(name, {}).get("priv", 1) == 0:
            cwe = "CWE-284"
        units.append({
            "id": f"authz-{rid}-{name}",
            "title": (f"Confirm {kind}: {name} got {cell['status']} on "
                      f"{req_spec.get('method', 'GET')} "
                      f"{urllib.parse.urlsplit(req_spec['url']).path} (owner: {owner})"),
            "targets": [req_spec["url"]],
            "hints": {
                "method": (req_spec.get("method") or "GET").upper(),
                "owner_identity": str(owner),
                "attacker_identity": name,
                "verdict": cell["verdict"],
                "owner_status": str(oc["status"] if oc else "n/a"),
                "attacker_status": str(cell["status"]),
                "owner_len": str(oc["length"] if oc else "n/a"),
                "attacker_len": str(cell["length"]),
                "same_body": str(bool(oc and oc["sha256"] == cell["sha256"])).lower(),
                "wstg": wstg,
                "cwe": cwe,
                "next": "Diff bodies; if attacker response contains owner data, "
                        "report via finding-report skill",
            },
        })
    if args.work_units:
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)

    # ---- findings.report payloads for CONFIRMED cells ------------------
    findings = []
    for req_spec, rid, owner, oc, name, ident, cell in flagged:
        if cell["verdict"] != "CONFIRMED":
            continue
        method = (req_spec.get("method") or "GET").upper()
        write_verb = method in ("PUT", "PATCH", "DELETE", "POST")
        vertical = (identities.get(name, {}).get("priv", 0)
                    < identities.get(owner, {}).get("priv", 0))
        anon = identities.get(name, {}).get("priv", 1) == 0
        if vertical:
            cls = "WSTG-ATHZ-02 / CWE-285 / OWASP A01:2021 (API5:2023 BFLA)"
            what = "function-level authorization is not enforced"
        else:
            cls = "WSTG-ATHZ-04 / CWE-639 / OWASP A01:2021 (API1:2023 BOLA)"
            what = "object-level authorization is not enforced"
        if anon:
            cls = cls.replace("CWE-285", "CWE-284").replace("CWE-639", "CWE-284")
        sev = "critical" if (write_verb or vertical or anon) else "high"
        findings.append({
            "title": (f"{'BFLA' if vertical else 'IDOR'}: {name} "
                      f"{'(unauthenticated) ' if anon else ''}got identical "
                      f"{cell['status']} on {method} "
                      f"{urllib.parse.urlsplit(req_spec['url']).path} owned by {owner}"),
            "scope": "endpoint",
            "target_ref": req_spec["url"],
            "severity": sev,
            "classification": cls,
            "evidence": {
                "rationale": (f"{what}: the request captured for identity "
                              f"'{owner}' returns a byte-identical "
                              f"{cell['status']} response (sha256 "
                              f"{cell['sha256'][:16]}...) when replayed with "
                              f"'{name}' credentials. {name} received {owner}'s "
                              f"data/function result."),
                "owner_exchange": exchange_text(req_spec, owner,
                                                identities.get(owner, {}), oc or {}),
                "attacker_exchange": exchange_text(req_spec, name, ident, cell),
            },
        })
    if args.findings:
        with open(args.findings, "w") as f:
            json.dump(findings, f, indent=2)

    # ---- assets.mark payloads ------------------------------------------
    if args.assets:
        confirmed_urls = {f["target_ref"] for f in findings}
        assets, seen = [], set()
        for row in matrix:
            u = urllib.parse.urlsplit(row["url"])
            route = u.path or "/"
            key = (u.scheme, u.netloc, route)
            if key in seen:
                continue
            seen.add(key)
            coords = [{"t": "url", "v": f"{u.scheme}://{u.netloc}"},
                      {"t": "http_route", "v": route}]
            p = guess_param(row["url"])
            if p:
                coords.append({"t": "param", "v": p})
            assets.append({
                "kind": "web:route",
                "label": f"{row['method']} {route}",
                "coordinates": coords,
                "depth": "exploited" if row["url"] in confirmed_urls else "tested",
            })
        with open(args.assets, "w") as f:
            json.dump(assets, f, indent=2)

    n_conf = sum(1 for *_, c in flagged if c["verdict"] == "CONFIRMED")
    sys.stderr.write(f"\n{len(matrix)} requests x {len(identities)} identities: "
                     f"{len(flagged)} flagged cells, {n_conf} CONFIRMED, "
                     f"{len(findings)} finding payloads.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
