#!/usr/bin/env python3
"""parse_dalfox.py — normalize dalfox output into rupu-ingestible artifacts.

Reads dalfox results in JSON (array), JSONL (one object per line), or plain
([POC][V][...][GET] url) format. Normalizes each PoC, dedupes, and emits:

  --out out.json          merged normalized results (JSON array)
  --work-units wu.json    rupu work-units array (first char '['), one per injection point
  --findings f.json       findings.report payloads (scope endpoint, WSTG/CWE classified)
  --assets a.json         assets.mark payloads (web:route, depth tested/exploited)

Usage:
  python3 scripts/parse_dalfox.py dalfox.json [more files...] \
      --out norm.json --work-units units.json --findings findings.json --assets assets.json

Only verified (V) and reflected (R) results become findings; grep (G) hits are
kept in the normalized output as leads for sibling skills. vulture / lapis-outpost
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl, unquote

PLAIN_RE = re.compile(
    r"^\[(?:POC|W|I)\]\[(?P<type>[A-Z])\](?:\[(?P<ctx>[^\]]*)\])?(?:\[(?P<method>[A-Z]+)\])?\s+(?P<url>\S+)"
)

TYPE_MAP = {"V": "V", "R": "R", "G": "G"}

WSTG_BY_VARIANT = {
    "reflected": "WSTG-INPV-01",
    "stored": "WSTG-INPV-02",
    "dom": "WSTG-CLNT-01",
}


def load_results(path):
    """Yield raw dalfox result dicts from a json/jsonl/plain file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print("[!] cannot read %s: %s" % (path, exc), file=sys.stderr)
        return
    stripped = text.lstrip()
    if not stripped:
        return
    if stripped[0] == "[" and stripped[1:2] in ("{", "]", "\n", " ", "\t", "\r"):
        # JSON array
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                for obj in data:
                    if isinstance(obj, dict):
                        yield obj
                return
        except json.JSONDecodeError:
            pass  # fall through to line-based parsing
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] == "{":
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
                continue
            except json.JSONDecodeError:
                continue
        m = PLAIN_RE.match(line)
        if m:
            yield {
                "type": m.group("type"),
                "inject_type": m.group("ctx") or "",
                "method": m.group("method") or "GET",
                "data": m.group("url"),
            }


def classify_variant(rec):
    """reflected / stored / dom from dalfox fields."""
    ctx = (rec.get("inject_type") or "").lower()
    msg = (rec.get("message_str") or "").lower()
    poc_type = (rec.get("poc_type") or "").lower()
    if "dom" in ctx or "dom" in msg:
        return "dom"
    if "sxss" in msg or "stored" in msg or "sxss" in poc_type:
        return "stored"
    return "reflected"


def guess_param(rec):
    param = rec.get("param") or ""
    if param:
        return param
    url = rec.get("data") or ""
    payload = rec.get("payload") or ""
    try:
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if payload and (payload in v or payload in unquote(v)):
                return k
    except ValueError:
        pass
    return ""


def normalize(rec):
    url = rec.get("data") or rec.get("url") or ""
    if not url.startswith("http"):
        return None
    rtype = TYPE_MAP.get((rec.get("type") or "").upper(), "R")
    variant = classify_variant(rec)
    if rtype == "V":
        norm_type = "DOM" if variant == "dom" else ("S" if variant == "stored" else "V")
    else:
        norm_type = rtype
    return {
        "type": norm_type,            # V verified / R reflected / S stored / DOM / G grep
        "variant": variant,            # reflected | stored | dom
        "verified": rtype == "V",
        "url": url,
        "method": rec.get("method") or "GET",
        "param": guess_param(rec),
        "payload": rec.get("payload") or "",
        "evidence": rec.get("evidence") or "",
        "context": rec.get("inject_type") or "",
        "cwe": rec.get("cwe") or "CWE-79",
        "severity": (rec.get("severity") or "High").lower(),
        "message": rec.get("message_str") or "",
    }


def dedupe(records):
    seen = set()
    out = []
    for r in records:
        try:
            parts = urlsplit(r["url"])
            route = parts.path or "/"
            site = "%s://%s" % (parts.scheme, parts.netloc)
        except ValueError:
            site, route = r["url"], "/"
        key = (site, route, r["param"], r["type"], r["payload"])
        if key in seen:
            continue
        seen.add(key)
        r["_site"] = site
        r["_route"] = route
        out.append(r)
    # prefer verified over reflected for the same (site, route, param)
    best = {}
    rank = {"V": 3, "S": 3, "DOM": 3, "R": 2, "G": 1}
    for r in out:
        k = (r["_site"], r["_route"], r["param"])
        if k not in best or rank.get(r["type"], 0) > rank.get(best[k]["type"], 0):
            best[k] = r
    keep = set(id(v) for v in best.values())
    return [r for r in out if id(r) in keep or r["type"] == "G"]


def slug(text, maxlen=60):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen] or "x"


def make_work_units(records):
    units = []
    for r in records:
        if r["type"] == "G":
            continue
        host = urlsplit(r["_site"]).netloc
        uid = "xss-%s-%s-%s" % (slug(host), slug(r["_route"]), slug(r["param"] or "nop"))
        units.append({
            "id": uid,
            "title": "XSS candidate: %s on %s (%s, type %s)" % (
                r["param"] or "<mined>", r["_route"], r["context"] or "unknown", r["type"]),
            "targets": [r["url"]],
            "hints": {
                "param": r["param"],
                "type": r["type"],
                "context": r["context"],
                "payload": r["payload"],
                "evidence": r["evidence"],
                "method": r["method"],
                "cwe": r["cwe"],
                "next": ("report via finding-report skill" if r["verified"]
                         else "verify PoC in browser, capture exchange, then report"),
            },
        })
    return units


def make_findings(records):
    findings = []
    for r in records:
        if r["type"] == "G":
            continue
        variant = r["variant"]
        wstg = WSTG_BY_VARIANT.get(variant, "WSTG-INPV-01")
        severity = "high" if (r["verified"] or variant in ("stored", "dom")) else "medium"
        title = "%s XSS in '%s' parameter of %s" % (
            variant.capitalize(), r["param"] or "mined parameter", r["_route"])
        rationale = (
            "Parameter '%s' at %s reflects attacker input unencoded (context: %s). "
            "Payload: %s . Evidence: %s . %s" % (
                r["param"] or "<mined>", r["_route"], r["context"] or "unknown",
                r["payload"] or "<see PoC URL>", r["evidence"] or "<see response>",
                "dalfox headless browser verified JavaScript execution (type V)."
                if r["verified"] else
                "Payload reflected unencoded (type R); confirm execution before final severity.")
        )
        parts = urlsplit(r["url"])
        req_path = parts.path + (("?" + parts.query) if parts.query else "")
        request = "%s %s HTTP/1.1\nHost: %s\n\n" % (r["method"], req_path or "/", parts.netloc)
        response = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n...%s..." % (
            r["evidence"] or r["payload"])
        findings.append({
            "scope": "endpoint",
            "target_ref": r["url"],
            "title": title,
            "severity": severity,
            "classification": {"owasp": wstg, "cwe": r["cwe"]},
            "evidence": {
                "rationale": rationale,
                "request": request,
                "response": response,
            },
        })
    return findings


def make_assets(records):
    assets = []
    seen = set()
    for r in records:
        if r["type"] == "G":
            continue
        depth = "exploited" if r["verified"] else "tested"
        coords = [
            {"t": "url", "v": r["_site"]},
            {"t": "http_route", "v": r["_route"]},
        ]
        if r["param"]:
            coords.append({"t": "param", "v": r["param"]})
        key = (r["_site"], r["_route"], r["param"], depth)
        if key in seen:
            continue
        seen.add(key)
        assets.append({
            "kind": "web:route",
            "coordinates": coords,
            "label": "%s %s%s (XSS %s)" % (
                r["method"], r["_route"],
                ("?%s=" % r["param"]) if r["param"] else "", depth),
            "depth": depth,
        })
    return assets


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print("[+] wrote %d item(s) -> %s" % (len(data), path), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Normalize dalfox output for rupu.")
    ap.add_argument("inputs", nargs="+", help="dalfox output file(s): json, jsonl, or plain")
    ap.add_argument("--out", help="write merged normalized JSON array here")
    ap.add_argument("--work-units", help="write rupu work-units JSON array here")
    ap.add_argument("--findings", help="write findings.report payloads (JSON array) here")
    ap.add_argument("--assets", help="write assets.mark payloads (JSON array) here")
    args = ap.parse_args()

    raw = []
    for path in args.inputs:
        raw.extend(load_results(path))
    norm = [n for n in (normalize(r) for r in raw) if n]
    records = dedupe(norm)

    verified = sum(1 for r in records if r["verified"])
    reflected = sum(1 for r in records if r["type"] == "R")
    print("[*] parsed %d raw -> %d unique (%d verified, %d reflected-only)" % (
        len(raw), len(records), verified, reflected), file=sys.stderr)

    public = [{k: v for k, v in r.items() if not k.startswith("_")} for r in records]
    if args.out:
        write_json(args.out, public)
    if args.work_units:
        write_json(args.work_units, make_work_units(records))
    if args.findings:
        write_json(args.findings, make_findings(records))
    if args.assets:
        write_json(args.assets, make_assets(records))
    if not any([args.out, args.work_units, args.findings, args.assets]):
        json.dump(public, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
