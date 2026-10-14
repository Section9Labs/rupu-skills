#!/usr/bin/env python3
"""parse_cmdi.py — normalize command-injection results into rupu outputs.

Inputs (any combination):
  --commix-dir DIR   commix output dir (e.g. ~/.commix/output/example.com),
                     parses logs.txt / *.txt detection lines and session.db.
  --manual FILE      JSON file: either a list of result objects or
                     {"results": [...]}. Each object:
                       {"url": "...", "param": "...", "method": "GET",
                        "separator": ";", "technique": "classic",
                        "payload": ";id", "confirmed": true,
                        "evidence": {"request": "...", "response": "...",
                                     "command_output": "...", "oob": "..."}}

Outputs:
  -o FILE            merged normalized JSON (list of records).
  --work-units FILE  JSON array (first char '[') of work units for rupu
                     for_each / dispatch (hand to the work-units skill).
  --findings FILE    JSON array of findings.report payloads
                     (scope endpoint, critical, WSTG-INPV-12 / CWE-78).
  --assets FILE      JSON array of assets.mark payloads
                     (web:route, depth exploited/tested).

Usage:
  python3 scripts/parse_cmdi.py --commix-dir ~/.commix/output/example.com \
      --manual manual_hits.json -o confirmed.json \
      --work-units units.json --findings findings.json --assets assets.json
"""

import argparse
import glob
import json
import os
import re
import sqlite3
import sys
from urllib.parse import urlsplit

INJECTABLE_RE = re.compile(
    r"parameter\s+'(?P<param>[^']+)'\s+(?:seems|appears to be|is)\s+injectable"
    r"(?:\s+via\s+(?:a\s+)?\(?(?P<flavor>[\w-]+)\)?[\s-]*"
    r"(?P<technique>classic|eval-based|time-based|file-based))?",
    re.IGNORECASE,
)
PAYLOAD_RE = re.compile(r"Payload\s*:\s*(?P<payload>.+?)\s*$", re.IGNORECASE)
URL_RE = re.compile(r"(?:URL|Target)\s*:?\s*(?P<url>https?://\S+)", re.IGNORECASE)
ANY_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
SEPARATORS = [";", "%0a", "\n", "&&", "||", "|", "&", "`", "$("]


def guess_separator(payload):
    if not payload:
        return None
    for sep in SEPARATORS:
        if payload.startswith(sep) or sep in payload[:4]:
            return sep
    return None


def norm_record(url, param, technique=None, separator=None, payload=None,
                method="GET", confirmed=True, evidence=None, source="manual"):
    evidence = dict(evidence or {})
    if payload and "payload" not in evidence:
        evidence["payload"] = payload
    return {
        "url": url or "",
        "param": param or "",
        "method": (method or "GET").upper(),
        "separator": separator or guess_separator(payload),
        "technique": technique or "unknown",
        "confirmed": bool(confirmed),
        "payload": payload,
        "evidence": evidence,
        "source": source,
    }


def parse_commix_dir(path):
    records = []
    path = os.path.expanduser(path)
    txt_files = sorted(glob.glob(os.path.join(path, "**", "*.txt"),
                                 recursive=True))
    for fn in txt_files:
        try:
            with open(fn, "r", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        file_url = None
        for ln in lines:
            m = URL_RE.search(ln)
            if m:
                file_url = m.group("url").rstrip(".,")
                break
        if not file_url:
            for ln in lines:
                m = ANY_URL_RE.search(ln)
                if m:
                    file_url = m.group(0).rstrip(".,")
                    break
        pending = None
        for ln in lines:
            m = INJECTABLE_RE.search(ln)
            if m:
                if pending:
                    records.append(pending)
                pending = norm_record(
                    url=file_url,
                    param=m.group("param"),
                    technique=(m.group("technique") or "unknown").lower(),
                    source="commix:" + os.path.basename(fn),
                )
                continue
            if pending:
                pm = PAYLOAD_RE.search(ln)
                if pm:
                    pending["payload"] = pm.group("payload")
                    pending["separator"] = guess_separator(pending["payload"])
                    pending["evidence"]["payload"] = pending["payload"]
                    records.append(pending)
                    pending = None
        if pending:
            records.append(pending)
    # Session databases (sqlite) — best-effort, schema varies by version.
    for db in sorted(glob.glob(os.path.join(path, "**", "session.db"),
                               recursive=True)):
        try:
            con = sqlite3.connect(db)
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            for t in tables:
                try:
                    cur.execute("SELECT * FROM %s" % t)  # trusted local file
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        d = dict(zip(cols, [str(v) for v in row]))
                        param = d.get("vuln_parameter") or d.get("parameter")
                        if not param:
                            continue
                        records.append(norm_record(
                            url=d.get("url") or d.get("target_url"),
                            param=param,
                            technique=(d.get("technique") or "unknown").lower(),
                            payload=d.get("payload"),
                            method=d.get("http_request_method") or "GET",
                            evidence={"session_table": t},
                            source="commix-session:" + os.path.basename(db),
                        ))
                except sqlite3.Error:
                    continue
            con.close()
        except sqlite3.Error:
            continue
    return records


def parse_manual(path):
    with open(path, "r") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("results", [])
    records = []
    for item in data:
        records.append(norm_record(
            url=item.get("url"),
            param=item.get("param") or item.get("parameter"),
            technique=item.get("technique"),
            separator=item.get("separator"),
            payload=item.get("payload"),
            method=item.get("method", "GET"),
            confirmed=item.get("confirmed", True),
            evidence=item.get("evidence"),
            source="manual",
        ))
    return records


def dedupe(records):
    seen, out = set(), []
    for r in records:
        key = (r["url"], r["param"], r["technique"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "x").lower()).strip("-") or "x"


def to_work_units(records):
    units = []
    for r in records:
        parts = urlsplit(r["url"])
        uid = "cmdi-%s-%s-%s" % (slug(parts.netloc), slug(parts.path),
                                 slug(r["param"]))
        hints = {
            "param": r["param"],
            "method": r["method"],
            "separator": r["separator"] or "",
            "technique": r["technique"],
            "payload": r["payload"] or "",
            "status": "confirmed" if r["confirmed"] else "suspect",
            "next": ("commix -u '%s' -p %s --batch --os-shell"
                     % (r["url"], r["param"])),
        }
        units.append({
            "id": uid,
            "title": "Exploit %s command injection: %s @ %s" % (
                r["technique"], r["param"], parts.path or "/"),
            "targets": [r["url"]],
            "hints": hints,
        })
    return units


def to_assets(records):
    assets = []
    for r in records:
        parts = urlsplit(r["url"])
        base = "%s://%s" % (parts.scheme or "https", parts.netloc)
        depth = "exploited" if r["confirmed"] else "tested"
        assets.append({
            "kind": "web:route",
            "label": "%s %s?%s — command injection (%s)" % (
                r["method"], parts.path or "/", r["param"],
                "confirmed" if r["confirmed"] else "probed"),
            "coordinates": [
                {"t": "url", "v": base},
                {"t": "http_route", "v": parts.path or "/"},
                {"t": "param", "v": r["param"]},
            ],
            "depth": depth,
        })
    return assets


def to_findings(records):
    findings = []
    for r in records:
        if not r["confirmed"]:
            continue
        ev = dict(r["evidence"])
        rationale = (
            "The '%s' parameter of %s is concatenated into an OS shell "
            "command. Injection confirmed via %s technique"
            % (r["param"], r["url"], r["technique"]))
        if r["separator"]:
            rationale += " using separator %r" % r["separator"]
        if ev.get("command_output"):
            rationale += ("; injected command output observed in response: "
                          + ev["command_output"][:200])
        if ev.get("oob"):
            rationale += "; out-of-band confirmation: " + str(ev["oob"])[:200]
        rationale += ". Arbitrary command execution as the web service user."
        ev["rationale"] = rationale
        findings.append({
            "title": "OS command injection in '%s' parameter (%s)" % (
                r["param"], urlsplit(r["url"]).path or "/"),
            "scope": "endpoint",
            "target_ref": r["url"],
            "severity": "critical",
            "classification": {"owasp": "WSTG-INPV-12", "cwe": "CWE-78"},
            "evidence": ev,
        })
    return findings


def write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("[+] wrote %s (%d items)" % (path, len(obj)), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--commix-dir", help="commix output directory")
    ap.add_argument("--manual", help="manual results JSON file")
    ap.add_argument("-o", "--output", help="merged normalized JSON out")
    ap.add_argument("--work-units", help="work-units JSON array out")
    ap.add_argument("--findings", help="findings.report payloads out")
    ap.add_argument("--assets", help="assets.mark payloads out")
    args = ap.parse_args()

    if not args.commix_dir and not args.manual:
        ap.error("need --commix-dir and/or --manual")

    records = []
    if args.commix_dir:
        records += parse_commix_dir(args.commix_dir)
    if args.manual:
        records += parse_manual(args.manual)
    records = dedupe(records)

    if not records:
        print("[-] no injection records parsed", file=sys.stderr)

    if args.output:
        write_json(args.output, records)
    if args.work_units:
        write_json(args.work_units, to_work_units(records))
    if args.assets:
        write_json(args.assets, to_assets(records))
    if args.findings:
        write_json(args.findings, to_findings(records))
    if not any([args.output, args.work_units, args.assets, args.findings]):
        json.dump(records, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
