#!/usr/bin/env python3
"""parse_nikto.py - normalize nikto output (JSON or CSV) for rupu.

Accepts:
  * nikto -Format json  (single object, array of objects, or concatenated
    objects - all variants seen in the wild are handled)
  * nikto -Format csv   ("host","ip","port","id","method","uri","msg")

Normalizes every item to {url, method, msg, id, references}, dedupes, and
emits:
  --out         merged JSON summary
  --work-units  rupu work-units ARRAY (one per finding worth manual
                confirmation) for `for_each:` / dispatch
  --findings    DRAFT findings.report payloads (confirm manually first)
  --assets      assets.mark payloads (web:site / web:route, depth tested)

Usage:
  python3 scripts/parse_nikto.py nikto.json --out merged.json \
      --work-units units.json --findings findings.json --assets assets.json
Only Python 3 standard library. (vulture / ebony-atoll)
"""

import argparse
import csv
import io
import json
import re
import sys

CRIT_RE = re.compile(r"(command exec|remote shell|shellshock|code execution|"
                     r"file upload|PUT method|allows? .*upload)", re.I)
HIGH_RE = re.compile(r"(sql injection|directory traversal|path traversal|"
                     r"\.git/|\.svn/|\.env|wp-config|backup file|password file|"
                     r"credential|remote file inclusion|config(uration)? file)", re.I)
MED_RE = re.compile(r"(xss|cross.site scripting|server-status|server-info|"
                    r"phpmyadmin|manager/html|admin(istration)? (console|page|interface)|"
                    r"TRACE .*enabled|XST|directory indexing|index of)", re.I)
LOW_RE = re.compile(r"(outdated|appears to be|default file|default page|"
                    r"x-frame-options|x-content-type|strict-transport|"
                    r"anti.clickjacking|uncommon header|banner|version)", re.I)


def severity_for(msg):
    m = msg or ""
    if CRIT_RE.search(m):
        return "critical"
    if HIGH_RE.search(m):
        return "high"
    if MED_RE.search(m):
        return "medium"
    if LOW_RE.search(m):
        return "low"
    return "info"


def cwe_for(msg):
    m = (msg or "").lower()
    table = [
        (r"sql injection", "CWE-89 / OWASP A03:2021 / WSTG-INPV-05"),
        (r"xss|cross.site scripting", "CWE-79 / OWASP A03:2021 / WSTG-INPV-01"),
        (r"command exec|shellshock|code execution", "CWE-78 / OWASP A03:2021"),
        (r"traversal", "CWE-22 / OWASP A01:2021 / WSTG-ATHZ-01"),
        (r"put method|file upload", "CWE-434 / OWASP A04:2021 / WSTG-CONF-06"),
        (r"trace|xst", "CWE-693 / OWASP A05:2021 / WSTG-CONF-06"),
        (r"directory indexing|index of", "CWE-548 / OWASP A05:2021 / WSTG-CONF-04"),
        (r"\.git|\.svn|\.env|backup|config", "CWE-538 / OWASP A05:2021 / WSTG-CONF-04"),
        (r"outdated|appears to be", "CWE-1104 / OWASP A06:2021"),
        (r"server-status|server-info|information|disclos", "CWE-200 / OWASP A05:2021 / WSTG-INFO-02"),
        (r"x-frame|clickjack|header", "CWE-16 / OWASP A05:2021 / WSTG-CONF-07"),
        (r"auth", "CWE-287 / OWASP A07:2021"),
    ]
    for pat, cls in table:
        if re.search(pat, m):
            return cls
    return "CWE-16 / OWASP A05:2021"


def base_url_for(host, port, ssl_hint=False):
    host = (host or "").strip()
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    port = str(port or "").strip()
    scheme = "https" if ssl_hint or port in ("443", "8443") else "http"
    if port and port not in ("80", "443"):
        return "%s://%s:%s" % (scheme, host, port)
    return "%s://%s" % (scheme, host)


def items_from_json_obj(obj):
    """Yield (base_url, banner, item) from one nikto JSON object."""
    if not isinstance(obj, dict):
        return
    base = base_url_for(obj.get("host"), obj.get("port"))
    banner = obj.get("banner") or ""
    for it in obj.get("vulnerabilities") or []:
        yield base, banner, it


def load_json_objects(raw):
    """Return list of nikto host objects from object/array/concatenated JSON."""
    raw = raw.strip()
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    # concatenated objects: {..}{..} or {..},{..} with no wrapper
    dec, objs, idx = json.JSONDecoder(), [], 0
    cleaned = raw.lstrip()
    while idx < len(cleaned):
        try:
            obj, end = dec.raw_decode(cleaned, idx)
            objs.append(obj)
            idx = end
            while idx < len(cleaned) and cleaned[idx] in ", \t\r\n":
                idx += 1
        except json.JSONDecodeError:
            break
    if objs:
        return objs
    sys.exit("could not parse input as nikto JSON")


def parse_csv(raw):
    """Yield (base_url, banner, item) from nikto CSV."""
    for row in csv.reader(io.StringIO(raw)):
        if not row or row[0].startswith("Nikto"):
            continue
        if len(row) >= 7:
            host, _ip, port, nid, method, uri, msg = row[:7]
            yield (base_url_for(host, port), "",
                   {"id": nid, "method": method, "url": uri, "msg": msg})
        elif len(row) >= 4:  # banner-ish line: host, ip, port, banner
            yield base_url_for(row[0], row[2]), row[3], None


def slugify(s):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", s.lower())).strip("-")[:70]


def main():
    ap = argparse.ArgumentParser(description="normalize nikto output for rupu")
    ap.add_argument("report", help="nikto JSON or CSV file ('-' for stdin)")
    ap.add_argument("--out", help="write merged summary JSON here")
    ap.add_argument("--work-units", dest="work_units",
                    help="write rupu work-units JSON array here")
    ap.add_argument("--findings", help="write DRAFT findings.report payloads here")
    ap.add_argument("--assets", help="write assets.mark payloads here")
    ap.add_argument("--min-severity", default="info",
                    choices=["info", "low", "medium", "high", "critical"],
                    help="floor for work units / findings (default info)")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.report == "-" else open(
        args.report, "r", encoding="utf-8", errors="replace").read()

    triples = []
    if raw.lstrip().startswith(("{", "[")):
        for obj in load_json_objects(raw):
            triples.extend(items_from_json_obj(obj))
    else:
        triples.extend(parse_csv(raw))

    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    floor = rank[args.min_severity]

    normalized, seen, banners = [], set(), {}
    for base, banner, it in triples:
        if banner:
            banners[base] = banner
        if it is None:
            continue
        path = it.get("url") or it.get("uri") or "/"
        url = path if path.startswith("http") else base + path
        msg = (it.get("msg") or it.get("message") or "").strip()
        key = (url, msg)
        if key in seen:
            continue
        seen.add(key)
        refs = it.get("references") or ""
        if isinstance(refs, str):
            refs = [r for r in re.split(r"[,\s]+", refs) if r]
        normalized.append({
            "url": url,
            "base": base,
            "path": path if path.startswith("/") else "/" + path.split("://")[-1].partition("/")[2],
            "method": (it.get("method") or "GET").upper(),
            "msg": msg,
            "id": str(it.get("id") or ""),
            "references": refs,
            "severity": severity_for(msg),
            "classification": cwe_for(msg),
        })

    merged = {"banners": banners, "count": len(normalized), "items": normalized}

    units = []
    for n in normalized:
        if rank[n["severity"]] < floor:
            continue
        units.append({
            "id": "nikto-" + slugify("%s %s" % (n["base"], n["path"] or n["msg"])),
            "title": "Confirm: %s" % (n["msg"][:120] or n["path"]),
            "targets": [n["url"]],
            "hints": {
                "tool": "nikto",
                "nikto_id": n["id"],
                "method": n["method"],
                "msg": n["msg"],
                "severity_guess": n["severity"],
                "confirm": "replay with curl -i -X %s '%s' and verify the "
                           "behavior before reporting" % (n["method"], n["url"]),
            },
        })

    findings = []
    for n in normalized:
        if rank[n["severity"]] < max(floor, 1):  # skip pure-info drafts
            continue
        host_wide = bool(re.search(r"outdated|appears to be|banner", n["msg"], re.I))
        findings.append({
            "title": n["msg"][:140] or ("nikto finding at %s" % n["path"]),
            "scope": "host" if host_wide else "endpoint",
            "target_ref": n["base"] if host_wide else n["url"],
            "severity": n["severity"],
            "classification": n["classification"],
            "evidence": {
                "rationale": "nikto signature %s matched: %s. DRAFT - replay and "
                             "attach the confirming HTTP exchange before submitting."
                             % (n["id"] or "(unnumbered)", n["msg"]),
                "http_exchange": "%s %s HTTP/1.1\nHost: %s\n\n<attach verified "
                                 "response>" % (n["method"], n["path"] or "/",
                                                n["base"].split("://")[-1]),
                "references": n["references"],
            },
        })

    assets = []
    for base, banner in sorted(banners.items()) or [
            (n["base"], "") for n in normalized[:1]]:
        assets.append({
            "kind": "web:site",
            "label": "%s (%s)" % (base, banner or "nikto baseline"),
            "coordinates": [{"t": "url", "v": base}],
            "depth": "tested",
        })
    marked = set()
    for n in normalized:
        if not n["path"] or (n["base"], n["path"]) in marked:
            continue
        marked.add((n["base"], n["path"]))
        assets.append({
            "kind": "web:route",
            "label": (n["msg"] or n["path"])[:120],
            "coordinates": [{"t": "url", "v": n["base"]},
                            {"t": "http_route", "v": n["path"]}],
            "depth": "tested",
        })

    def dump(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        print("wrote %s (%d items)" % (path, len(obj) if isinstance(obj, list) else 1),
              file=sys.stderr)

    if args.out:
        dump(args.out, merged)
    if args.work_units:
        dump(args.work_units, units)
    if args.findings:
        dump(args.findings, findings)
    if args.assets:
        dump(args.assets, assets)
    if not any((args.out, args.work_units, args.findings, args.assets)):
        json.dump(merged, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
