#!/usr/bin/env python3
"""parse_discovery.py — normalize and merge content-discovery tool output.

Reads any mix of:
  * ffuf JSON            (--ffuf out.json)        ffuf ... -o out.json -of json
  * feroxbuster NDJSON   (--ferox out.ndjson)     feroxbuster ... --json -o out.ndjson
  * dirsearch JSON       (--dirsearch out.json)   dirsearch ... --format json -o out.json
  * gobuster text        (--gobuster out.txt)     gobuster dir|vhost|dns|fuzz ... -o out.txt
                         (dir/fuzz output needs --base-url to rebuild full URLs)

Normalizes everything to records:
  {url, status, length, words, lines, redirect, source, category, host_header}

Emits:
  * merged, deduped JSON array of records  (-o merged.json, default stdout)
  * rupu work-units JSON array             (--work-units units.json)
  * rupu assets.mark payload array         (--assets assets.json)

Examples:
  python3 scripts/parse_discovery.py --ffuf ffuf-dirs.json --ferox ferox.ndjson \
      --dirsearch dirsearch.json --gobuster gobuster-dir.txt \
      --base-url https://192.0.2.10 -o merged.json \
      --work-units units.json --assets assets.json
"""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit

# ---------------------------------------------------------------- categories

CATEGORY_PATTERNS = [
    ("admin", re.compile(
        r"(?:^|/)(admin|administrator|manager|console|dashboard|cpanel|"
        r"phpmyadmin|pma|wp-admin|wp-login|login|signin|auth|portal)"
        r"(?:[/._?]|$)", re.I)),
    ("upload", re.compile(
        r"(?:^|/)(upload|uploads|uploader|files|file|import|attachments?|media)"
        r"(?:[/._?]|$)", re.I)),
    ("api", re.compile(
        r"(?:^|/)(api|apis|rest|graphql|v[0-9]+|swagger[^/]*|openapi[^/]*|"
        r"api-docs|soap|rpc|ws|jsonrpc)(?:[/._?]|$)", re.I)),
    ("backup", re.compile(
        r"(\.bak|\.old|\.orig|\.save|\.swp|~$|\.zip|\.tar|\.tar\.gz|\.tgz|"
        r"\.rar|\.7z|\.sql|\.dump|backup|\.copy|\.1$)", re.I)),
    ("config", re.compile(
        r"(\.env|\.git|\.svn|\.hg|\.DS_Store|web\.config|\.htaccess|"
        r"\.htpasswd|config|settings|\.ini$|\.yml$|\.yaml$|\.conf$|"
        r"composer\.json|package\.json|phpinfo|server-status|\.idea)", re.I)),
]

NEXT_SKILL = {
    "admin": "auth-testing",
    "upload": "file-upload-testing",
    "api": "api-testing",
    "backup": "secret-extraction",
    "config": "secret-extraction",
    "vhost": "recon-and-crawl",
    "other": "vuln-testing",
}


def categorize(url):
    path = urlsplit(url).path or "/"
    query = urlsplit(url).query
    hay = path + ("?" + query if query else "")
    for cat, rx in CATEGORY_PATTERNS:
        if rx.search(hay):
            return cat
    return "other"


# ----------------------------------------------------------------- record


def record(url, status=None, length=None, words=None, lines=None,
           redirect="", source="", host_header="", category=None):
    url = (url or "").strip()
    return {
        "url": url,
        "status": int(status) if status not in (None, "") else None,
        "length": int(length) if length not in (None, "") else None,
        "words": int(words) if words not in (None, "") else None,
        "lines": int(lines) if lines not in (None, "") else None,
        "redirect": redirect or "",
        "source": source,
        "host_header": host_header or "",
        "category": category or categorize(url),
    }


# ----------------------------------------------------------------- parsers


def parse_ffuf(path):
    """ffuf -o out.json -of json : {"results":[{url,status,length,words,lines,
    redirectlocation,input:{KEYWORD:payload},host}]}"""
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    for r in data.get("results", []):
        url = r.get("url", "")
        inputs = r.get("input", {}) or {}
        host_header = ""
        # vhost fuzzing: FUZZ payload lands in the Host header, url is static
        host_val = r.get("host", "")
        if host_val and host_val not in url:
            host_header = host_val
        rec = record(
            url,
            status=r.get("status"),
            length=r.get("length"),
            words=r.get("words"),
            lines=r.get("lines"),
            redirect=r.get("redirectlocation", ""),
            source="ffuf",
            host_header=host_header,
        )
        if host_header:
            rec["category"] = "vhost"
            parts = urlsplit(url)
            rec["url"] = "%s://%s/" % (parts.scheme or "https", host_header)
        if not host_header and len(inputs) == 1:
            payload = next(iter(inputs.values()))
            if payload and payload not in url:
                # keyword was elsewhere (header/body); keep url, note payload
                rec["payload"] = payload
        out.append(rec)
    return out


def parse_ferox(path):
    """feroxbuster --json -o out.ndjson : NDJSON, keep type==response."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("type") != "response":
                continue
            headers = obj.get("headers", {}) or {}
            redirect = headers.get("location") or headers.get("Location") or ""
            out.append(record(
                obj.get("url", ""),
                status=obj.get("status"),
                length=obj.get("content_length"),
                words=obj.get("word_count"),
                lines=obj.get("line_count"),
                redirect=redirect,
                source="feroxbuster",
            ))
    return out


def parse_dirsearch(path):
    """dirsearch --format json -o out.json.
    New: {"info":{...},"results":[{url,status,content-length,redirect}]}
    Old: {"https://target:443/": [{"path","status","content-length","redirect"}]}
    """
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        for r in data["results"]:
            out.append(record(
                r.get("url", ""),
                status=r.get("status"),
                length=r.get("content-length", r.get("content_length")),
                redirect=r.get("redirect", ""),
                source="dirsearch",
            ))
        return out
    if isinstance(data, dict):
        for base, entries in data.items():
            if base == "info" or not isinstance(entries, list):
                continue
            for r in entries:
                if not isinstance(r, dict):
                    continue
                p = r.get("path", "")
                url = r.get("url") or (base.rstrip("/") + "/" + p.lstrip("/"))
                out.append(record(
                    url,
                    status=r.get("status"),
                    length=r.get("content-length", r.get("content_length")),
                    redirect=r.get("redirect", ""),
                    source="dirsearch",
                ))
    return out


# gobuster dir:   /admin  (Status: 301) [Size: 312] [--> https://x/admin/]
GOBUSTER_DIR_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?")
# gobuster vhost: Found: admin.example.com Status: 200 [Size: 4321]
GOBUSTER_VHOST_RE = re.compile(
    r"^Found:\s*(?P<host>[A-Za-z0-9._-]+)\s+Status:\s*(?P<status>\d+)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?")
# gobuster dns:   Found: dev.example.com [198.51.100.7]
GOBUSTER_DNS_RE = re.compile(
    r"^Found:\s*(?P<host>[A-Za-z0-9._-]+)\s*(?:\[(?P<ips>[^\]]*)\])?\s*$")
# gobuster fuzz:  Found: [Status=200] [Length=42] https://x/FUZZed?x=1
GOBUSTER_FUZZ_RE = re.compile(
    r"^Found:\s*\[Status=(?P<status>\d+)\]\s*\[Length=(?P<size>\d+)\]"
    r"\s*(?P<url>\S+)")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_gobuster(path, base_url):
    """Parse gobuster plain-text output (dir / vhost / dns / fuzz lines)."""
    out = []
    scheme = urlsplit(base_url).scheme if base_url else "https"
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = ANSI_RE.sub("", raw).strip()
            if not line or line.startswith(("=", "[+]", "[-]", "---", "Progress")):
                continue
            m = GOBUSTER_FUZZ_RE.match(line)
            if m:
                out.append(record(m.group("url"), status=m.group("status"),
                                  length=m.group("size"),
                                  source="gobuster-fuzz"))
                continue
            m = GOBUSTER_VHOST_RE.match(line)
            if m:
                url = "%s://%s/" % (scheme, m.group("host"))
                rec = record(url, status=m.group("status"),
                             length=m.group("size"), source="gobuster-vhost",
                             host_header=m.group("host"))
                rec["category"] = "vhost"
                out.append(rec)
                continue
            m = GOBUSTER_DIR_RE.match(line)
            if m:
                if not base_url:
                    print("warning: gobuster dir line without --base-url, "
                          "skipped: %s" % line, file=sys.stderr)
                    continue
                url = base_url.rstrip("/") + m.group("path")
                out.append(record(url, status=m.group("status"),
                                  length=m.group("size"),
                                  redirect=m.group("redirect") or "",
                                  source="gobuster-dir"))
                continue
            m = GOBUSTER_DNS_RE.match(line)
            if m:
                url = "%s://%s/" % (scheme, m.group("host"))
                rec = record(url, source="gobuster-dns",
                             host_header=m.group("host"))
                rec["category"] = "vhost"
                if m.group("ips"):
                    rec["ips"] = m.group("ips")
                out.append(rec)
    return out


# ------------------------------------------------------------------ merge


def dedupe(records):
    """Dedupe on normalized URL; keep the record with the most information."""
    def key(r):
        parts = urlsplit(r["url"])
        path = parts.path or "/"
        return (parts.scheme.lower(), parts.netloc.lower(),
                path.rstrip("/") or "/", parts.query)

    def score(r):
        return sum(1 for k in ("status", "length", "words", "lines")
                   if r.get(k) is not None) + (1 if r.get("redirect") else 0)

    best = {}
    for r in records:
        if not r["url"]:
            continue
        k = key(r)
        if k not in best:
            best[k] = dict(r)
        else:
            cur = best[k]
            if score(r) > score(cur):
                merged = dict(r)
            else:
                merged = dict(cur)
            srcs = set(cur["source"].split("+")) | set(r["source"].split("+"))
            merged["source"] = "+".join(sorted(s for s in srcs if s))
            best[k] = merged
    return sorted(best.values(), key=lambda r: r["url"])


# -------------------------------------------------------------- rupu output


def slug(text, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen].strip("-") or "x"


def site_of(url):
    p = urlsplit(url)
    return "%s://%s" % (p.scheme, p.netloc)


INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def build_work_units(records):
    units = []
    seen = set()
    for i, r in enumerate(records, 1):
        if r["status"] is not None and r["status"] not in INTERESTING_STATUSES:
            continue
        if r["url"] in seen:
            continue
        seen.add(r["url"])
        cat = r.get("category", "other")
        if cat == "vhost":
            title = "New virtual host %s" % urlsplit(r["url"]).netloc
        else:
            title = "Probe discovered route %s on %s" % (
                urlsplit(r["url"]).path or "/", site_of(r["url"]))
        hints = {
            "category": cat,
            "source": r.get("source", ""),
            "next": NEXT_SKILL.get(cat, "vuln-testing"),
        }
        if r["status"] is not None:
            hints["status"] = str(r["status"])
        if r["length"] is not None:
            hints["length"] = str(r["length"])
        if r.get("redirect"):
            hints["redirect"] = r["redirect"]
        units.append({
            "id": "cd-%s-%04d" % (slug(urlsplit(r["url"]).netloc), i),
            "title": title,
            "targets": [r["url"]],
            "hints": hints,
        })
    return units


def build_assets(records):
    assets = []
    seen = set()
    for r in records:
        if r["url"] in seen:
            continue
        seen.add(r["url"])
        status = (" [%s]" % r["status"]) if r["status"] is not None else ""
        if r.get("category") == "vhost":
            site = site_of(r["url"]).rstrip("/")
            assets.append({
                "kind": "web:site",
                "coordinates": [{"t": "url", "v": site}],
                "label": site + status,
                "depth": "mapped",
            })
        else:
            parts = urlsplit(r["url"])
            route = parts.path or "/"
            coords = [{"t": "url", "v": site_of(r["url"])},
                      {"t": "http_route", "v": route}]
            if parts.query:
                first_param = parts.query.split("&")[0].split("=")[0]
                if first_param:
                    coords.append({"t": "param", "v": first_param})
            assets.append({
                "kind": "web:route",
                "coordinates": coords,
                "label": route + status,
                "depth": "mapped",
            })
    return assets


# ------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description="Normalize/merge ffuf, feroxbuster, dirsearch, gobuster "
                    "output into rupu-ingestible JSON.")
    ap.add_argument("--ffuf", action="append", default=[],
                    help="ffuf JSON file (repeatable)")
    ap.add_argument("--ferox", action="append", default=[],
                    help="feroxbuster NDJSON file (repeatable)")
    ap.add_argument("--dirsearch", action="append", default=[],
                    help="dirsearch JSON file (repeatable)")
    ap.add_argument("--gobuster", action="append", default=[],
                    help="gobuster text output file (repeatable)")
    ap.add_argument("--base-url", default="",
                    help="base URL for gobuster dir output "
                         "(e.g. https://192.0.2.10)")
    ap.add_argument("-o", "--output", default="-",
                    help="merged records JSON (default stdout)")
    ap.add_argument("--work-units", metavar="FILE",
                    help="write rupu work-units JSON array here")
    ap.add_argument("--assets", metavar="FILE",
                    help="write assets.mark payload JSON array here")
    args = ap.parse_args()

    records = []
    for p in args.ffuf:
        records.extend(parse_ffuf(p))
    for p in args.ferox:
        records.extend(parse_ferox(p))
    for p in args.dirsearch:
        records.extend(parse_dirsearch(p))
    for p in args.gobuster:
        records.extend(parse_gobuster(p, args.base_url))

    if not records:
        print("no records parsed — check inputs", file=sys.stderr)

    merged = dedupe(records)

    blob = json.dumps(merged, indent=2)
    if args.output == "-":
        print(blob)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(blob + "\n")

    if args.work_units:
        units = build_work_units(merged)
        with open(args.work_units, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(units, indent=2) + "\n")
        print("wrote %d work units -> %s" % (len(units), args.work_units),
              file=sys.stderr)

    if args.assets:
        assets = build_assets(merged)
        with open(args.assets, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(assets, indent=2) + "\n")
        print("wrote %d asset payloads -> %s" % (len(assets), args.assets),
              file=sys.stderr)

    print("merged %d raw records into %d unique endpoints"
          % (len(records), len(merged)), file=sys.stderr)


if __name__ == "__main__":
    main()
