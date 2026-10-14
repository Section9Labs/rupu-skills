#!/usr/bin/env python3
"""parse_sqlmap.py — turn sqlmap output into rupu-ingestible JSON.

Reads any combination of:
  * a sqlmap per-host output directory (--output-dir), e.g.
    ~/.local/share/sqlmap/output/192.0.2.10/  — uses `log`, `target.txt`, `dump/**/*.csv`
    (session.sqlite is a hashdb with hashed keys; the text `log` is the parseable record)
  * a --results-file CSV written by sqlmap's --results-file
    (header: Target URL,Place,Parameter,Technique(s),Note(s))
  * an explicit --log file (overrides <output-dir>/log)

Emits:
  -o merged.json          merged machine-readable summary
  --work-units out.json   JSON ARRAY (first char '[') of work units for rupu for_each/dispatch
  --findings out.json     findings.report payloads (scope endpoint, WSTG-INPV-05 / CWE-89)
  --assets out.json       assets.mark payloads (web:site mapped, web:route exploited/tested)

Usage:
  python3 scripts/parse_sqlmap.py --output-dir ~/.local/share/sqlmap/output/192.0.2.10 \
      --results-file results.csv -o merged.json \
      --work-units work-units.json --findings findings.json --assets assets.json

Signed: vulture (crew hazel-marina)
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit

TECH_LETTERS = {
    "B": "boolean-based blind",
    "E": "error-based",
    "U": "UNION query",
    "S": "stacked queries",
    "T": "time-based blind",
    "Q": "inline query",
}

# place may itself contain parens, e.g. "Parameter: X-Foo #1* ((custom) HEADER)"
PARAM_RE = re.compile(r"^Parameter:\s*(?P<param>.+?)\s*\((?P<place>.+)\)\s*$")
TYPE_RE = re.compile(r"^\s+Type:\s*(.+?)\s*$")
TITLE_RE = re.compile(r"^\s+Title:\s*(.+?)\s*$")
PAYLOAD_RE = re.compile(r"^\s+Payload:\s*(.+?)\s*$")
VECTOR_RE = re.compile(r"^\s+Vector:\s*(.+?)\s*$")
DBMS_RE = re.compile(r"back-end DBMS(?:\s+is|:)\s*(?:active fingerprint:\s*)?([^\r\n\[]+)")
CURRENT_USER_RE = re.compile(r"current user:\s*'?([^'\r\n]+)'?")
CURRENT_DB_RE = re.compile(r"current database:\s*'?([^'\r\n]+)'?")
IS_DBA_RE = re.compile(r"current user is DBA:\s*(True|False)", re.IGNORECASE)
OS_SHELL_RE = re.compile(r"going to use .* to (?:execute|retrieve)|os-shell>", re.IGNORECASE)
URL_RE = re.compile(r"^(https?://\S+)")


def slugify(text):
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


def parse_log(log_path):
    """Extract injection-point blocks and facts from a sqlmap text log."""
    injections = {}  # (param, place) -> record
    facts = {"dbms": None, "current_user": None, "current_db": None,
             "is_dba": None, "os_shell": False}
    current = None
    try:
        text = Path(log_path).read_text(errors="replace")
    except OSError as exc:
        print(f"[!] cannot read log {log_path}: {exc}", file=sys.stderr)
        return injections, facts

    pending = None  # technique dict under construction
    for line in text.splitlines():
        m = PARAM_RE.match(line)
        if m:
            key = (m.group("param"), m.group("place"))
            current = injections.setdefault(
                key, {"parameter": m.group("param"), "place": m.group("place"),
                      "techniques": []})
            pending = None
            continue
        if current is not None:
            m = TYPE_RE.match(line)
            if m:
                pending = {"type": m.group(1), "title": None, "payload": None,
                           "vector": None}
                # dedupe by (type) later when payload known
                current["techniques"].append(pending)
                continue
            if pending is not None:
                m = TITLE_RE.match(line)
                if m:
                    pending["title"] = m.group(1)
                    continue
                m = PAYLOAD_RE.match(line)
                if m:
                    pending["payload"] = m.group(1)
                    continue
                m = VECTOR_RE.match(line)
                if m:
                    pending["vector"] = m.group(1)
                    continue
            if line.strip() == "---":
                current = None
                pending = None
                continue
        m = DBMS_RE.search(line)
        if m:
            facts["dbms"] = m.group(1).strip()
        m = CURRENT_USER_RE.search(line)
        if m:
            facts["current_user"] = m.group(1).strip()
        m = CURRENT_DB_RE.search(line)
        if m:
            facts["current_db"] = m.group(1).strip()
        m = IS_DBA_RE.search(line)
        if m:
            facts["is_dba"] = m.group(1).lower() == "true"
        if OS_SHELL_RE.search(line):
            facts["os_shell"] = True

    # dedupe repeated technique blocks (sqlmap reprints on resume)
    for rec in injections.values():
        seen = set()
        uniq = []
        for t in rec["techniques"]:
            k = (t["type"], t.get("payload"))
            if k not in seen:
                seen.add(k)
                uniq.append(t)
        rec["techniques"] = uniq
    return injections, facts


def parse_target(output_dir):
    """First URL in <output-dir>/target.txt, format: '<url> (<METHOD>)  # cmdline'."""
    tfile = Path(output_dir) / "target.txt"
    if not tfile.is_file():
        return None
    for line in tfile.read_text(errors="replace").splitlines():
        m = URL_RE.match(line.strip())
        if m:
            return m.group(1).split(" (")[0]
    return None


def parse_results_csv(path):
    """sqlmap --results-file CSV -> list of {url, place, parameter, techniques, notes}."""
    rows = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                letters = (row.get("Technique(s)") or "").strip()
                rows.append({
                    "url": (row.get("Target URL") or "").strip(),
                    "place": (row.get("Place") or "").strip(),
                    "parameter": (row.get("Parameter") or "").strip(),
                    "technique_letters": letters,
                    "techniques": [TECH_LETTERS[c] for c in letters
                                   if c in TECH_LETTERS],
                    "notes": (row.get("Note(s)") or "").strip(),
                })
    except OSError as exc:
        print(f"[!] cannot read results file {path}: {exc}", file=sys.stderr)
    return rows


def parse_dumps(output_dir):
    """Summarize <output-dir>/dump/<db>/<table>.csv files."""
    out = []
    dump_root = Path(output_dir) / "dump"
    if not dump_root.is_dir():
        return out
    for csvf in sorted(dump_root.rglob("*.csv")):
        try:
            with open(csvf, newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.reader(fh)
                header = next(reader, [])
                nrows = sum(1 for _ in reader)
        except OSError:
            continue
        out.append({
            "database": csvf.parent.name,
            "table": csvf.stem,
            "columns": header,
            "rows": nrows,
            "path": str(csvf),
        })
    return out


def sample_exchange(url, place, parameter, payload):
    """Reconstruct a representative HTTP exchange for evidence (replace with the
    proxy-captured pair before filing)."""
    parts = urlsplit(url or "http://example.com/")
    host = parts.netloc or "example.com"
    path = parts.path or "/"
    if place.upper() == "GET" and payload:
        qs = quote(payload, safe="=&")
        req = f"GET {path}?{qs} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    elif place.upper() in ("POST", "JSON") and payload:
        req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(payload)}\r\n\r\n{payload}")
    else:
        req = (f"GET {path}{'?' + parts.query if parts.query else ''} HTTP/1.1\r\n"
               f"Host: {host}\r\n{place}: {payload or '<injected value>'}\r\n\r\n")
    resp = ("HTTP/1.1 200 OK\r\n\r\n[response differential/delay confirming injection "
            "— replace this reconstructed exchange with the proxy-captured pair]")
    return req + "\r\n---\r\n" + resp


def merge(log_inj, facts, csv_rows, target_url):
    """Merge log-derived and results-CSV-derived injection records keyed on
    (parameter, place)."""
    merged = {}
    for (param, place), rec in log_inj.items():
        merged[(param, place)] = {
            "url": target_url,
            "parameter": param,
            "place": place,
            "techniques": [t["type"] for t in rec["techniques"]],
            "payloads": [t["payload"] for t in rec["techniques"] if t.get("payload")],
            "titles": [t["title"] for t in rec["techniques"] if t.get("title")],
            "dbms": facts.get("dbms"),
        }
    for row in csv_rows:
        key = (row["parameter"], row["place"])
        if key in merged:
            m = merged[key]
            m["url"] = m["url"] or row["url"]
            for t in row["techniques"]:
                if t not in m["techniques"]:
                    m["techniques"].append(t)
        else:
            merged[key] = {
                "url": row["url"] or target_url,
                "parameter": row["parameter"],
                "place": row["place"],
                "techniques": row["techniques"],
                "payloads": [],
                "titles": [],
                "dbms": facts.get("dbms"),
            }
    return list(merged.values())


def build_work_units(injections, facts):
    units = []
    for inj in injections:
        url = inj["url"] or "http://example.com/"
        host = urlsplit(url).netloc or "unknown"
        dbms_flag = f" --dbms='{inj['dbms']}'" if inj.get("dbms") else ""
        units.append({
            "id": slugify(f"sqli-{host}-{inj['parameter']}-{inj['place']}"),
            "title": (f"Exploit SQLi: parameter '{inj['parameter']}' "
                      f"({inj['place']}) at {url}"),
            "targets": [url],
            "hints": {
                "param": inj["parameter"],
                "place": inj["place"],
                "techniques": "; ".join(inj["techniques"]) or "unknown",
                "dbms": inj.get("dbms") or "unknown",
                "payload": inj["payloads"][0] if inj["payloads"] else "",
                "next": (f"sqlmap -u '{url}' -p {inj['parameter']} --batch"
                         f"{dbms_flag} --technique=BEUSTQ --dbs"),
            },
        })
    return units


def severity(inj, facts, dumps):
    techs = " ".join(inj["techniques"]).lower()
    if facts.get("os_shell") or facts.get("is_dba") or dumps or "stacked" in techs:
        return "critical"
    return "high"


def build_findings(injections, facts, dumps):
    findings = []
    dump_note = ""
    if dumps:
        parts = [f"{d['database']}.{d['table']} ({d['rows']} rows: "
                 f"{', '.join(d['columns'][:8])})" for d in dumps]
        dump_note = " Data dumped: " + "; ".join(parts) + "."
    for inj in injections:
        url = inj["url"] or "http://example.com/"
        payload = inj["payloads"][0] if inj["payloads"] else None
        rationale = (
            f"Parameter '{inj['parameter']}' ({inj['place']}) is injectable via "
            f"{', '.join(inj['techniques']) or 'SQL injection'}"
            + (f" (sample payload: {payload})" if payload else "")
            + (f". Back-end DBMS: {inj['dbms']}" if inj.get("dbms") else "")
            + (f". Current user: {facts['current_user']}" if facts.get("current_user") else "")
            + (". Current user is DBA." if facts.get("is_dba") else "")
            + (" OS command execution obtained via --os-shell." if facts.get("os_shell") else "")
            + "." + dump_note
        )
        findings.append({
            "title": (f"SQL injection in '{inj['parameter']}' ({inj['place']}) "
                      f"at {url}"),
            "scope": "endpoint",
            "target_ref": url,
            "severity": severity(inj, facts, dumps),
            "classification": {"owasp": "WSTG-INPV-05", "cwe": "CWE-89"},
            "evidence": {
                "rationale": rationale,
                "http_exchange": sample_exchange(url, inj["place"],
                                                 inj["parameter"], payload),
            },
        })
    return findings


def build_assets(injections, target_url):
    assets = []
    sites = set()
    for inj in injections:
        url = inj["url"] or target_url
        if not url:
            continue
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}"
        if base not in sites:
            sites.add(base)
            assets.append({"kind": "web:site",
                           "coordinates": [{"t": "url", "v": base}],
                           "label": base, "depth": "mapped"})
        assets.append({
            "kind": "web:route",
            "coordinates": [
                {"t": "url", "v": base},
                {"t": "http_route", "v": parts.path or "/"},
                {"t": "param", "v": inj["parameter"]},
            ],
            "label": (f"SQLi: {inj['parameter']} ({inj['place']}) "
                      f"{parts.path or '/'}"
                      + (f" — {inj['dbms']}" if inj.get("dbms") else "")),
            "depth": "exploited",
        })
    return assets


def main():
    ap = argparse.ArgumentParser(
        description="Parse sqlmap output into merged JSON, rupu work units, "
                    "findings.report and assets.mark payloads.")
    ap.add_argument("--output-dir",
                    help="sqlmap per-host output dir (contains log, target.txt, dump/)")
    ap.add_argument("--log", help="explicit sqlmap log file (overrides <output-dir>/log)")
    ap.add_argument("--results-file", help="CSV from sqlmap --results-file")
    ap.add_argument("--url", help="override/supply the target URL")
    ap.add_argument("-o", "--out", help="write merged summary JSON here (default stdout)")
    ap.add_argument("--work-units", help="write work-units JSON array here")
    ap.add_argument("--findings", help="write findings.report payloads here")
    ap.add_argument("--assets", help="write assets.mark payloads here")
    args = ap.parse_args()

    if not (args.output_dir or args.log or args.results_file):
        ap.error("need at least one of --output-dir / --log / --results-file")

    log_path = args.log
    if not log_path and args.output_dir:
        cand = Path(args.output_dir) / "log"
        log_path = str(cand) if cand.is_file() else None

    log_inj, facts = parse_log(log_path) if log_path else ({}, {
        "dbms": None, "current_user": None, "current_db": None,
        "is_dba": None, "os_shell": False})
    csv_rows = parse_results_csv(args.results_file) if args.results_file else []
    target_url = args.url or (parse_target(args.output_dir) if args.output_dir else None)
    dumps = parse_dumps(args.output_dir) if args.output_dir else []

    injections = merge(log_inj, facts, csv_rows, target_url)
    work_units = build_work_units(injections, facts)
    findings = build_findings(injections, facts, dumps)
    assets = build_assets(injections, target_url)

    merged = {
        "target": target_url,
        "facts": facts,
        "injections": injections,
        "dumped_tables": dumps,
        "counts": {"injections": len(injections), "dumped_tables": len(dumps)},
    }

    def write(path, obj):
        Path(path).write_text(json.dumps(obj, indent=2) + "\n")
        print(f"[+] wrote {path} ({len(obj) if isinstance(obj, list) else 1} items)",
              file=sys.stderr)

    if args.work_units:
        write(args.work_units, work_units)
    if args.findings:
        write(args.findings, findings)
    if args.assets:
        write(args.assets, assets)
    if args.out:
        write(args.out, merged)
    else:
        json.dump(merged, sys.stdout, indent=2)
        print()

    if not injections:
        print("[!] no injection points found in the supplied sqlmap output",
              file=sys.stderr)


if __name__ == "__main__":
    main()
