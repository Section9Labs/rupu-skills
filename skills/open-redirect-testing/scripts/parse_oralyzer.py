#!/usr/bin/env python3
"""parse_oralyzer.py - normalize Oralyzer output into rupu-ingestible artifacts.

Inputs (any mix):
  -i oralyzer.json      Oralyzer JSON output (-o file); list/dict/console-text tolerated.
  --confirmed file      manually confirmed hits: one per line,
                        "url<TAB>param<TAB>payload<TAB>type" (type: header|javascript|meta|crlf);
                        or a JSON array of {url,param,payload,type[,request,response]}.
  --candidates file     plain URL list (pre-scan) -> candidate work units only.

Outputs:
  -o merged.json        normalized records {url,param,payload,type,...}
  --work-units units.json   rupu work-units JSON array (first char '[')
  --findings findings.json  array of ready findings.report payloads

Example:
  python3 scripts/parse_oralyzer.py -i oralyzer.json --confirmed confirmed.txt \
      -o merged.json --work-units units.json --findings findings.json

Stdlib only. -- vulture (sage-ferry)
"""
import argparse
import json
import re
import sys
import urllib.parse

TYPES = ("header", "javascript", "meta", "crlf")

REDIRECT_PARAM = re.compile(
    r"^(redirect|redirect_uri|redirect_url|url|u|r|next|return|returnurl|return_to|"
    r"returnto|dest|destination|continue|goto|go|target|to|out|view|link|login_url|"
    r"logout|forward|callback|checkout_url|image_url|page|back|backurl|ref|"
    r"success_url|fail_url)$",
    re.I,
)


def guess_type(blob):
    low = str(blob).lower()
    for t in TYPES:
        if t in low:
            return t
    if "location" in low or "302" in low or "301" in low:
        return "header"
    if "refresh" in low:
        return "meta"
    return "header"


def guess_param(url):
    try:
        q = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                   keep_blank_values=True)
    except ValueError:
        return ""
    for k, _ in q:
        if REDIRECT_PARAM.match(k):
            return k
    return q[0][0] if q else ""


def norm_record(url, param=None, payload=None, rtype=None, extra=None):
    rec = {
        "url": url,
        "param": param or guess_param(url),
        "payload": payload or "",
        "type": (rtype or guess_type(payload or "")).lower(),
    }
    if rec["type"] not in TYPES:
        rec["type"] = guess_type(rec["type"])
    if extra:
        rec.update(extra)
    return rec


def parse_oralyzer_blob(text):
    """Accept Oralyzer JSON (list or dict) or raw console text."""
    records = []
    try:
        data = json.loads(text)
    except ValueError:
        # console text fallback: lines mentioning a payload URL and a type word
        for line in text.splitlines():
            m = re.search(r"(https?://\S+)", line)
            if not m:
                continue
            t = next((t for t in TYPES if t in line.lower()), None)
            if t or "vulnerable" in line.lower():
                records.append(norm_record(m.group(1), rtype=t))
        return records

    def pull(d, *keys):
        for k in keys:
            for kk in d:
                if kk.lower().replace(" ", "_") == k:
                    return d[kk]
        return None

    if isinstance(data, dict):
        items = []
        for k, v in data.items():
            if isinstance(v, list):
                for e in v:
                    items.append((k, e))
            else:
                items.append((k, v))
        for key, v in items:
            if isinstance(v, dict):
                url = pull(v, "url", "target", "link") or (
                    key if key.startswith("http") else "")
                records.append(norm_record(
                    url, pull(v, "param", "parameter"),
                    pull(v, "payload"),
                    pull(v, "type", "class", "kind", "filter"), ))
            elif isinstance(v, str) and key.startswith("http"):
                records.append(norm_record(key, rtype=guess_type(v), payload=v))
    elif isinstance(data, list):
        for v in data:
            if isinstance(v, str):
                records.append(norm_record(v))
            elif isinstance(v, dict):
                url = (v.get("url") or v.get("target") or v.get("link") or "")
                records.append(norm_record(
                    url, v.get("param") or v.get("parameter"),
                    v.get("payload"),
                    v.get("type") or v.get("class") or v.get("kind")))
    return [r for r in records if r["url"]]


def parse_confirmed(path):
    text = open(path).read()
    try:
        data = json.loads(text)
        return [norm_record(d.get("url", ""), d.get("param"), d.get("payload"),
                            d.get("type"),
                            {k: d[k] for k in ("request", "response") if k in d})
                for d in data if isinstance(d, dict) and d.get("url")]
    except ValueError:
        pass
    recs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t") if "\t" in line else line.split()
        url = parts[0]
        recs.append(norm_record(
            url,
            parts[1] if len(parts) > 1 else None,
            parts[2] if len(parts) > 2 else None,
            parts[3] if len(parts) > 3 else None))
    return recs


def unit_id(url, param, prefix="redir"):
    p = urllib.parse.urlsplit(url)
    path = p.path.strip("/").replace("/", "-") or "root"
    return "%s-%s-%s-%s" % (prefix, p.netloc or "unknown", path, param or "noparam")


def make_unit(rec):
    p = urllib.parse.urlsplit(rec["url"])
    hints = {
        "param": rec.get("param", ""),
        "vuln_class": "crlf-injection" if rec.get("type") == "crlf" else "open-redirect",
        "cwe": "CWE-113" if rec.get("type") == "crlf" else "CWE-601",
        "wstg": "WSTG-INPV-15" if rec.get("type") == "crlf" else "WSTG-CLNT-04",
    }
    if rec.get("type"):
        hints["type"] = rec["type"]
        hints["next_step"] = {
            "javascript": "js-type hit: test string breakout for DOM XSS escalation",
            "header": "header hit: verify with curl -skI; check OAuth/SSO context",
            "meta": "meta-refresh hit: verify reflected tag; phishing-chain PoC",
            "crlf": "crlf hit: try Set-Cookie injection and double-CRLF body split to XSS",
        }[rec["type"]]
    else:
        hints["next_step"] = ("fire references/payloads.md set; classify "
                              "header/js/meta; then -crlf mode")
    base = rec["url"].split("?")[0]
    target = "%s?%s=FUZZ" % (base, rec.get("param")) if rec.get("param") else rec["url"]
    return {
        "id": unit_id(rec["url"], rec.get("param")),
        "title": "Open-redirect candidate: %s @ %s://%s%s" % (
            rec.get("param") or "?", p.scheme or "https", p.netloc, p.path),
        "targets": [target],
        "hints": hints,
    }


def make_finding(rec):
    crlf = rec.get("type") == "crlf"
    p = urllib.parse.urlsplit(rec["url"])
    base = rec["url"].split("?")[0]
    target_ref = "%s?%s=" % (base, rec["param"]) if rec.get("param") else rec["url"]
    mech = rec.get("type", "header")
    if crlf:
        title = "CRLF injection / response splitting via %s parameter on %s" % (
            rec.get("param") or "?", p.path or "/")
        rationale = (
            "CR/LF sequences in the %s parameter are emitted unencoded into the "
            "response headers, allowing attacker-controlled headers/cookies on the "
            "trusted origin (CWE-113). Payload: %s"
            % (rec.get("param") or "?", rec.get("payload") or "(see request)"))
    else:
        title = "Open redirect via %s parameter on %s" % (
            rec.get("param") or "?", p.path or "/")
        rationale = (
            "The %s parameter controls navigation without validating the "
            "destination; payload %s redirects the user off-origin to an "
            "attacker-chosen site (CWE-601). Mechanism: %s."
            % (rec.get("param") or "?", rec.get("payload") or "(see request)", mech))
    req = rec.get("request") or "GET %s?%s=%s HTTP/1.1\r\nHost: %s\r\n\r\n" % (
        p.path or "/", rec.get("param") or "url",
        urllib.parse.quote(rec.get("payload") or "//evil.example.net/", safe=""),
        p.netloc)
    resp = rec.get("response") or (
        "HTTP/1.1 302 Found\r\nLocation: /account\r\nSet-Cookie: crlf=injected\r\n"
        "... (capture the real split response)" if crlf else
        "HTTP/1.1 302 Found\r\nLocation: %s\r\n... (capture the real response)"
        % (rec.get("payload") or "//evil.example.net/"))
    return {
        "title": title,
        "scope": "endpoint",
        "target_ref": target_ref,
        "severity": "high" if crlf else "medium",
        "classification": {"cwe": "CWE-113" if crlf else "CWE-601",
                           "wstg": "WSTG-INPV-15" if crlf else "WSTG-CLNT-04"},
        "evidence": {"rationale": rationale, "request": req, "response": resp,
                     "mechanism": mech},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input", action="append", default=[],
                    help="Oralyzer JSON output file (repeatable)")
    ap.add_argument("--confirmed", help="manually confirmed hits (tsv or JSON array)")
    ap.add_argument("--candidates", help="plain URL list -> candidate work units")
    ap.add_argument("-o", "--output", help="merged normalized JSON")
    ap.add_argument("--work-units", help="rupu work-units array output")
    ap.add_argument("--findings", help="findings.report payloads array output")
    a = ap.parse_args()

    records = []
    for path in a.input:
        records.extend(parse_oralyzer_blob(open(path).read()))
    if a.confirmed:
        records.extend(parse_confirmed(a.confirmed))

    candidates = []
    if a.candidates:
        for line in open(a.candidates):
            line = line.strip()
            if line.lower().startswith(("http://", "https://")):
                param = guess_param(line)
                if param:
                    candidates.append(norm_record(line, param, "", None))
                    candidates[-1]["type"] = ""  # pre-scan: no mechanism yet

    # dedupe on (url-without-query, param, type)
    seen, merged = set(), []
    for r in records + candidates:
        key = (r["url"].split("?")[0], r.get("param"), r.get("type"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(r)

    confirmed = [r for r in merged if r.get("type")]

    if a.output:
        open(a.output, "w").write(json.dumps(merged, indent=2) + "\n")
        print("[+] %d normalized record(s) -> %s" % (len(merged), a.output),
              file=sys.stderr)
    if a.work_units:
        units = [make_unit(r) for r in merged]
        open(a.work_units, "w").write(json.dumps(units, indent=2) + "\n")
        print("[+] %d work unit(s) -> %s" % (len(units), a.work_units),
              file=sys.stderr)
    if a.findings:
        payloads = [make_finding(r) for r in confirmed]
        open(a.findings, "w").write(json.dumps(payloads, indent=2) + "\n")
        print("[+] %d findings.report payload(s) -> %s"
              % (len(payloads), a.findings), file=sys.stderr)
    if not (a.output or a.work_units or a.findings):
        print(json.dumps(merged, indent=2))


if __name__ == "__main__":
    main()
