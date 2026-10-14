#!/usr/bin/env python3
"""parse_cors.py - normalize Corsy / CORScanner JSON into rupu-ingestible artifacts.

Inputs:
  -i file         Corsy JSON (dict keyed by URL) or CORScanner JSON (list of
                  records). Repeatable; format autodetected.
  --verify        re-send each hit's probe Origin with urllib and record the live
                  ACAO/ACAC headers as the HTTP exchange (evidence).
  --cookie "..."  Cookie header for the authenticated verify pass.
  --header "K: V" extra header for verify (repeatable).

Outputs:
  -o merged.json            normalized {url, misconfig_type, origin_reflected,
                            credentials, evidence} records
  --work-units units.json   rupu work-units JSON array (first char '[')
  --findings findings.json  array of ready findings.report payloads

Example:
  python3 scripts/parse_cors.py -i corsy.json -i corscanner.json \
      --verify --cookie "session=abc" \
      -o merged.json --work-units units.json --findings findings.json

Stdlib only. -- vulture (sage-ferry)
"""
import argparse
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request

# canonical misconfig type <- labels from both tools
TYPE_MAP = {
    "origin reflected": "reflect_origin",
    "reflect_origin": "reflect_origin",
    "wildcard value": "wildcard",
    "null origin allowed": "trust_null",
    "whitelisted null origin": "trust_null",
    "trust_null": "trust_null",
    "http origin allowed": "https_trust_http",
    "https_trust_http": "https_trust_http",
    "unescaped regex dot": "not_escape_dot",
    "not_escape_dot": "not_escape_dot",
    "pre-domain bypass": "suffix_match",
    "suffix_match": "suffix_match",
    "post-domain bypass": "prefix_match",
    "prefix_match": "prefix_match",
    "include_match": "include_match",
    "broad subdomain trust": "trust_any_subdomain",
    "trust_any_subdomain": "trust_any_subdomain",
    "custom_third_parties": "third_party_trust",
    "third party allowed": "third_party_trust",
    "special_characters_bypass": "special_characters_bypass",
    "invalid value": "invalid_value",
    "unrecognized origin": "unrecognized",
}

HIGH_TYPES = {"reflect_origin", "trust_null", "not_escape_dot", "prefix_match",
              "suffix_match", "include_match", "special_characters_bypass"}
MED_TYPES = {"trust_any_subdomain", "https_trust_http", "third_party_trust"}


def canon_type(label):
    if not label:
        return "unknown"
    key = str(label).strip().lower()
    return TYPE_MAP.get(key, key.replace(" ", "_"))


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def norm(url, mtype, origin, creds, evidence):
    return {
        "url": url,
        "misconfig_type": canon_type(mtype),
        "origin_reflected": origin or "",
        "credentials": bool(creds),
        "evidence": evidence or {},
    }


def parse_file(path):
    data = json.load(open(path))
    records = []
    if isinstance(data, dict):  # Corsy: {url: {class, acao header, acac header,...}}
        for url, v in data.items():
            if not isinstance(v, dict):
                continue
            acao = v.get("acao header") or v.get("acao") or ""
            acac = v.get("acac header") or v.get("acac") or ""
            records.append(norm(
                url, v.get("class") or v.get("type"), acao, truthy(acac),
                {"tool": "corsy",
                 "description": v.get("description", ""),
                 "exploitation": v.get("exploitation", ""),
                 "acao": acao, "acac": str(acac),
                 "tool_severity": v.get("severity", "")}))
    elif isinstance(data, list):  # CORScanner: [{url,type,credentials,origin}]
        for v in data:
            if not isinstance(v, dict) or not v.get("url"):
                continue
            records.append(norm(
                v["url"], v.get("type"), v.get("origin", ""),
                truthy(v.get("credentials", "")),
                {"tool": "corscanner", "acao": v.get("origin", ""),
                 "acac": str(v.get("credentials", ""))}))
    return records


def verify(rec, cookie=None, headers=None, timeout=10):
    """Re-send the probe Origin; store the live exchange in rec['evidence']."""
    origin = rec["origin_reflected"] or "https://evil.example.net"
    req = urllib.request.Request(rec["url"], method="GET")
    req.add_header("Origin", origin)
    req.add_header("User-Agent", "Mozilla/5.0 (cors-verify)")
    if cookie:
        req.add_header("Cookie", cookie)
    for h in headers or []:
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status, hdrs, body = resp.status, resp.headers, resp.read(2048)
    except urllib.error.HTTPError as e:
        status, hdrs, body = e.code, e.headers, e.read(2048)
    except Exception as e:  # network failure: keep tool evidence
        rec["evidence"]["verify_error"] = str(e)
        return rec
    acao = hdrs.get("Access-Control-Allow-Origin", "")
    acac = hdrs.get("Access-Control-Allow-Credentials", "")
    p = urllib.parse.urlsplit(rec["url"])
    req_lines = ["GET %s%s HTTP/1.1" % (p.path or "/",
                                        ("?" + p.query) if p.query else ""),
                 "Host: %s" % p.netloc, "Origin: %s" % origin]
    if cookie:
        req_lines.append("Cookie: %s=[REDACTED]" % cookie.split("=")[0])
    resp_lines = ["HTTP/1.1 %s" % status]
    for h in ("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
              "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
              "Vary", "Content-Type"):
        if hdrs.get(h):
            resp_lines.append("%s: %s" % (h, hdrs[h]))
    rec["evidence"].update({
        "verified": bool(acao),
        "request": "\r\n".join(req_lines) + "\r\n\r\n",
        "response": "\r\n".join(resp_lines) + "\r\n\r\n" +
                    body.decode("utf-8", "replace")[:500],
        "acao": acao, "acac": acac,
    })
    rec["origin_reflected"] = acao or rec["origin_reflected"]
    rec["credentials"] = truthy(acac) or rec["credentials"]
    return rec


def severity(rec):
    t, creds = rec["misconfig_type"], rec["credentials"]
    if t in HIGH_TYPES and creds:
        return "high"
    if t in MED_TYPES and creds:
        return "medium"
    if t in HIGH_TYPES:
        return "medium"
    if t == "wildcard":
        return "low"
    if t == "invalid_value":
        return "info"
    return "low"


def unit_id(rec):
    p = urllib.parse.urlsplit(rec["url"])
    path = p.path.strip("/").replace("/", "-") or "root"
    return "cors-%s-%s-%s" % (p.netloc or "unknown", path, rec["misconfig_type"])


def make_unit(rec):
    return {
        "id": unit_id(rec),
        "title": "CORS misconfig: %s @ %s" % (rec["misconfig_type"], rec["url"]),
        "targets": [rec["url"]],
        "hints": {
            "misconfig_type": rec["misconfig_type"],
            "origin_reflected": rec["origin_reflected"],
            "credentials": str(rec["credentials"]).lower(),
            "vuln_class": "cors-misconfiguration",
            "cwe": "CWE-942",
            "wstg": "WSTG-CLNT-07",
            "next_step": "authed verify with session cookie; build credentialed-"
                         "fetch PoC; capture exfiltrated body",
        },
    }


def make_finding(rec):
    sev = severity(rec)
    creds_txt = ("and sets Access-Control-Allow-Credentials: true, so any attacker "
                 "page can read the authenticated response with a credentialed fetch"
                 if rec["credentials"] else
                 "without Access-Control-Allow-Credentials; non-credentialed "
                 "responses are readable cross-origin")
    rationale = (
        "CORS misconfiguration (%s): the endpoint allows origin %s %s "
        "(CWE-942 / CWE-346, WSTG-CLNT-07). Tool evidence: %s"
        % (rec["misconfig_type"], rec["origin_reflected"] or "(see evidence)",
           creds_txt, rec["evidence"].get("tool", "manual")))
    p = urllib.parse.urlsplit(rec["url"])
    req = rec["evidence"].get("request") or (
        "GET %s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\n\r\n"
        % (p.path or "/", p.netloc,
           rec["origin_reflected"] or "https://evil.example.net"))
    resp = rec["evidence"].get("response") or (
        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: %s\r\n"
        "Access-Control-Allow-Credentials: %s\r\n... (capture the real response)"
        % (rec["evidence"].get("acao", rec["origin_reflected"]),
           rec["evidence"].get("acac", str(rec["credentials"]).lower())))
    return {
        "title": "CORS misconfiguration: %s%s on %s" % (
            rec["misconfig_type"].replace("_", " "),
            " with credentials" if rec["credentials"] else "",
            p.path or "/"),
        "scope": "endpoint",
        "target_ref": rec["url"],
        "severity": sev,
        "classification": {"cwe": "CWE-942", "wstg": "WSTG-CLNT-07"},
        "evidence": {"rationale": rationale, "request": req, "response": resp,
                     "misconfig_type": rec["misconfig_type"],
                     "origin_reflected": rec["origin_reflected"],
                     "credentials": str(rec["credentials"]).lower()},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input", action="append", default=[], required=True,
                    help="Corsy or CORScanner JSON file (repeatable, autodetected)")
    ap.add_argument("--verify", action="store_true",
                    help="re-send probe Origin per hit, record live ACAO/ACAC")
    ap.add_argument("--cookie", help="Cookie header value for authed verify")
    ap.add_argument("--header", action="append", help='extra "K: V" header for verify')
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("-o", "--output", help="merged normalized JSON")
    ap.add_argument("--work-units", help="rupu work-units array output")
    ap.add_argument("--findings", help="findings.report payloads array output")
    a = ap.parse_args()

    records = []
    for path in a.input:
        records.extend(parse_file(path))

    # dedupe on (url, misconfig_type), prefer credentialed record
    best = {}
    for r in records:
        key = (r["url"], r["misconfig_type"])
        if key not in best or (r["credentials"] and not best[key]["credentials"]):
            best[key] = r
    merged = list(best.values())

    if a.verify:
        for r in merged:
            verify(r, a.cookie, a.header, a.timeout)

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
        reportable = [r for r in merged
                      if not a.verify or r["evidence"].get("verified", True)]
        payloads = [make_finding(r) for r in reportable]
        open(a.findings, "w").write(json.dumps(payloads, indent=2) + "\n")
        print("[+] %d findings.report payload(s) -> %s"
              % (len(payloads), a.findings), file=sys.stderr)
    if not (a.output or a.work_units or a.findings):
        print(json.dumps(merged, indent=2))


if __name__ == "__main__":
    main()
