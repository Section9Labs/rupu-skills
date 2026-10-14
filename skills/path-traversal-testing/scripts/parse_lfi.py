#!/usr/bin/env python3
"""parse_lfi.py — normalize path-traversal/LFI tool output into rupu outputs.

Ingests any mix of:
  --lfimap lfimap.out       lfimap console/--log output ([+] confirmed lines)
  --dotdotpwn ddp.out       DotDotPwn console output (<- VULNERABLE lines)
  --ffuf ffuf.json          ffuf -of json output (matched traversal payloads)
  --hits hits.json          manual hits: JSON list of
                            {url, param?, payload?, technique?, file_read?,
                             evidence?, rce?}

Emits:
  --merged lfi_hits.json        normalized hit list (JSON array)
  --work-units lfi_units.json   rupu work-units ARRAY (for_each:/dispatch fan-out)
  --findings lfi_findings.json  findings.report payloads (one per hit)

Severity: rce -> critical, RFI -> critical, file read -> high.
Classification: WSTG-INPV-11/12 + CWE-22/CWE-98 per technique.
"""
import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl, unquote

URL_RE = re.compile(r"https?://[^\s'\"<>]+")

TECH_MAP = [
    ("php://filter", "php-filter", False),
    ("php://input", "php-input", True),
    ("data://", "data-wrapper", True),
    ("data:", "data-wrapper", True),
    ("expect://", "expect-wrapper", True),
    ("http://", "rfi", True),
    ("https://", "rfi", True),
    ("ftp://", "rfi", True),
    ("/proc/self/environ", "proc-environ", True),
    ("sess_", "session-include", True),
    ("log", "log-poisoning", True),
    ("..", "traversal", False),
    ("%2e", "traversal-encoded", False),
    ("%252e", "traversal-double-encoded", False),
]

READ_SIGNS = {
    "/etc/passwd": "passwd", "win.ini": "win.ini", "/etc/shadow": "shadow",
    "wp-config": "wp-config.php", ".env": ".env", "resource=": None,
}


def classify_technique(payload, line=""):
    blob = (payload or "") + " " + (line or "")
    low = blob.lower()
    for marker, tech, rce in TECH_MAP:
        if marker in low:
            return tech, rce
    return "traversal", False


def guess_param_payload(url):
    """Return (param, payload) for the query key whose value looks like a payload."""
    try:
        qs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return None, None
    best = (None, None)
    for k, v in qs:
        dv = unquote(unquote(v))
        if any(m in dv for m in ("../", "..\\", "://", "/etc/", "\\windows\\", "....//")):
            return k, v
        if best == (None, None):
            best = (k, v)
    return best


def guess_file_read(payload, line=""):
    blob = ((payload or "") + " " + (line or "")).lower()
    for sign, name in READ_SIGNS.items():
        if sign in blob:
            if sign == "resource=":
                m = re.search(r"resource=([^&\s'\"]+)", blob)
                return m.group(1) if m else None
            return name
    return None


def norm_hit(url, source, line=None, param=None, payload=None,
             technique=None, file_read=None, evidence=None, rce=None):
    if param is None or payload is None:
        p, pl = guess_param_payload(url)
        param = param or p
        payload = payload or pl
    if technique is None:
        technique, trce = classify_technique(payload, line)
        if rce is None:
            rce = trce
    if file_read is None:
        file_read = guess_file_read(payload, line)
    return {
        "url": url,
        "param": param,
        "payload": payload,
        "technique": technique,
        "file_read": file_read,
        "rce": bool(rce),
        "evidence": evidence or (line.strip() if line else ""),
        "source": source,
    }


def parse_lfimap(path):
    hits = []
    with open(path, errors="replace") as f:
        for line in f:
            if not line.lstrip().startswith("[+]"):
                continue
            m = URL_RE.search(line)
            if not m:
                continue
            rce = bool(re.search(r"shell|rce|command|exec", line, re.I)) or None
            hits.append(norm_hit(m.group(0).rstrip("'\""), "lfimap",
                                 line=line, rce=rce))
    return hits


def parse_dotdotpwn(path):
    hits = []
    with open(path, errors="replace") as f:
        for line in f:
            if "VULNERABLE" not in line.upper():
                continue
            m = URL_RE.search(line)
            if m:
                hits.append(norm_hit(m.group(0), "dotdotpwn", line=line))
            else:
                # non-URL modules print the raw traversal payload
                pm = re.search(r"(?:Path|Testing)[:\s]+(\S+)", line)
                if pm:
                    hits.append(norm_hit("", "dotdotpwn", line=line,
                                         payload=pm.group(1)))
    return hits


def parse_ffuf(path):
    hits = []
    with open(path, errors="replace") as f:
        data = json.load(f)
    for r in data.get("results", []):
        payload = None
        inp = r.get("input") or {}
        if isinstance(inp, dict):
            payload = inp.get("FUZZ") or (list(inp.values())[0] if inp else None)
        hits.append(norm_hit(
            r.get("url", ""), "ffuf", payload=payload,
            evidence="status=%s length=%s words=%s" % (
                r.get("status"), r.get("length"), r.get("words"))))
    return hits


def parse_hits_json(path):
    with open(path, errors="replace") as f:
        raw = json.load(f)
    return [norm_hit(h.get("url", ""), "manual",
                     param=h.get("param"), payload=h.get("payload"),
                     technique=h.get("technique"), file_read=h.get("file_read"),
                     evidence=h.get("evidence"), rce=h.get("rce"))
            for h in raw]


def dedupe(hits):
    seen, out = set(), []
    for h in hits:
        key = (h["url"], h["param"], h["payload"], h["technique"])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def classification(h):
    if h["technique"] == "rfi":
        return {"wstg": "WSTG-INPV-12", "cwe": "CWE-98"}, "critical"
    if h["rce"]:
        return {"wstg": "WSTG-INPV-11", "cwe": "CWE-98"}, "critical"
    return {"wstg": "WSTG-INPV-11", "cwe": "CWE-22"}, "high"


def to_work_units(hits):
    units = []
    for i, h in enumerate(hits, 1):
        host = urlsplit(h["url"]).netloc or "unknown"
        cls, _ = classification(h)
        units.append({
            "id": "lfi-%s-%s-%d" % (
                re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-"),
                re.sub(r"[^a-z0-9]+", "-", (h["param"] or "p").lower()).strip("-"),
                i),
            "title": "Escalate %s on %s param %s" % (
                h["technique"], h["url"].split("?")[0], h["param"]),
            "targets": [h["url"]],
            "hints": {
                "param": h["param"] or "",
                "payload": h["payload"] or "",
                "technique": h["technique"],
                "file_read": h["file_read"] or "",
                "rce": str(h["rce"]).lower(),
                "next": ("post-exploitation: loot creds, pivot" if h["rce"] else
                         "php://filter source read, filter-chain RCE, log "
                         "poisoning, session include; loot configs"),
                "wstg": cls["wstg"],
                "cwe": cls["cwe"],
            },
        })
    return units


def to_findings(hits):
    findings = []
    for h in hits:
        cls, sev = classification(h)
        what = ("remote/local file inclusion reaching code execution" if h["rce"]
                else "arbitrary file read outside the intended directory")
        findings.append({
            "title": "%s via %s in %s parameter" % (
                "RCE through file inclusion" if h["rce"] else "Path traversal",
                h["technique"], h["param"] or "unknown"),
            "scope": "endpoint",
            "target_ref": h["url"],
            "severity": sev,
            "classification": cls,
            "evidence": {
                "rationale": (
                    "Parameter %r accepts attacker-controlled path/wrapper input "
                    "(%s), resulting in %s. Payload: %s. File/content obtained: %s. "
                    "Tool evidence: %s. (%s / %s)" % (
                        h["param"], h["technique"], what, h["payload"],
                        h["file_read"] or "see exchange", h["evidence"],
                        cls["wstg"], cls["cwe"])),
                "http_exchanges": [{
                    "name": "confirmation",
                    "request": "REPLACE: raw request for %s" % h["url"],
                    "response": "REPLACE: raw response incl. leaked content/command output",
                }],
            },
        })
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lfimap", action="append", default=[])
    ap.add_argument("--dotdotpwn", action="append", default=[])
    ap.add_argument("--ffuf", action="append", default=[])
    ap.add_argument("--hits", action="append", default=[])
    ap.add_argument("--merged", help="write normalized hits JSON array")
    ap.add_argument("--work-units", help="write rupu work-units JSON array")
    ap.add_argument("--findings", help="write findings.report payloads JSON array")
    args = ap.parse_args()

    hits = []
    for p in args.lfimap:
        hits += parse_lfimap(p)
    for p in args.dotdotpwn:
        hits += parse_dotdotpwn(p)
    for p in args.ffuf:
        hits += parse_ffuf(p)
    for p in args.hits:
        hits += parse_hits_json(p)
    hits = dedupe(hits)

    if not hits:
        print("[-] no confirmed hits parsed", file=sys.stderr)

    print("[+] %d normalized hits (%d rce-capable)" % (
        len(hits), sum(1 for h in hits if h["rce"])))
    for h in hits:
        print("    %-22s %-8s %s param=%s" % (
            h["technique"], "RCE" if h["rce"] else "read", h["url"][:80], h["param"]))

    if args.merged:
        with open(args.merged, "w") as f:
            json.dump(hits, f, indent=2)
        print("[+] merged hits -> %s" % args.merged)
    if args.work_units:
        with open(args.work_units, "w") as f:
            json.dump(to_work_units(hits), f, indent=2)
        print("[+] work units -> %s (hand to the work-units skill / for_each:)"
              % args.work_units)
    if args.findings:
        with open(args.findings, "w") as f:
            json.dump(to_findings(hits), f, indent=2)
        print("[+] findings.report payloads -> %s "
              "(attach real HTTP exchanges, submit via finding-report skill)"
              % args.findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
