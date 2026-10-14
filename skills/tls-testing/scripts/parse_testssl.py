#!/usr/bin/env python3
"""parse_testssl.py - normalize testssl.sh JSON (flat or pretty) and sslscan XML
into rupu-ingestible outputs.

Emits:
  -o merged.json        normalized findings  [{id, host, port, severity, ...}]
  --work-units u.json   JSON ARRAY of work units (one per affected host:port)
  --findings f.json     findings.report payloads (scope endpoint, WSTG/CWE tagged)

Usage:
  python3 scripts/parse_testssl.py ts.json [ts2.json ...] \
      [--sslscan out.xml ...] [--min-severity LOW] \
      [-o merged.json] [--work-units units.json] [--findings findings.json]

Python 3 standard library only.
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET

# testssl severity -> rupu severity. WARN/DEBUG/FATAL are engine noise: drop.
SEV_MAP = {
    "OK": "info",
    "INFO": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CERT_ID_RE = re.compile(r"^(cert_|OCSP_|certificate)", re.I)
CIPHER_LINE_RE = re.compile(r"^cipher-[a-z0-9_]+_x[0-9a-f]+$", re.I)

WEAK_CIPHER_RE = re.compile(
    r"(RC4|DES-CBC3|3DES|DES-CBC(?!3)|NULL|EXP-|EXPORT|ADH|AECDH|IDEA|RC2)", re.I
)


def norm(fid, host, port, severity, finding, cve="", cwe="", source="testssl"):
    sev = SEV_MAP.get(str(severity).upper())
    if sev is None:
        return None
    return {
        "id": str(fid),
        "host": str(host),
        "port": str(port),
        "severity": sev,
        "finding": str(finding).strip(),
        "cve": str(cve or "").strip(),
        "cwe": str(cwe or "").strip(),
        "source": source,
    }


# ---------------------------------------------------------------- testssl ---

def split_host(ipfield, fallback=""):
    # flat JSON "ip" is "host/1.2.3.4"
    s = str(ipfield or "")
    if "/" in s:
        h = s.split("/", 1)[0]
        return h if h else s.split("/", 1)[1]
    return s or fallback


def load_testssl(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            sys.stderr.write("[!] %s: not valid JSON (%s)\n" % (path, exc))
            return []
    out = []
    if isinstance(data, list):  # --jsonfile flat format
        for e in data:
            if not isinstance(e, dict) or "id" not in e:
                continue
            r = norm(e.get("id"), split_host(e.get("ip")), e.get("port", "443"),
                     e.get("severity", ""), e.get("finding", ""),
                     e.get("cve", ""), e.get("cwe", ""))
            if r:
                out.append(r)
    elif isinstance(data, dict):  # --json-pretty structured format
        for target in data.get("scanResult", []):
            host = target.get("targetHost") or split_host(target.get("ip"))
            port = target.get("port", "443")
            for key, section in target.items():
                if not isinstance(section, list):
                    continue
                for e in section:
                    if not isinstance(e, dict) or "id" not in e:
                        continue
                    r = norm(e.get("id"), host, port, e.get("severity", ""),
                             e.get("finding", ""), e.get("cve", ""),
                             e.get("cwe", ""))
                    if r:
                        out.append(r)
    return out


# ---------------------------------------------------------------- sslscan ---

def load_sslscan(path):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        sys.stderr.write("[!] %s: XML parse error (%s)\n" % (path, exc))
        return []
    out = []
    for st in root.iter("ssltest"):
        host = st.get("host", "")
        port = st.get("port", "443")

        def add(fid, sev, finding, cve="", cwe=""):
            r = norm(fid, host, port, sev, finding, cve, cwe, source="sslscan")
            if r:
                out.append(r)

        legacy_proto = False
        for p in st.iter("protocol"):
            if p.get("enabled") != "1":
                continue
            ptype, ver = p.get("type", ""), p.get("version", "")
            if ptype == "ssl" and ver == "2":
                add("SSLv2", "CRITICAL", "SSLv2 enabled (DROWN surface)",
                    "CVE-2016-0800", "CWE-310")
                legacy_proto = True
            elif ptype == "ssl" and ver == "3":
                add("SSLv3", "HIGH", "SSLv3 enabled (POODLE)",
                    "CVE-2014-3566", "CWE-757")
                legacy_proto = True
            elif ptype == "tls" and ver == "1.0":
                add("TLS1", "LOW", "TLS 1.0 enabled (deprecated, RFC 8996)",
                    "", "CWE-326")
                legacy_proto = True
            elif ptype == "tls" and ver == "1.1":
                add("TLS1_1", "LOW", "TLS 1.1 enabled (deprecated, RFC 8996)",
                    "", "CWE-326")
                legacy_proto = True

        weak = []
        for c in st.iter("cipher"):
            if c.get("status") not in ("accepted", "preferred"):
                continue
            name = c.get("cipher", "")
            try:
                bits = int(c.get("bits", "0"))
            except ValueError:
                bits = 0
            try:
                dhebits = int(c.get("dhebits", "0"))
            except ValueError:
                dhebits = 0
            tags = []
            if WEAK_CIPHER_RE.search(name) or bits < 112:
                tags.append("weak")
            if 0 < dhebits <= 1024:
                tags.append("dhe%d" % dhebits)
            if tags:
                weak.append("%s %s %dbits %s"
                            % (c.get("sslversion", "?"), name, bits,
                               ",".join(tags)))
        if weak:
            sev = "HIGH" if any(
                re.search(r"(RC4|NULL|EXP|ADH|AECDH)", w) for w in weak
            ) else "MEDIUM"
            add("weak_ciphers", sev,
                "weak cipher suites accepted: " + "; ".join(weak[:20]),
                "", "CWE-326")

        for hb in st.iter("heartbleed"):
            if hb.get("vulnerable") == "1":
                add("heartbleed", "CRITICAL",
                    "heartbleed VULNERABLE on %s" % hb.get("sslversion", "?"),
                    "CVE-2014-0160", "CWE-119")
        for rn in st.iter("renegotiation"):
            if rn.get("supported") == "1" and rn.get("secure") == "0":
                add("secure_renego", "MEDIUM",
                    "insecure (non-RFC5746) renegotiation supported",
                    "CVE-2009-3555", "CWE-310")
        for cp in st.iter("compression"):
            if cp.get("supported") == "1":
                add("CRIME_TLS", "HIGH", "TLS compression enabled (CRIME)",
                    "CVE-2012-4929", "CWE-310")
        for fb in st.iter("fallback"):
            if fb.get("supported") == "0" and legacy_proto:
                add("fallback_SCSV", "LOW",
                    "no TLS_FALLBACK_SCSV support while legacy protocols "
                    "are enabled (downgrade aid)", "", "CWE-310")

        for cert in st.iter("certificate"):
            def text(tag):
                el = cert.find(tag)
                return (el.text or "").strip() if el is not None else ""
            if text("expired").lower() == "true":
                add("cert_expirationStatus", "HIGH",
                    "certificate expired (notAfter=%s)"
                    % text("not-valid-after"), "", "CWE-295")
            if text("self-signed").lower() == "true":
                add("cert_trust", "MEDIUM", "self-signed certificate",
                    "", "CWE-295")
            sig = text("signature-algorithm")
            if re.search(r"(sha1|md5)", sig, re.I):
                add("cert_signatureAlgorithm", "MEDIUM",
                    "weak certificate signature algorithm: %s" % sig,
                    "", "CWE-326")
            pk = cert.find("pk")
            if pk is not None and pk.get("type", "").upper() == "RSA":
                try:
                    if int(pk.get("bits", "0")) < 2048:
                        add("cert_keySize", "MEDIUM",
                            "RSA key < 2048 bits (%s)" % pk.get("bits"),
                            "", "CWE-326")
                except ValueError:
                    pass
    return out


# ------------------------------------------------------- merge / collapse ---

def collapse(records):
    """Dedupe by (host, port, id); fold per-cipher testssl lines
    (id like cipher-tls1_2_x9f) into one weak_ciphers_offered record."""
    merged = {}
    cipher_bucket = {}
    for r in records:
        if CIPHER_LINE_RE.match(r["id"]):
            key = (r["host"], r["port"])
            b = cipher_bucket.setdefault(
                key, {"lines": [], "sev": "low", "cwe": r["cwe"]})
            b["lines"].append(r["finding"])
            if RANK[r["severity"]] > RANK[b["sev"]]:
                b["sev"] = r["severity"]
            continue
        key = (r["host"], r["port"], r["id"])
        if key in merged:
            m = merged[key]
            if RANK[r["severity"]] > RANK[m["severity"]]:
                m["severity"] = r["severity"]
            if r["finding"] and r["finding"] not in m["finding"]:
                m["finding"] = (m["finding"] + " | " + r["finding"])[:2000]
            for f in ("cve", "cwe"):
                if r[f] and not m[f]:
                    m[f] = r[f]
            if r["source"] not in m["source"]:
                m["source"] += "+" + r["source"]
        else:
            merged[key] = dict(r)
    for (host, port), b in cipher_bucket.items():
        merged[(host, port, "weak_ciphers_offered")] = {
            "id": "weak_ciphers_offered", "host": host, "port": port,
            "severity": b["sev"],
            "finding": "weak cipher suites offered: "
                       + "; ".join(b["lines"][:25]),
            "cve": "", "cwe": b["cwe"] or "CWE-326", "source": "testssl",
        }
    return sorted(merged.values(),
                  key=lambda r: (r["host"], r["port"],
                                 -RANK[r["severity"]], r["id"]))


# ------------------------------------------------------------ rupu output ---

def build_work_units(records):
    groups = {}
    for r in records:
        groups.setdefault((r["host"], r["port"]), []).append(r)
    units = []
    for (host, port), recs in sorted(groups.items()):
        top = max(recs, key=lambda r: RANK[r["severity"]])["severity"]
        ids = sorted({r["id"] for r in recs})
        units.append({
            "id": "tls-%s-%s" % (host, port),
            "title": "TLS issues on %s:%s (max severity: %s)"
                     % (host, port, top),
            "targets": ["https://%s:%s/" % (host, port)],
            "hints": {
                "host": host,
                "port": port,
                "max_severity": top,
                "issue_ids": ",".join(ids)[:1000],
                "issue_count": str(len(recs)),
                "next": "confirm with openssl s_client, then findings.report",
            },
        })
    return units


def build_findings(records):
    payloads = []
    for r in records:
        url = "https://%s:%s/" % (r["host"], r["port"])
        cls = ["OWASP WSTG-CRYP-01"]
        if r["cwe"]:
            cls.append(r["cwe"])
        elif CERT_ID_RE.match(r["id"]):
            cls.append("CWE-295")
        else:
            cls.append("CWE-326")
        if r["cve"]:
            cls.append(r["cve"])
        rationale = ("%s id=%s on %s:%s: %s."
                     % (r["source"], r["id"], r["host"], r["port"],
                        r["finding"]))
        if r["cve"]:
            rationale += " Associated: %s." % r["cve"]
        payloads.append({
            "title": "TLS: %s on %s:%s" % (r["id"], r["host"], r["port"]),
            "scope": "endpoint",
            "target_ref": url,
            "severity": r["severity"],
            "classification": "; ".join(cls),
            "evidence": {
                "rationale": rationale,
                "exchange": "REPLACE: paste the openssl s_client "
                            "confirmation transcript for %s against %s "
                            "(negotiated Protocol/Cipher lines)."
                            % (r["id"], url),
            },
        })
    return payloads


# ------------------------------------------------------------------- main ---

def main():
    ap = argparse.ArgumentParser(
        description="Normalize testssl.sh JSON + sslscan XML into rupu "
                    "merged findings, work units, and findings.report "
                    "payloads.")
    ap.add_argument("testssl_json", nargs="*",
                    help="testssl.sh --jsonfile or --json-pretty output(s)")
    ap.add_argument("--sslscan", action="append", default=[],
                    metavar="XML", help="sslscan --xml= output (repeatable)")
    ap.add_argument("--min-severity", default="LOW",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
                             "info", "low", "medium", "high", "critical"],
                    help="minimum severity to keep (default LOW)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="merged normalized findings JSON")
    ap.add_argument("--work-units", metavar="FILE",
                    help="work-units JSON array (for rupu for_each/dispatch)")
    ap.add_argument("--findings", metavar="FILE",
                    help="findings.report payloads JSON array")
    args = ap.parse_args()

    if not args.testssl_json and not args.sslscan:
        ap.error("give at least one testssl JSON file or --sslscan XML")

    records = []
    for path in args.testssl_json:
        records.extend(load_testssl(path))
    for path in args.sslscan:
        records.extend(load_sslscan(path))

    floor = RANK[SEV_MAP.get(args.min_severity.upper(),
                             args.min_severity.lower())]
    records = [r for r in records if RANK[r["severity"]] >= floor]
    records = collapse(records)

    sys.stderr.write("[*] %d finding(s) at severity >= %s across %d "
                     "host:port target(s)\n"
                     % (len(records), args.min_severity.upper(),
                        len({(r["host"], r["port"]) for r in records})))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)
        sys.stderr.write("[*] merged -> %s\n" % args.output)
    if args.work_units:
        with open(args.work_units, "w", encoding="utf-8") as fh:
            json.dump(build_work_units(records), fh, indent=2)
        sys.stderr.write("[*] work units -> %s\n" % args.work_units)
    if args.findings:
        with open(args.findings, "w", encoding="utf-8") as fh:
            json.dump(build_findings(records), fh, indent=2)
        sys.stderr.write("[*] findings.report payloads -> %s\n"
                         % args.findings)
    if not (args.output or args.work_units or args.findings):
        json.dump(records, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
