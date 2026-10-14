#!/usr/bin/env python3
"""race_runner.py - fire K tightly synchronized HTTP requests to test for
race conditions (WSTG-BUSL-04 / CWE-367). Python 3 standard library only.

Technique: all K connections are opened and TLS-handshaked up front
(optionally warmed with a keep-alive GET /), each request is sent except its
final byte, all threads block on a barrier, then the last bytes are released
together ("last-byte sync"). The per-response (status, length, body-hash)
distribution makes a race win (unexpected duplicate successes) visible.

Examples:
  python3 scripts/race_runner.py --url https://example.com/api/coupon/redeem \
      --method POST -H 'Content-Type: application/json' \
      -H 'Cookie: session=abc' --data '{"code":"SAVE10"}' \
      --concurrency 20 --warm --success-regex '"applied":true' \
      --output race-result.json --finding-out finding.json

  python3 scripts/race_runner.py --request-file redeem.req --force-ssl \
      --concurrency 30 --sync last-byte --repeat 3

Body/path templating: the literal {SLOT} is replaced per-thread with the slot
index (or the matching line of --slot-values FILE).

On >=2 successes in a round, --finding-out writes a draft findings.report
payload (scope endpoint, WSTG-BUSL-04 / CWE-367, HTTP exchange in evidence).
Verify the duplicated effect server-side and set severity by impact before
submitting via the finding-report skill.  -- vulture (bronze-dune)
"""

import argparse
import hashlib
import json
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit


def parse_raw_request(text):
    """Parse a raw HTTP request file -> (method, path, headers list, body)."""
    text = text.replace("\r\n", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    lines = head.split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("bad request line: %r" % lines[0])
    method, path = parts[0], parts[1]
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("bad header line: %r" % line)
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return method, path, headers, body


def build_request(method, path, headers, body, host):
    """Build full HTTP/1.1 request bytes with corrected framing headers."""
    hdrs = [(n, v) for (n, v) in headers
            if n.lower() not in ("content-length", "connection")]
    if not any(n.lower() == "host" for n, _ in hdrs):
        hdrs.insert(0, ("Host", host))
    body_bytes = body.encode() if isinstance(body, str) else (body or b"")
    if body_bytes or method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        hdrs.append(("Content-Length", str(len(body_bytes))))
    hdrs.append(("Connection", "close"))
    head = "%s %s HTTP/1.1\r\n" % (method.upper(), path)
    head += "".join("%s: %s\r\n" % (n, v) for n, v in hdrs)
    head += "\r\n"
    return head.encode() + body_bytes


def read_response(reader):
    """Read one HTTP response from a buffered binary reader."""
    status_line = reader.readline()
    if not status_line:
        raise ConnectionError("empty response")
    parts = status_line.decode("latin-1").strip().split(None, 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers = {}
    while True:
        line = reader.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        name, _, value = line.decode("latin-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    body = b""
    if headers.get("transfer-encoding", "").lower().startswith("chunked"):
        while True:
            size_line = reader.readline()
            if not size_line:
                break
            try:
                size = int(size_line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                reader.readline()
                break
            body += reader.read(size)
            reader.readline()  # trailing CRLF
    elif "content-length" in headers:
        body = reader.read(int(headers["content-length"]))
    else:
        body = reader.read()
    return status, headers, body


def open_connection(host, port, tls, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def sync_wait(barrier, timeout):
    """Barrier wait that degrades gracefully if a peer died pre-barrier."""
    try:
        barrier.wait(timeout=timeout)
    except threading.BrokenBarrierError:
        pass  # a peer failed/aborted; send anyway (degraded sync)


def worker(slot, req_bytes, host, port, tls, args, barrier, t0_holder, results):
    rec = {"slot": slot, "status": None, "length": None,
           "body_sha256_12": None, "send_ms": None, "recv_ms": None,
           "body_preview": None, "error": None}
    sock = None
    try:
        sock = open_connection(host, port, tls, args.timeout)
        reader = sock.makefile("rb")
        if args.warm:
            warm = ("GET / HTTP/1.1\r\nHost: %s\r\n"
                    "Connection: keep-alive\r\n\r\n" % host).encode()
            sock.sendall(warm)
            try:
                read_response(reader)
            except Exception:
                pass  # warm response is best-effort
        if args.sync == "last-byte":
            sock.sendall(req_bytes[:-1])
            sync_wait(barrier, args.timeout)
            if t0_holder[0] is None:
                t0_holder[0] = time.perf_counter()
            sock.sendall(req_bytes[-1:])
        else:  # barrier mode: send whole request after the barrier
            sync_wait(barrier, args.timeout)
            if t0_holder[0] is None:
                t0_holder[0] = time.perf_counter()
            sock.sendall(req_bytes)
        rec["send_ms"] = round((time.perf_counter() - t0_holder[0]) * 1000, 3)
        status, _hdrs, body = read_response(reader)
        rec["recv_ms"] = round((time.perf_counter() - t0_holder[0]) * 1000, 3)
        rec["status"] = status
        rec["length"] = len(body)
        rec["body_sha256_12"] = hashlib.sha256(body).hexdigest()[:12]
        rec["body_preview"] = body[:300].decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - record every failure mode
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
        barrier.abort()  # don't let peers hang waiting for this slot
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    results[slot] = rec


def classify(rec, args):
    """True when a response counts as 'success' per the operator criteria."""
    if rec["error"] is not None or rec["status"] is None:
        return False
    if args.success_status:
        if rec["status"] not in args.success_status:
            return False
    elif not 200 <= rec["status"] < 300:
        return False
    if args.success_regex:
        return re.search(args.success_regex, rec["body_preview"] or "") is not None
    return True


def build_finding(args, target_url, req_text, round_result):
    successes = [r for r in round_result["responses"] if r.get("_success")]
    example = successes[0] if successes else {}
    rationale = (
        "The endpoint performs a check-then-act state transition without "
        "atomicity. %d synchronized identical requests (%s sync, "
        "concurrency %d) yielded %d success responses where exactly one "
        "should have succeeded (WSTG-BUSL-04 limit overrun / TOCTOU). "
        "VERIFY the duplicated effect server-side (balance/order/usage "
        "count) and append that evidence before submitting."
        % (args.concurrency, args.sync, args.concurrency, len(successes)))
    exchange = (req_text + "\n\n--- success response (x%d, status %s, "
                "sha256/12 %s) ---\n%s"
                % (len(successes), example.get("status"),
                   example.get("body_sha256_12"), example.get("body_preview")))
    return {
        "title": "Race condition (limit overrun) in %s" % target_url,
        "scope": "endpoint",
        "target_ref": target_url,
        "severity": "high",
        "classification": {"wstg": "WSTG-BUSL-04", "cwe": "CWE-367"},
        "evidence": {
            "rationale": rationale,
            "http_exchange": exchange,
            "reproduction": "python3 scripts/race_runner.py " + " ".join(
                a if " " not in a else "'%s'" % a for a in sys.argv[1:]),
            "distribution": round_result["distribution"],
        },
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    tgt = ap.add_argument_group("target")
    tgt.add_argument("--url", help="target URL (scheme://host[:port]/path)")
    tgt.add_argument("--request-file", action="append", default=[],
                     help="raw HTTP request file; repeatable (round-robin "
                          "across slots for multi-endpoint races)")
    tgt.add_argument("--force-ssl", action="store_true",
                     help="use TLS for --request-file targets")
    tgt.add_argument("--port", type=int, help="override target port")
    req = ap.add_argument_group("request (with --url)")
    req.add_argument("--method", default="GET")
    req.add_argument("-H", "--header", action="append", default=[],
                     metavar="'Name: value'")
    req.add_argument("--data", help="request body ({SLOT} templated)")
    req.add_argument("--data-file", help="read request body from file")
    run = ap.add_argument_group("execution")
    run.add_argument("--concurrency", type=int, default=20, metavar="K")
    run.add_argument("--sync", choices=["last-byte", "barrier"],
                     default="last-byte")
    run.add_argument("--warm", action="store_true",
                     help="send keep-alive GET / per connection before burst")
    run.add_argument("--repeat", type=int, default=1, metavar="ROUNDS")
    run.add_argument("--timeout", type=float, default=10.0)
    run.add_argument("--slot-values", help="file of per-slot {SLOT} values")
    det = ap.add_argument_group("detection / output")
    det.add_argument("--success-status",
                     help="comma list, e.g. 200,201 (default: any 2xx)")
    det.add_argument("--success-regex",
                     help="body regex that must also match for success")
    det.add_argument("--output", help="write full JSON summary here")
    det.add_argument("--finding-out",
                     help="write draft findings.report payload on a race win")
    args = ap.parse_args()

    if args.success_status:
        args.success_status = {int(s) for s in args.success_status.split(",")}
    slot_values = None
    if args.slot_values:
        with open(args.slot_values) as fh:
            slot_values = [ln.rstrip("\n") for ln in fh if ln.strip()]

    # Build the per-slot request specs: (method, path, headers, body, host,
    # port, tls, display_url)
    specs = []
    if args.url:
        u = urlsplit(args.url)
        tls = u.scheme == "https"
        host = u.hostname
        port = args.port or u.port or (443 if tls else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        headers = []
        for h in args.header:
            n, _, v = h.partition(":")
            headers.append((n.strip(), v.strip()))
        body = args.data or ""
        if args.data_file:
            with open(args.data_file) as fh:
                body = fh.read()
        specs.append((args.method, path, headers, body, host, port, tls,
                      args.url))
    for rf in args.request_file:
        with open(rf) as fh:
            method, path, headers, body = parse_raw_request(fh.read())
        host = next((v for n, v in headers if n.lower() == "host"), None)
        if host is None:
            ap.error("request file %s has no Host header" % rf)
        if ":" in host:
            host, _, hp = host.partition(":")
            port = args.port or int(hp)
        else:
            port = args.port or (443 if args.force_ssl else 80)
        tls = args.force_ssl or port == 443
        url = "%s://%s%s" % ("https" if tls else "http", host,
                             path.split("?")[0])
        specs.append((method, path, headers, body, host, port, tls, url))
    if not specs:
        ap.error("need --url or --request-file")

    summary = {"targets": [s[7] for s in specs], "concurrency": args.concurrency,
               "sync": args.sync, "warm": args.warm, "rounds": [],
               "race_suspected": False}
    first_req_text = None
    win_round = None

    for rnd in range(args.repeat):
        results = [None] * args.concurrency
        barrier = threading.Barrier(args.concurrency)
        t0_holder = [None]
        threads = []
        for slot in range(args.concurrency):
            method, path, headers, body, host, port, tls, _url = \
                specs[slot % len(specs)]
            sv = (slot_values[slot % len(slot_values)] if slot_values
                  else str(slot))
            s_path = path.replace("{SLOT}", sv)
            s_body = (body or "").replace("{SLOT}", sv)
            req_bytes = build_request(method, s_path, headers, s_body, host)
            if first_req_text is None:
                first_req_text = req_bytes.decode("latin-1")
            t = threading.Thread(
                target=worker,
                args=(slot, req_bytes, host, port, tls, args, barrier,
                      t0_holder, results))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        dist = {}
        successes = 0
        for rec in results:
            ok = classify(rec, args)
            rec["_success"] = ok
            successes += ok
            key = (rec["status"], rec["length"], rec["body_sha256_12"],
                   rec["error"])
            dist[key] = dist.get(key, 0) + 1
        distribution = [
            {"status": k[0], "length": k[1], "body_sha256_12": k[2],
             "error": k[3], "count": v}
            for k, v in sorted(dist.items(), key=lambda kv: -kv[1])]
        round_result = {"round": rnd, "responses": results,
                        "distribution": distribution,
                        "successes": successes,
                        "race_suspected": successes >= 2}
        summary["rounds"].append(round_result)
        if successes >= 2:
            summary["race_suspected"] = True
            if win_round is None:
                win_round = round_result
        recv = [r["recv_ms"] for r in results if r["recv_ms"] is not None]
        spread = (max(recv) - min(recv)) if recv else None
        print("[round %d] successes=%d/%d  distribution=%s  recv-spread=%sms"
              % (rnd, successes, args.concurrency,
                 ["%sx%s/%s" % (d["count"], d["status"], d["length"])
                  for d in distribution],
                 spread), file=sys.stderr)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(summary, fh, indent=2)
        print("[+] summary -> %s" % args.output, file=sys.stderr)
    if args.finding_out and win_round is not None:
        finding = build_finding(args, specs[0][7], first_req_text, win_round)
        with open(args.finding_out, "w") as fh:
            json.dump(finding, fh, indent=2)
        print("[+] RACE SUSPECTED - draft findings.report payload -> %s "
              "(verify server-side state, then submit via the "
              "finding-report skill)" % args.finding_out, file=sys.stderr)
    if not args.output:
        json.dump(summary, sys.stdout, indent=2)
        print()
    sys.exit(0 if not summary["race_suspected"] else 10)


if __name__ == "__main__":
    main()
