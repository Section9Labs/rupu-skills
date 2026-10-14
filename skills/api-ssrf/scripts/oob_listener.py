#!/usr/bin/env python3
"""oob_listener.py - minimal stdlib out-of-band callback listener for blind SSRF.

Runs an HTTP server that logs every inbound request (method, path, headers,
source IP) and, optionally, a tiny UDP DNS responder that logs every query
name and answers with a configurable A record. Use when no interactsh/
Collaborator is available. Point SSRF payloads at
http://<token>.<your-domain>/ (NS delegated here) or http://<ip>:<port>/<token>.

Each event is appended as one JSON line to the --out file (atomic appends),
so a probe token like "p07" is confirmed by grepping the log:
    grep p07 reports/oob-hits.jsonl

Usage:
  python3 scripts/oob_listener.py --http-port 80 --out reports/oob-hits.jsonl
  python3 scripts/oob_listener.py --http-port 8080 --dns-port 53 \
      --a-record 203.0.113.10 --out reports/oob-hits.jsonl
"""

import argparse
import json
import os
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_LOCK = threading.Lock()
LOG_PATH = "reports/oob-hits.jsonl"


def log_event(event):
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = json.dumps(event)
    with LOG_LOCK:
        os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    print("[+] %s" % line)


class HTTPHits(BaseHTTPRequestHandler):
    server_version = "nginx"  # unremarkable banner

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)) if length else b""
        log_event({
            "proto": "http",
            "src": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body[:2048].decode("utf-8", "replace"),
        })
        payload = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle
    do_OPTIONS = do_PATCH = _handle

    def log_message(self, fmt, *a):  # quiet default access log
        pass


def parse_qname(data):
    """Extract the query name from a DNS packet; return (name, end_offset)."""
    i = 12
    labels = []
    while i < len(data):
        n = data[i]
        if n == 0:
            i += 1
            break
        if n > 63:  # compression pointer or junk; bail
            i += 2
            break
        labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels), i


def dns_response(data, qname_end, a_record):
    """Build a minimal DNS answer (A record) or empty NOERROR."""
    tid = data[0:2]
    question = data[12:qname_end + 4]  # name + qtype + qclass
    qtype = data[qname_end:qname_end + 2]
    flags = b"\x81\x80"  # standard response, RA
    if a_record and qtype == b"\x00\x01":  # A query
        header = tid + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" +
                  b"\x00\x00\x00\x3c" + b"\x00\x04" +
                  socket.inet_aton(a_record))
        return header + question + answer
    header = tid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    return header + question


class DNSHandler(socketserver.BaseRequestHandler):
    a_record = None

    def handle(self):
        data, sock = self.request
        if len(data) < 14:
            return
        try:
            qname, end = parse_qname(data)
        except Exception:
            return
        qtype = data[end:end + 2]
        tname = {b"\x00\x01": "A", b"\x00\x1c": "AAAA",
                 b"\x00\x10": "TXT", b"\x00\x0f": "MX"}.get(qtype, "other")
        log_event({"proto": "dns", "src": self.client_address[0],
                   "qname": qname, "qtype": tname})
        try:
            sock.sendto(dns_response(data, end, self.a_record),
                        self.client_address)
        except Exception:
            pass


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


def main():
    global LOG_PATH
    ap = argparse.ArgumentParser(description="OOB callback listener")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--dns-port", type=int, default=0,
                    help="UDP DNS port (0 = disabled; 53 needs privileges)")
    ap.add_argument("--a-record", default=None,
                    help="IP to answer A queries with (usually this host)")
    ap.add_argument("--out", default="reports/oob-hits.jsonl")
    args = ap.parse_args()
    LOG_PATH = args.out

    threads = []
    httpd = ThreadingHTTPServer((args.bind, args.http_port), HTTPHits)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    threads.append(t)
    print("[*] HTTP listener on %s:%d -> %s"
          % (args.bind, args.http_port, args.out))

    if args.dns_port:
        DNSHandler.a_record = args.a_record
        dnsd = ThreadingUDPServer((args.bind, args.dns_port), DNSHandler)
        t = threading.Thread(target=dnsd.serve_forever, daemon=True)
        t.start()
        threads.append(t)
        print("[*] DNS listener on %s:%d (A -> %s)"
              % (args.bind, args.dns_port, args.a_record or "NOERROR only"))

    print("[*] waiting for callbacks; Ctrl-C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] stopped; hits logged to %s" % args.out)


if __name__ == "__main__":
    main()
