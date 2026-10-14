#!/usr/bin/env python3
"""jwt_decode.py - decode a JWT with zero dependencies and flag risky conditions.

Usage:
  python3 scripts/jwt_decode.py <JWT>
  python3 scripts/jwt_decode.py --file response.txt [--url https://api.example.com/v1/me]
  python3 scripts/jwt_decode.py <JWT> --units reports/jwt-attacks-units.json

Prints a JSON report (header, payload, timing, flags) to stdout. With --units,
also writes a rupu-ingestible work-unit array (atomically) mapping each flag to
a jwt_tool attack. Titles/hints come from a fixed vocabulary; untrusted input
strings only ever appear inside "targets", length-capped.
"""
import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time

TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")
TARGET_CAP = 4096
YEAR = 365 * 24 * 3600

SENSITIVE_CLAIMS = (
    "role", "roles", "admin", "isadmin", "is_admin", "scope", "scp",
    "groups", "permissions", "privileges", "sub", "user_id", "uid",
    "email", "username", "tenant_id", "org_id", "acl",
)

# flag -> (unit title, fixed hint list)  -- fixed vocabulary only
ATTACK_MAP = {
    "alg-none-accepted-header": ("jwt alg none forgery",
                                 ["jwt_tool -X a", "jwt_tool -X n", "replay-against-endpoint"]),
    "alg-hmac": ("jwt hmac secret crack",
                 ["jwt_tool -C -d jwt.secrets.list", "hashcat -m 16500",
                  "forge: -S hs256 -p SECRET", "replay-against-endpoint"]),
    "alg-asymmetric": ("jwt key confusion rs256-hs256",
                       ["fetch /.well-known/jwks.json", "jwt_tool -X k -pk public.pem",
                        "rsa_sign2n jwt_forgery.py two-tokens", "replay-against-endpoint"]),
    "kid-present": ("jwt kid header injection",
                    ["jwt_tool -I -hc kid -hv ../../dev/null -S hs256 -p ''",
                     "kid sqli union-select known key", "replay-against-endpoint"]),
    "jku-or-x5u-present": ("jwt jwks url spoof",
                           ["jwt_tool -X s -ju ATTACKER_JWKS_URL", "host jwks file",
                            "replay-against-endpoint"]),
    "embedded-jwk-or-x5c": ("jwt inline jwks injection",
                            ["jwt_tool -X i", "extract pubkey for key confusion",
                             "replay-against-endpoint"]),
    "no-exp": ("jwt missing expiry",
               ["eternal token - report after acceptance check", "replay-against-endpoint"]),
    "long-lived": ("jwt excessive lifetime",
                   ["lifetime over one year", "replay-against-endpoint"]),
    "expired": ("jwt expired token acceptance test",
                ["replay expired token against endpoint", "replay-against-endpoint"]),
    "always": ("jwt live playbook scan",
               ["jwt_tool -M pb -t URL -rh 'Authorization: Bearer jwt_tool'",
                "jwt_tool -M at", "scripts/run_jwt_tool.py"]),
}


def b64url_decode(seg):
    seg = seg.strip()
    pad = -len(seg) % 4
    return base64.urlsafe_b64decode(seg + ("=" * pad))


def decode_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a 3-part JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def analyze(header, payload, signature):
    flags = []
    now = int(time.time())
    alg = str(header.get("alg", "")).strip()
    alg_l = alg.lower()

    if alg_l == "none" or not signature:
        flags.append("alg-none-accepted-header")
    if alg_l.startswith("hs"):
        flags.append("alg-hmac")
    if alg_l.startswith(("rs", "es", "ps")):
        flags.append("alg-asymmetric")
    if "kid" in header:
        flags.append("kid-present")
    if "jku" in header or "x5u" in header:
        flags.append("jku-or-x5u-present")
    if "jwk" in header or "x5c" in header:
        flags.append("embedded-jwk-or-x5c")

    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        flags.append("no-exp")
    else:
        try:
            exp = int(exp)
            if exp < now:
                flags.append("expired")
            base = int(iat) if iat is not None else now
            if exp - base > YEAR:
                flags.append("long-lived")
        except (TypeError, ValueError):
            flags.append("no-exp")

    sensitive = sorted(
        k for k in payload
        if k.lower() in SENSITIVE_CLAIMS
    )
    if sensitive:
        flags.append("sensitive-claims")
    return flags, sensitive


def build_units(token, flags, url):
    units = []
    targets = []
    if url:
        targets.append(url[:TARGET_CAP])
    targets.append(token[:TARGET_CAP])
    keys = ["always"] + [f for f in flags if f in ATTACK_MAP]
    for i, key in enumerate(keys, 1):
        title, hints = ATTACK_MAP[key]
        units.append({
            "id": "jwt-%s-%d" % (key, i),
            "title": title,
            "targets": list(targets),
            "hints": list(hints),
        })
    return units


def write_atomic(path, data):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".jwtunits-", dir=d)
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
    ap = argparse.ArgumentParser(description="dependency-free JWT decoder + risk triage")
    ap.add_argument("token", nargs="?", help="the JWT")
    ap.add_argument("--file", help="scan a file (e.g. saved response) for JWTs")
    ap.add_argument("--url", help="protected endpoint URL to embed in work units")
    ap.add_argument("--units", metavar="PATH",
                    help="write work-unit JSON array here (e.g. reports/jwt-attacks-units.json)")
    args = ap.parse_args()

    tokens = []
    if args.token:
        tokens.append(args.token.strip().strip('"').removeprefix("Bearer ").strip())
    if args.file:
        with open(args.file, "r", errors="replace") as f:
            tokens.extend(TOKEN_RE.findall(f.read()))
    if not tokens:
        print("no JWT supplied or found", file=sys.stderr)
        return 2

    reports, all_units = [], []
    for token in dict.fromkeys(tokens):  # dedupe, keep order
        try:
            header, payload, signature = decode_token(token)
        except (ValueError, json.JSONDecodeError) as e:
            reports.append({"token_prefix": token[:40], "error": str(e)})
            continue
        flags, sensitive = analyze(header, payload, signature)
        exp = payload.get("exp")
        reports.append({
            "token_prefix": token[:40] + "...",
            "alg": header.get("alg"),
            "kid": header.get("kid"),
            "jku": header.get("jku"),
            "x5u": header.get("x5u"),
            "header": header,
            "payload": payload,
            "signature_present": bool(signature),
            "exp": exp,
            "exp_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(exp)))
            if isinstance(exp, (int, float)) or (isinstance(exp, str) and exp.isdigit())
            else None,
            "iat": payload.get("iat"),
            "sensitive_claims": sensitive,
            "flags": flags,
        })
        all_units.extend(build_units(token, flags, args.url))

    print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))

    if args.units:
        write_atomic(args.units, all_units)
        print("wrote %d work units -> %s" % (len(all_units), args.units), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
