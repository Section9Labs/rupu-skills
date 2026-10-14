#!/usr/bin/env python3
"""analyze_jwt.py — decode and triage a JWT for auth-session-testing.

Decodes header/payload/signature, reports alg + claims + expiry, flags likely
attack paths (alg:none acceptance, crackable HMAC, key-confusion material,
kid/jku/x5u abuse, missing exp, authz claims to tamper), and emits:

  * a human summary (stdout)
  * --json FILE        full machine-readable report
  * --work-units FILE  rupu work-units JSON array (first char '['), one unit per
                       attack worth attempting — hand to the `work-units` skill
  * --findings FILE    findings.report-shaped payloads for issues provable from
                       the token alone (e.g. missing exp, sensitive data in
                       payload) — finish via the `finding-report` skill

Usage:
  python3 scripts/analyze_jwt.py <token> [--target URL] [--json out.json]
                                 [--work-units wu.json] [--findings f.json]
  echo "$TOKEN" | python3 scripts/analyze_jwt.py - --target https://example.com/api/me

vulture / sand-atlas
"""

import argparse
import base64
import binascii
import json
import re
import sys
import time

HMAC_ALGS = {"HS256", "HS384", "HS512"}
RSA_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
EC_ALGS = {"ES256", "ES384", "ES512", "EdDSA"}
AUTHZ_CLAIM_RE = re.compile(
    r"role|admin|scope|group|perm|priv|is_|staff|superuser|level|acl", re.I
)
SENSITIVE_CLAIM_RE = re.compile(r"pass|secret|ssn|credit|card|key", re.I)


def b64url_decode(seg: str) -> bytes:
    seg = seg.strip()
    pad = -len(seg) % 4
    return base64.urlsafe_b64decode(seg + "=" * pad)


def decode_token(token: str):
    parts = token.strip().strip('"').split(".")
    if len(parts) not in (2, 3):
        raise ValueError(
            "not a JWS compact token (expected 2 or 3 dot-separated parts, got %d)"
            % len(parts)
        )
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("base64/JSON decode failed: %s" % exc)
    sig = parts[2] if len(parts) == 3 else ""
    return header, payload, sig


def fmt_epoch(val):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(val)))
    except (ValueError, TypeError, OverflowError):
        return "unparseable(%r)" % (val,)


def analyze(token: str, target: str):
    header, payload, sig = decode_token(token)
    alg = str(header.get("alg", "<missing>"))
    now = int(time.time())
    flags = []       # [{id, severity_hint, note}]
    work_units = []  # rupu units
    findings = []    # findings.report payloads provable from the token alone
    host = "unknown-host"
    if target:
        m = re.match(r"https?://([^/]+)", target)
        if m:
            host = m.group(1)
    targets = [target] if target else []

    def unit(attack, title, hints):
        base = {"mechanism": "jwt", "attack": attack, "token": token, "alg": alg}
        base.update(hints)
        work_units.append(
            {
                "id": "auth-jwt-%s-%s" % (attack, host),
                "title": title,
                "targets": targets,
                "hints": {k: str(v) for k, v in base.items()},
            }
        )

    # --- algorithm triage -------------------------------------------------
    if alg.lower() == "none" or sig == "":
        flags.append(
            {
                "id": "alg-none-in-use",
                "severity_hint": "critical",
                "note": "Token is UNSIGNED (alg=%s, empty signature). The issuer "
                "accepts/emits unsigned tokens — forge claims directly." % alg,
            }
        )
        unit("alg-none-confirmed", "Forge claims on unsigned JWT (alg=none)", {})
    else:
        # alg:none is always worth one cheap probe against the verifier
        unit(
            "alg-none",
            "Test alg:none acceptance (jwt_tool -X a) against the verifier",
            {"command": "jwt_tool <token> -X a -t <oracle> -rh 'Authorization: Bearer TOKEN'"},
        )

    if alg in HMAC_ALGS:
        flags.append(
            {
                "id": "hmac-crackable",
                "severity_hint": "high",
                "note": "%s is symmetric — the secret verifies AND signs. "
                "Dictionary-crack it (jwt_tool -C -d wordlist / hashcat -m 16500)." % alg,
            }
        )
        unit(
            "hmac-crack",
            "Crack HMAC secret of %s JWT" % alg,
            {"command": "jwt_tool <token> -C -d rockyou.txt"},
        )
    elif alg in RSA_ALGS:
        flags.append(
            {
                "id": "rsa-key-confusion-candidate",
                "severity_hint": "high",
                "note": "%s is asymmetric — test RS->HS key confusion with the "
                "public key (jwks.json / TLS cert): jwt_tool -X k -pk pub.pem." % alg,
            }
        )
        unit(
            "key-confusion",
            "RS256->HS256 key confusion using the public key",
            {"command": "jwt_tool <token> -X k -pk pub.pem -t <oracle>"},
        )
    elif alg in EC_ALGS:
        flags.append(
            {
                "id": "ec-alg",
                "severity_hint": "info",
                "note": "%s (EC) — check CVE-2022-21449 'psychic signatures' "
                "(Java 15-18: r=s=0 signature accepted) if the backend is Java." % alg,
            }
        )
        unit("psychic-signature", "Test ECDSA null signature (CVE-2022-21449)", {})

    # --- header claims ----------------------------------------------------
    for hclaim, attack, note in (
        ("kid", "kid-injection",
         "kid header present (%r) — try path traversal (../../dev/null + empty "
         "HMAC key), SQLi, and command injection in kid."),
        ("jku", "jku-ssrf",
         "jku header present (%r) — point it at your own JWKS (jwt_tool -X s "
         "-ju ...); SSRF + signature bypass."),
        ("x5u", "x5u-ssrf",
         "x5u header present (%r) — host your own cert chain; same class as jku."),
    ):
        if hclaim in header:
            flags.append(
                {"id": attack, "severity_hint": "high",
                 "note": note % (header[hclaim],)}
            )
            unit(attack, "Abuse %s header of JWT" % hclaim,
                 {hclaim: header[hclaim]})
    if "jwk" in header:
        flags.append(
            {"id": "embedded-jwk", "severity_hint": "high",
             "note": "Embedded jwk header — try self-signed key injection "
             "(jwt_tool -X i)."}
        )
        unit("embedded-jwk", "Inject self-signed inline JWKS (jwt_tool -X i)", {})

    # --- payload claims ---------------------------------------------------
    exp = payload.get("exp")
    if exp is None:
        flags.append(
            {"id": "missing-exp", "severity_hint": "medium",
             "note": "No exp claim — token never expires (CWE-613)."}
        )
        findings.append(
            {
                "title": "JWT issued without expiry (exp claim missing)",
                "scope": "endpoint",
                "target_ref": target or "SET-TARGET-URL",
                "severity": "medium",
                "classification": {"owasp": "WSTG-SESS-07", "cwe": "CWE-613"},
                "evidence": {
                    "rationale": "The session JWT carries no exp claim, so a "
                    "stolen token is valid indefinitely and cannot age out. "
                    "Evidence: decoded payload below (attach the HTTP exchange "
                    "in which the token was issued).",
                    "decoded_payload": payload,
                    "http_exchange": "ATTACH-ISSUING-EXCHANGE",
                },
            }
        )
    else:
        try:
            iexp = int(exp)
            if iexp < now:
                flags.append(
                    {"id": "expired", "severity_hint": "info",
                     "note": "Token expired at %s — test whether the verifier "
                     "still accepts it (expiry-check bypass)." % fmt_epoch(iexp)}
                )
                unit("expired-accepted", "Replay expired JWT against verifier", {})
            elif iexp - now > 60 * 60 * 24 * 30:
                flags.append(
                    {"id": "long-lived", "severity_hint": "low",
                     "note": "exp is %s (>30 days out) — excessive lifetime "
                     "(CWE-613)." % fmt_epoch(iexp)}
                )
        except (ValueError, TypeError):
            flags.append({"id": "exp-unparseable", "severity_hint": "low",
                          "note": "exp claim is not an integer: %r" % (exp,)})

    authz = sorted(k for k in payload if AUTHZ_CLAIM_RE.search(k))
    if authz:
        flags.append(
            {"id": "authz-claims", "severity_hint": "info",
             "note": "Authorization-bearing claims to tamper once a signing "
             "primitive exists: %s" % ", ".join(authz)}
        )
        unit("claim-tamper", "Tamper authz claims (%s)" % ",".join(authz),
             {"claims": ",".join(authz)})

    sensitive = sorted(k for k in payload if SENSITIVE_CLAIM_RE.search(k))
    if sensitive:
        flags.append(
            {"id": "sensitive-claims", "severity_hint": "medium",
             "note": "Possibly sensitive data in a client-readable payload: %s"
             % ", ".join(sensitive)}
        )

    report = {
        "token": token,
        "header": header,
        "payload": payload,
        "signature_b64url": sig,
        "alg": alg,
        "alg_class": ("none/unsigned" if alg.lower() == "none" or not sig
                      else "HMAC (symmetric, crackable)" if alg in HMAC_ALGS
                      else "RSA (asymmetric)" if alg in RSA_ALGS
                      else "EC/EdDSA (asymmetric)" if alg in EC_ALGS
                      else "unknown"),
        "exp_human": fmt_epoch(exp) if exp is not None else None,
        "iat_human": fmt_epoch(payload["iat"]) if "iat" in payload else None,
        "nbf_human": fmt_epoch(payload["nbf"]) if "nbf" in payload else None,
        "flags": flags,
        "work_units": work_units,
        "finding_payloads": findings,
    }
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("token", help="JWT, or '-' to read from stdin")
    ap.add_argument("--target", default="",
                    help="verifier/oracle URL (goes into work-unit targets and "
                         "finding target_ref)")
    ap.add_argument("--json", help="write full report JSON here")
    ap.add_argument("--work-units", help="write rupu work-units array here")
    ap.add_argument("--findings", help="write findings.report payload array here")
    args = ap.parse_args()

    token = sys.stdin.read().strip() if args.token == "-" else args.token
    try:
        report = analyze(token, args.target)
    except ValueError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        sys.exit(2)

    print("=== JWT analysis ===")
    print("alg       : %s  (%s)" % (report["alg"], report["alg_class"]))
    print("header    : %s" % json.dumps(report["header"]))
    print("payload   : %s" % json.dumps(report["payload"]))
    if report["exp_human"]:
        print("exp       : %s" % report["exp_human"])
    if report["iat_human"]:
        print("iat       : %s" % report["iat_human"])
    print("--- flags (%d) ---" % len(report["flags"]))
    for f in report["flags"]:
        print("[%s] %s: %s" % (f["severity_hint"].upper(), f["id"], f["note"]))
    print("--- next: %d work unit(s), %d token-only finding payload(s) ---"
          % (len(report["work_units"]), len(report["finding_payloads"])))

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print("[+] report -> %s" % args.json)
    if args.work_units:
        with open(args.work_units, "w") as fh:
            json.dump(report["work_units"], fh, indent=2)
        print("[+] work units -> %s (feed to the work-units skill / for_each)"
              % args.work_units)
    if args.findings:
        with open(args.findings, "w") as fh:
            json.dump(report["finding_payloads"], fh, indent=2)
        print("[+] finding payloads -> %s (finish via the finding-report skill)"
              % args.findings)


if __name__ == "__main__":
    main()
