#!/usr/bin/env python3
"""oidc_discover.py - fetch and summarize OAuth/OIDC provider metadata.

Fetches /.well-known/openid-configuration and
/.well-known/oauth-authorization-server from an issuer, prints the
endpoints, grant/response types, PKCE support, and flags weak signals
(implicit enabled, no PKCE, plain PKCE, ROPC, open registration,
permissive scopes). Optionally emits:

  --units FILE   rupu work units: a JSON array of
                 {"id","title","targets","hints"} written atomically.
  --assets       ready-to-use assets.mark JSON lines (api:service /
                 api:endpoint at depth "mapped") on stdout.

Usage:
  python3 scripts/oidc_discover.py https://login.example.com \
      --units reports/oauth-oidc-units.json --assets
  python3 scripts/oidc_discover.py \
      https://login.example.com/realms/corp/.well-known/openid-configuration

Stdlib only. Exit 0 if at least one metadata document was retrieved.
"""

import argparse
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

WELL_KNOWN_PATHS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)

ENDPOINT_KEYS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "device_authorization_endpoint",
    "end_session_endpoint",
    "pushed_authorization_request_endpoint",
)

LIST_KEYS = (
    "grant_types_supported",
    "response_types_supported",
    "response_modes_supported",
    "scopes_supported",
    "code_challenge_methods_supported",
    "token_endpoint_auth_methods_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
)

MAX_TARGET_LEN = 512

# Endpoint metadata key -> (unit id, title, hint vocabulary). Fixed
# vocabulary only: unit titles/hints never contain server-supplied strings.
UNIT_DEFS = [
    ("authorization_endpoint", "oidc-redirect-uri",
     "redirect_uri validation tests",
     ["redirect-replacement", "subdomain", "at-confusion",
      "path-traversal", "open-redirect-chain", "localhost",
      "scheme-downgrade"]),
    ("authorization_endpoint", "oidc-state-csrf",
     "state / CSRF tests",
     ["state-dropped", "state-replayed", "code-injection"]),
    ("token_endpoint", "oidc-pkce",
     "PKCE enforcement tests",
     ["downgrade-plain", "verifier-omitted", "verifier-wrong",
      "challenge-omitted"]),
    ("token_endpoint", "oidc-code-token",
     "code replay / client auth / refresh rotation tests",
     ["code-replay", "client-secret-none", "refresh-no-rotation",
      "ropc-enabled"]),
    ("authorization_endpoint", "oidc-scope",
     "scope escalation tests",
     ["scope-widening-authorize", "scope-widening-token",
      "cross-client-audience"]),
    ("authorization_endpoint", "oidc-implicit",
     "implicit flow token leakage tests",
     ["response-type-token", "fragment-leak", "token-substitution"]),
    ("registration_endpoint", "oidc-dyn-reg",
     "dynamic client registration abuse tests",
     ["open-registration", "attacker-redirect-client", "metadata-ssrf"]),
    ("device_authorization_endpoint", "oidc-device",
     "device grant tests",
     ["user-code-bruteforce", "device-code-polling"]),
    ("jwks_uri", "oidc-jwt-handoff",
     "hand off tokens and jwks to jwt-attacks",
     ["jwt-structural", "jwks-review"]),
]


def fetch_json(url, insecure=False, timeout=15):
    """GET url, return (dict_or_None, note)."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(1 << 20).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, "HTTP %d" % e.code
    except Exception as e:  # URLError, ssl, timeout
        return None, str(e)[:120]
    try:
        data = json.loads(body)
    except ValueError:
        return None, "non-JSON response"
    if not isinstance(data, dict):
        return None, "unexpected JSON shape"
    return data, "ok"


def candidate_urls(target):
    """Return list of metadata URLs to try for the given input."""
    if ".well-known/" in target:
        return [target]
    base = target.rstrip("/")
    return [base + p for p in WELL_KNOWN_PATHS]


def flag_signals(meta):
    """Return list of (severity, message) weak signals."""
    out = []
    rts = meta.get("response_types_supported") or []
    grants = meta.get("grant_types_supported") or []
    pkce = meta.get("code_challenge_methods_supported")
    auth = meta.get("token_endpoint_auth_methods_supported") or []
    scopes = meta.get("scopes_supported") or []

    if any(rt in ("token", "id_token token", "code token",
                  "code id_token token") for rt in rts):
        out.append(("HIGH", "implicit/hybrid-with-token enabled "
                            "(response_types include a bare access token)"))
    if "implicit" in grants:
        out.append(("HIGH", "grant_types_supported includes 'implicit'"))
    if pkce is None:
        out.append(("MED", "code_challenge_methods_supported absent - "
                           "PKCE support/enforcement unknown, test it"))
    elif "plain" in pkce:
        out.append(("MED", "PKCE 'plain' method supported - downgrade target"))
    if "password" in grants:
        out.append(("HIGH", "ROPC (grant_type=password) enabled - "
                            "MFA bypass / credential-stuffing oracle"))
    if "none" in auth:
        out.append(("MED", "token_endpoint_auth 'none' supported - public "
                           "clients exist; PKCE must be enforced"))
    if "registration_endpoint" in meta:
        out.append(("MED", "dynamic client registration endpoint exposed - "
                           "try unauthenticated registration"))
    if "device_authorization_endpoint" in meta:
        out.append(("INFO", "device grant available - test user_code entropy"))
    risky = [s for s in scopes if isinstance(s, str) and (
        s == "*" or "admin" in s.lower() or s.lower().endswith((":write",
                                                                ".write",
                                                                "_write")))]
    if risky:
        out.append(("MED", "privileged scopes advertised: "
                    + ", ".join(sorted(risky)[:10])))
    if "offline_access" in scopes:
        out.append(("INFO", "offline_access (refresh tokens) requestable"))
    if "introspection_endpoint" not in meta and "revocation_endpoint" not in meta:
        out.append(("INFO", "no introspection/revocation endpoints advertised"))
    return out


def build_units(meta):
    units, seen = [], set()
    for key, uid, title, hints in UNIT_DEFS:
        ep = meta.get(key)
        if not isinstance(ep, str) or not ep or uid in seen:
            continue
        seen.add(uid)
        units.append({
            "id": uid,
            "title": title,
            "targets": [ep[:MAX_TARGET_LEN]],
            "hints": list(hints),
        })
    return units


def atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".units.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def asset_lines(meta):
    """Yield assets.mark JSON lines for the service and endpoints."""
    issuer = meta.get("issuer") or ""
    if issuer:
        host = urllib.parse.urlsplit(issuer).hostname or issuer
        base = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(issuer))
        yield json.dumps({"kind": "api:service",
                          "coordinates": [{"t": "url", "v": base}],
                          "depth": "mapped", "label": host})
    methods = {"authorization_endpoint": "GET", "jwks_uri": "GET",
               "userinfo_endpoint": "GET"}
    for key in ENDPOINT_KEYS:
        ep = meta.get(key)
        if key == "issuer" or not isinstance(ep, str) or not ep:
            continue
        path = urllib.parse.urlsplit(ep).path or "/"
        method = methods.get(key, "POST")
        route = "%s %s" % (method, path)
        yield json.dumps({"kind": "api:endpoint",
                          "coordinates": [{"t": "url", "v": ep},
                                          {"t": "http_route", "v": route}],
                          "depth": "mapped", "label": route})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("issuer", help="issuer base URL or full .well-known URL")
    ap.add_argument("--units", metavar="FILE",
                    help="write rupu work-unit JSON array to FILE (atomic)")
    ap.add_argument("--assets", action="store_true",
                    help="print assets.mark JSON lines")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    args = ap.parse_args()

    merged = {}
    got_any = False
    for url in candidate_urls(args.issuer):
        data, note = fetch_json(url, insecure=args.insecure)
        print("[*] %s -> %s" % (url, note))
        if data:
            got_any = True
            for k, v in data.items():
                merged.setdefault(k, v)
    if not got_any:
        print("[!] no metadata document retrieved", file=sys.stderr)
        return 1

    print("\n=== Endpoints ===")
    for k in ENDPOINT_KEYS:
        if k in merged:
            print("  %-42s %s" % (k, merged[k]))
    print("\n=== Capabilities ===")
    for k in LIST_KEYS:
        v = merged.get(k)
        if isinstance(v, list):
            print("  %-42s %s" % (k, ", ".join(str(x) for x in v)))

    print("\n=== Weak signals ===")
    signals = flag_signals(merged)
    if not signals:
        print("  (none from metadata alone - behavior still needs testing)")
    for sev, msg in signals:
        print("  [%s] %s" % (sev, msg))

    if args.assets:
        print("\n=== assets.mark payloads (one JSON object per line) ===")
        for line in asset_lines(merged):
            print(line)

    if args.units:
        units = build_units(merged)
        atomic_write_json(args.units, units)
        print("\n[+] wrote %d work units to %s" % (len(units), args.units))
        print("    fan out: for_each: \"{{ read_file('%s') }}\"" % args.units)
    return 0


if __name__ == "__main__":
    sys.exit(main())
