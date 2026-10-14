#!/usr/bin/env python3
"""entra_recon.py — unauthenticated Microsoft Entra ID (Azure AD) tenant recon.

Pure stdlib HTTP against public login endpoints. No credentials needed.

  * OpenID configuration  -> tenant GUID + region
      https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
  * GetUserRealm (getuserrealm.srf) -> namespace type (Managed/Federated),
      federation brand + AuthURL
  * GetCredentialType -> per-username existence oracle (--user / --userfile)
  * Autodiscover GetFederationInformation (SOAP) -> all tenant domains
      (--federation)

Writes full recon facts to a JSON file and a rupu-ingestible bare JSON array of
work units ({"id","title","targets","hints"}) to the --units file.

Examples:
  python3 scripts/entra_recon.py example.com
  python3 scripts/entra_recon.py example.com --federation \
      --userfile users.txt -o out/entra-recon.json --units out/recon-units.json
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

LOGIN = "https://login.microsoftonline.com"
AUTODISCOVER = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

IFEXISTS = {
    0: "exists",
    1: "does-not-exist",
    2: "throttled",
    4: "error",
    5: "exists-different-idp",
    6: "exists-both",
}


def http(url, data=None, headers=None, timeout=15):
    """GET/POST, return (status, body-str). Never raises on HTTP errors."""
    req = urllib.request.Request(url, data=data, headers=headers or {})
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # DNS, timeout, TLS
        return 0, "ERROR: %s" % e


def openid_config(domain):
    status, body = http("%s/%s/.well-known/openid-configuration" % (LOGIN, domain))
    out = {"status": status, "exists": False}
    if status != 200:
        return out
    try:
        cfg = json.loads(body)
    except ValueError:
        return out
    out["exists"] = True
    m = re.search(
        r"login\.microsoftonline\.com/([0-9a-f-]{36})", cfg.get("token_endpoint", "")
    ) or re.search(r"sts\.windows\.net/([0-9a-f-]{36})", cfg.get("issuer", ""))
    if m:
        out["tenant_id"] = m.group(1)
    out["tenant_region_scope"] = cfg.get("tenant_region_scope")
    out["token_endpoint"] = cfg.get("token_endpoint")
    out["issuer"] = cfg.get("issuer")
    out["cloud_instance_name"] = cfg.get("cloud_instance_name")
    return out


def user_realm(domain):
    login = "user@%s" % domain
    status, body = http(
        "%s/getuserrealm.srf?login=%s&json=1" % (LOGIN, urllib.parse.quote(login))
    )
    out = {"status": status}
    if status != 200:
        return out
    try:
        realm = json.loads(body)
    except ValueError:
        return out
    out["namespace_type"] = realm.get("NameSpaceType")  # Managed/Federated/Unknown
    out["federation_brand"] = realm.get("FederationBrandName")
    out["auth_url"] = realm.get("AuthURL")  # federation IdP endpoint
    out["cloud_instance"] = realm.get("CloudInstanceName")
    out["domain_name"] = realm.get("DomainName")
    return out


def check_user(username):
    body = json.dumps({"username": username, "isOtherIdpSupported": True}).encode()
    status, resp = http(
        "%s/common/GetCredentialType" % LOGIN,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    out = {"username": username, "status": status}
    if status != 200:
        return out
    try:
        data = json.loads(resp)
    except ValueError:
        return out
    ife = data.get("IfExistsResult")
    out["if_exists_result"] = ife
    out["verdict"] = IFEXISTS.get(ife, "unknown")
    out["throttled"] = bool(data.get("ThrottleStatus"))
    out["desktop_sso_enabled"] = bool(
        (data.get("EstsProperties") or {}).get("DesktopSsoEnabled")
    )
    return out


SOAP_TMPL = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">%s</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestType xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request><Domain>%s</Domain></Request>
    </GetFederationInformationRequestType>
  </soap:Body>
</soap:Envelope>"""


def federation_domains(domain):
    body = (SOAP_TMPL % (AUTODISCOVER, domain)).encode()
    status, resp = http(
        AUTODISCOVER,
        data=body,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
            'Autodiscover/GetFederationInformation"',
            "User-Agent": "AutodiscoverClient",
        },
        timeout=30,
    )
    out = {"status": status, "domains": []}
    if status == 200:
        out["domains"] = sorted(set(re.findall(r"<Domain>([^<]+)</Domain>", resp)))
        onms = [d for d in out["domains"] if d.lower().endswith(".onmicrosoft.com")]
        if onms:
            out["onmicrosoft_domain"] = onms[0]
            out["tenant_name"] = onms[0].split(".")[0]
    return out


def build_units(domain, facts):
    units = []
    oidc, realm = facts.get("openid", {}), facts.get("userrealm", {})
    tenant_id = oidc.get("tenant_id")
    targets = [domain] + ([tenant_id] if tenant_id else [])
    units.append(
        {
            "id": "tenant-%s" % domain,
            "title": "Entra tenant for %s (%s)"
            % (domain, realm.get("namespace_type") or "unknown"),
            "targets": targets,
            "hints": {
                "edge": "tenant-recon",
                "role": "tenant",
                "reason": "openid-configuration resolved" if oidc.get("exists")
                else "domain not found in any tenant",
                "tenant_id": tenant_id or "",
                "namespace_type": realm.get("namespace_type") or "",
                "federation_brand": realm.get("federation_brand") or "",
                "federation_auth_url": realm.get("auth_url") or "",
                "tenant_region": oidc.get("tenant_region_scope") or "",
            },
        }
    )
    fed = facts.get("federation") or {}
    if fed.get("domains"):
        units.append(
            {
                "id": "tenant-domains-%s" % domain,
                "title": "All domains registered to the tenant of %s" % domain,
                "targets": fed["domains"],
                "hints": {
                    "edge": "federated-domain-set",
                    "role": "tenant",
                    "reason": "autodiscover GetFederationInformation; recon each "
                    "domain and run subdomain/storage enumeration",
                    "onmicrosoft_domain": fed.get("onmicrosoft_domain", ""),
                },
            }
        )
    for u in facts.get("users", []):
        if u.get("verdict", "").startswith("exists"):
            units.append(
                {
                    "id": "user-%s" % u["username"],
                    "title": "Validated Entra user %s" % u["username"],
                    "targets": [u["username"]],
                    "hints": {
                        "edge": "valid-user",
                        "role": "user",
                        "reason": "GetCredentialType IfExistsResult=%s (%s); "
                        "candidate for spray / device-code phish"
                        % (u.get("if_exists_result"), u["verdict"]),
                        "desktop_sso": str(u.get("desktop_sso_enabled", False)),
                    },
                }
            )
    return units


def main():
    ap = argparse.ArgumentParser(
        description="Unauthenticated Entra ID tenant recon (stdlib only).",
        epilog="Writes recon facts JSON plus a bare-array work-units file for rupu.",
    )
    ap.add_argument("domain", help="target domain, e.g. example.com")
    ap.add_argument("--user", action="append", default=[],
                    help="username/UPN to validate via GetCredentialType (repeatable); "
                         "bare names get @<domain> appended")
    ap.add_argument("--userfile", help="file with one username per line")
    ap.add_argument("--federation", action="store_true",
                    help="pull the full tenant domain list via autodiscover SOAP")
    ap.add_argument("-o", "--output", default="out/entra-recon.json",
                    help="recon facts JSON (default: %(default)s)")
    ap.add_argument("--units", default="out/recon-units.json",
                    help="work-units bare JSON array (default: %(default)s)")
    args = ap.parse_args()

    users = list(args.user)
    if args.userfile:
        with open(args.userfile) as fh:
            users += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    users = [u if "@" in u else "%s@%s" % (u, args.domain) for u in users]

    facts = {"domain": args.domain}
    print("[*] openid-configuration ...", file=sys.stderr)
    facts["openid"] = openid_config(args.domain)
    print("    tenant_id=%s region=%s"
          % (facts["openid"].get("tenant_id"),
             facts["openid"].get("tenant_region_scope")), file=sys.stderr)
    print("[*] getuserrealm.srf ...", file=sys.stderr)
    facts["userrealm"] = user_realm(args.domain)
    print("    namespace=%s auth_url=%s"
          % (facts["userrealm"].get("namespace_type"),
             facts["userrealm"].get("auth_url")), file=sys.stderr)
    if args.federation:
        print("[*] autodiscover GetFederationInformation ...", file=sys.stderr)
        facts["federation"] = federation_domains(args.domain)
        print("    %d domains" % len(facts["federation"]["domains"]), file=sys.stderr)
    if users:
        print("[*] GetCredentialType on %d users ..." % len(users), file=sys.stderr)
        facts["users"] = [check_user(u) for u in users]
        for u in facts["users"]:
            print("    %-40s %s" % (u["username"], u.get("verdict", "?")),
                  file=sys.stderr)

    for path in (args.output, args.units):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(facts, fh, indent=2)
    units = build_units(args.domain, facts)
    with open(args.units, "w") as fh:
        json.dump(units, fh, indent=2)
    print("[+] facts -> %s ; %d work units -> %s"
          % (args.output, len(units), args.units), file=sys.stderr)


if __name__ == "__main__":
    main()
