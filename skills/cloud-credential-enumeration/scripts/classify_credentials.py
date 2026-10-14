#!/usr/bin/env python3
"""classify_credentials.py — recognize and classify cloud credential material.

Reads a blob (stdin), a file, or a directory tree of text and classifies any
credential material found: AWS AKIA/ASIA keys + secrets + session tokens, GCP
ya29. tokens and service_account JSON key files, JWTs (decoding claims to spot
Azure ARM/Graph tokens), Azure SAS tokens/URLs, Azure service-principal tuples,
and known credential cache files (~/.aws/credentials, azureProfile.json, ADC).

Emits:
  - a bare JSON ARRAY of work units ({"id","title","targets","hints"}) suitable
    for rupu for_each: fan-out (default out/work-units.json)
  - an assets list of principals/credentials (--assets)

Stdlib only. Example:
  python3 scripts/classify_credentials.py --input loot/ -o out/work-units.json --assets out/assets.json
"""
import argparse
import base64
import configparser
import json
import os
import re
import sys

AKIA_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
SECRET_RE = re.compile(
    r"(?:aws_secret_access_key|secret_access_key|SecretAccessKey|AWS_SECRET_ACCESS_KEY)"
    r"[\"'\s:=]+([A-Za-z0-9/+=]{40})\b")
SESSION_RE = re.compile(
    r"(?:aws_session_token|SessionToken|Token|AWS_SESSION_TOKEN)"
    r"[\"'\s:=]+([A-Za-z0-9/+=]{100,})")
YA29_RE = re.compile(r"\b(ya29\.[A-Za-z0-9_\-\.]{20,})")
GCP_REFRESH_RE = re.compile(r"\b(1//[A-Za-z0-9_\-]{20,})")
JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b")
SAS_RE = re.compile(r"[?&](sv=[^\s\"'&]+(?:&[a-z]{2,4}=[^\s\"'&]+)*&sig=[^\s\"'&]+)")
GUID_RE = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
AZ_SP_RE = re.compile(
    r"(?:appId|client_id|AZURE_CLIENT_ID)[\"'\s:=]+(" + GUID_RE + ")", re.I)
AZ_TENANT_RE = re.compile(
    r"(?:tenant(?:_id|Id)?|AZURE_TENANT_ID)[\"'\s:=]+(" + GUID_RE + ")", re.I)
AZ_SECRET_RE = re.compile(
    r"(?:password|client_secret|AZURE_CLIENT_SECRET)[\"'\s:=]+([A-Za-z0-9~._\-]{20,})", re.I)

TEXT_EXT_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".tar", ".pdf",
                 ".so", ".dylib", ".exe", ".dll", ".pyc", ".sqlite", ".db"}
MAX_FILE = 10 * 1024 * 1024


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt(token):
    try:
        parts = token.split(".")
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def iter_sources(path):
    """Yield (source_name, text) tuples."""
    if path == "-":
        yield "<stdin>", sys.stdin.read()
        return
    if os.path.isfile(path):
        yield from read_one(path)
        return
    for root, _dirs, files in os.walk(path):
        for fn in files:
            fp = os.path.join(root, fn)
            yield from read_one(fp)


def read_one(fp):
    if os.path.splitext(fp)[1].lower() in TEXT_EXT_SKIP:
        return
    try:
        if os.path.getsize(fp) > MAX_FILE:
            return
        with open(fp, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8", errors="ignore")
        if text.strip():
            yield fp, text
    except OSError:
        return


class Collector:
    def __init__(self):
        self.units = []
        self.assets = []
        self.seen = set()
        self.counter = 0

    def add(self, provider, ctype, target, title, hints, source):
        key = (provider, ctype, target)
        if key in self.seen:
            return
        self.seen.add(key)
        self.counter += 1
        h = {"provider": provider, "type": ctype, "source": source}
        h.update({k: str(v) for k, v in hints.items()})
        self.units.append({
            "id": "%s-%s-%04d" % (provider, ctype.replace("_", "-"), self.counter),
            "title": title,
            "targets": [target],
            "hints": h,
        })

    def asset(self, atype, aid, **hints):
        self.assets.append({"type": atype, "id": aid,
                            "hints": {k: str(v) for k, v in hints.items()}})


def classify_text(src, text, col):
    # --- AWS keys ---
    secrets = SECRET_RE.findall(text)
    sessions = SESSION_RE.findall(text)
    for key in AKIA_RE.findall(text):
        ctype = "access_key_long_term" if key.startswith("AKIA") else "access_key_temporary"
        col.add("aws", ctype, key,
                "AWS %s key %s" % ("long-term" if key.startswith("AKIA") else "temporary (STS)", key),
                {"has_secret": bool(secrets), "has_session_token": bool(sessions)}, src)
        col.asset("secret", key, provider="aws", kind=ctype, source=src)

    # --- AWS profile files ---
    base = os.path.basename(src)
    if base in ("credentials", "config") and (".aws" in src or "aws" in src.lower()):
        cp = configparser.ConfigParser()
        try:
            cp.read_string(text)
            for sect in cp.sections():
                prof = sect.replace("profile ", "")
                info = dict(cp[sect])
                if "role_arn" in info:
                    col.add("aws", "profile_role", info["role_arn"],
                            "AWS profile %s chains to role %s" % (prof, info["role_arn"]),
                            {"profile": prof, "source_profile": info.get("source_profile", "")}, src)
                if "sso_start_url" in info:
                    col.add("aws", "sso_profile", prof,
                            "AWS SSO profile %s (%s)" % (prof, info.get("sso_start_url")),
                            {"sso_account_id": info.get("sso_account_id", "")}, src)
        except configparser.Error:
            pass

    # --- GCP tokens ---
    for tok in YA29_RE.findall(text):
        col.add("gcp", "access_token", tok[:24] + "...",
                "GCP OAuth access token (ya29.)", {"token": tok}, src)
    for tok in GCP_REFRESH_RE.findall(text):
        col.add("gcp", "refresh_token", tok[:16] + "...",
                "GCP OAuth refresh token (1//)", {"token": tok}, src)

    # --- GCP service account JSON ---
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        if obj.get("type") == "service_account" and "client_email" in obj:
            col.add("gcp", "service_account_key", obj["client_email"],
                    "GCP service-account key for %s" % obj["client_email"],
                    {"project_id": obj.get("project_id", ""),
                     "private_key_id": obj.get("private_key_id", "")}, src)
            col.asset("principal", obj["client_email"], provider="gcp",
                      kind="service-account", project=obj.get("project_id", ""))
        if obj.get("type") == "authorized_user" and "refresh_token" in obj:
            col.add("gcp", "adc_user_refresh", obj.get("client_id", "adc-user"),
                    "GCP ADC authorized_user refresh token",
                    {"token": obj["refresh_token"][:16] + "..."}, src)
        # Azure SP JSON from `az ad sp create-for-rbac`
        if "appId" in obj and ("password" in obj or "tenant" in obj):
            col.add("azure", "service_principal", obj["appId"],
                    "Azure service principal %s (tenant %s)" % (obj["appId"], obj.get("tenant", "?")),
                    {"tenant": obj.get("tenant", ""), "has_secret": "password" in obj}, src)
            col.asset("principal", obj["appId"], provider="azure", kind="service-principal",
                      tenant=obj.get("tenant", ""))
        # azureProfile.json
        if "subscriptions" in obj and isinstance(obj["subscriptions"], list):
            for sub in obj["subscriptions"]:
                if isinstance(sub, dict) and "id" in sub and "tenantId" in sub:
                    col.asset("cloud-account", "azure-subscription:" + sub["id"],
                              provider="azure", tenant=sub["tenantId"],
                              name=sub.get("name", ""), source=src)

    # --- JWTs ---
    for tok in JWT_RE.findall(text):
        header, payload = decode_jwt(tok)
        if not payload:
            continue
        aud = payload.get("aud", "")
        aud_s = aud if isinstance(aud, str) else ",".join(aud)
        provider = "azure" if ("microsoft" in aud_s or "azure" in aud_s or
                               "windows.net" in aud_s or "tid" in payload) else "generic"
        hints = {"aud": aud_s, "exp": payload.get("exp", ""),
                 "token": tok[:40] + "..."}
        for claim in ("tid", "oid", "upn", "appid", "scp", "iss", "email"):
            if claim in payload:
                hints[claim] = payload[claim]
        if "roles" in payload:
            hints["roles"] = ",".join(map(str, payload["roles"]))
        subject = payload.get("oid") or payload.get("sub") or payload.get("email") or tok[:24]
        col.add(provider, "jwt", str(subject),
                "%s JWT (aud=%s) for %s" % (provider, aud_s or "?", subject), hints, src)
        if payload.get("oid"):
            col.asset("principal", payload["oid"], provider="azure",
                      kind="oid", tenant=payload.get("tid", ""), upn=payload.get("upn", ""))

    # --- Azure SAS ---
    for sas in SAS_RE.findall(text):
        params = dict(p.split("=", 1) for p in sas.split("&") if "=" in p)
        col.add("azure", "sas_token", "sig:" + params.get("sig", "")[:12],
                "Azure SAS token (sp=%s se=%s)" % (params.get("sp", "?"), params.get("se", "?")),
                {"sas": sas, "sp": params.get("sp", ""), "se": params.get("se", ""),
                 "sr": params.get("sr", params.get("srt", ""))}, src)

    # --- Azure SP tuple scattered in text (env/CI style) ---
    if not isinstance(obj, dict) or "appId" not in (obj or {}):
        app = AZ_SP_RE.search(text)
        ten = AZ_TENANT_RE.search(text)
        sec = AZ_SECRET_RE.search(text)
        if app and ten:
            col.add("azure", "service_principal", app.group(1),
                    "Azure service principal %s (tenant %s)" % (app.group(1), ten.group(1)),
                    {"tenant": ten.group(1), "has_secret": bool(sec)}, src)


def main():
    ap = argparse.ArgumentParser(description="Classify cloud credential material "
                                 "found in a blob, file, or directory tree.")
    ap.add_argument("--input", "-i", default="-",
                    help="file or directory to scan ('-' = stdin, default)")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units JSON array output (default out/work-units.json)")
    ap.add_argument("--assets", default=None,
                    help="optional assets JSON output (principals/accounts)")
    args = ap.parse_args()

    col = Collector()
    for src, text in iter_sources(args.input):
        classify_text(src, text, col)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(col.units, fh, indent=2)
    print("[+] %d work units -> %s" % (len(col.units), args.output))

    if args.assets:
        os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
        with open(args.assets, "w") as fh:
            json.dump(col.assets, fh, indent=2)
        print("[+] %d assets -> %s" % (len(col.assets), args.assets))

    for u in col.units:
        print("    %-28s %s" % (u["id"], u["title"]))


if __name__ == "__main__":
    main()
