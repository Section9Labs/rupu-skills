#!/usr/bin/env python3
"""parse_cloudfox.py - split CloudFox JSON output into rupu work units + assets.

Walks a CloudFox output tree (any depth; finds json/ dirs or loose *.json files),
and emits:
  * a bare JSON array of work units  {"id","title","targets","hints"}
      - one per public endpoint        (endpoints, api-gateway)
      - one per bucket                 (buckets)
      - one per principal-with-privesc-lead
            (role-trusts rows; instances with an attached instance profile)
      - one per secret                 (secrets; env-vars whose key looks secret)
  * an assets object: endpoints, instances, buckets, principals, secrets

Usage:
  python3 scripts/parse_cloudfox.py --dir ./cloudfox \
      --out out/work-units.json --assets out/assets.json
"""
import argparse
import hashlib
import json
import os
import re
import sys

SECRET_KEY_RE = re.compile(
    r"(secret|token|passw|pwd|cred|api[_-]?key|private[_-]?key|auth)", re.I
)
ACCT_RE = re.compile(r"(\d{12})")


def norm(k):
    return re.sub(r"[^a-z0-9]", "", k.lower())


def pick(row, *names):
    low = {norm(k): v for k, v in row.items() if isinstance(k, str)}
    for n in names:
        v = low.get(norm(n))
        if v not in (None, "", "-", "N/A", "NoValue"):
            return v
    return None


def load_rows(path):
    """CloudFox json files are either a list of row dicts or a dict wrapping one."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return [r for r in v if isinstance(r, dict)]
    return []


def account_from_path(path):
    for part in reversed(path.split(os.sep)):
        m = ACCT_RE.search(part)
        if m:
            return m.group(1)
    return None


def unit_id(kind, target):
    h = hashlib.sha1(("%s|%s" % (kind, target)).encode()).hexdigest()[:12]
    return "cf-%s-%s" % (kind, h)


def find_json_files(root):
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn.endswith(".json"):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def module_name(path):
    stem = os.path.splitext(os.path.basename(path))[0].lower()
    return stem


def main():
    ap = argparse.ArgumentParser(
        description="Split CloudFox json/ output into rupu work units + assets."
    )
    ap.add_argument("--dir", required=True, help="CloudFox output root (e.g. ./cloudfox)")
    ap.add_argument("--out", default="out/work-units.json", help="work-units array path")
    ap.add_argument("--assets", default="out/assets.json", help="assets list path")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.exit("not a directory: %s" % args.dir)

    units, seen = [], set()
    assets = {"endpoints": [], "instances": [], "buckets": [],
              "principals": [], "secrets": []}

    def add_unit(kind, title, targets, hints):
        key = (kind, tuple(targets))
        if key in seen or not targets:
            return
        seen.add(key)
        units.append({"id": unit_id(kind, targets[0]), "title": title,
                      "targets": targets, "hints": hints})

    for path in find_json_files(args.dir):
        mod = module_name(path)
        rows = load_rows(path)
        if not rows:
            continue
        acct = account_from_path(path)

        for row in rows:
            region = pick(row, "Region", "AWS Region", "Location")
            base = {"module": mod, "account": pick(row, "Account", "Account ID") or acct}
            if region:
                base["region"] = region

            if mod in ("endpoints", "api-gateway", "apigateway"):
                ep = pick(row, "Endpoint", "Endpoint URL", "URL", "Invoke URL", "DNS Name")
                if not ep:
                    continue
                svc = pick(row, "Service", "Type")
                public = str(pick(row, "Public", "Is Public") or "").lower()
                assets["endpoints"].append({"endpoint": ep, "service": svc,
                                            "region": region, "public": public})
                hints = dict(base, kind="endpoint", service=svc or "",
                             public=public, next_skill="cloud-security")
                add_unit("endpoint", "Public endpoint %s (%s)" % (ep, svc or mod),
                         [ep], hints)

            elif mod == "buckets":
                name = pick(row, "Name", "Bucket", "Bucket Name")
                if not name:
                    continue
                assets["buckets"].append({"bucket": name, "region": region})
                add_unit("bucket", "S3 bucket %s" % name, [name],
                         dict(base, kind="bucket", next_skill="cloud-storage-exposure"))

            elif mod == "instances":
                iid = pick(row, "Instance ID", "ID", "InstanceID")
                pub = pick(row, "External IP", "Public IP", "PublicIP")
                priv = pick(row, "Internal IP", "Private IP", "PrivateIP")
                prof = pick(row, "Profile", "Instance Profile", "Role", "Instance Profile Arn")
                if not iid:
                    continue
                assets["instances"].append({"instance": iid, "public_ip": pub,
                                            "private_ip": priv, "profile": prof,
                                            "region": region})
                if prof:
                    assets["principals"].append({"principal": prof,
                                                 "source": "instance-profile",
                                                 "instance": iid})
                    add_unit("principal",
                             "Instance %s carries profile %s (IMDS cred theft)" % (iid, prof),
                             [iid, prof],
                             dict(base, kind="principal", lead="instance-profile",
                                  public_ip=pub or "", private_ip=priv or "",
                                  next_skill="metadata-ssrf-pivot"))

            elif mod in ("role-trusts", "roletrusts"):
                role = pick(row, "Role", "Role Arn", "Role Name")
                trusted = pick(row, "Trusted Principal", "Trusted Provider",
                               "Trusted Service", "Principal")
                if not role:
                    continue
                assets["principals"].append({"principal": role, "trusts": trusted,
                                             "source": "role-trusts"})
                lead = None
                tacct = ACCT_RE.search(str(trusted or ""))
                if trusted and "*" in str(trusted):
                    lead = "wildcard-trust"
                elif tacct and acct and tacct.group(1) != acct:
                    lead = "cross-account-trust"
                if lead:
                    add_unit("principal",
                             "Role %s trusts %s (%s)" % (role, trusted, lead),
                             [role],
                             dict(base, kind="principal", lead=lead,
                                  trusted_principal=str(trusted),
                                  next_skill="pmapper"))

            elif mod in ("permissions", "principals"):
                p = pick(row, "Principal", "Principal Arn", "Arn", "Name")
                if p:
                    assets["principals"].append({"principal": p, "source": mod})

            elif mod == "secrets":
                name = pick(row, "Name", "Secret Name", "Parameter Name")
                svc = pick(row, "Service", "Type") or "secretsmanager/ssm"
                if not name:
                    continue
                assets["secrets"].append({"secret": name, "service": svc,
                                          "region": region})
                add_unit("secret", "Secret %s (%s)" % (name, svc), [name],
                         dict(base, kind="secret", service=svc,
                              next_skill="trufflehog"))

            elif mod in ("env-vars", "envvars"):
                key = pick(row, "Key", "Name", "Environment Variable", "Var")
                res = pick(row, "Function", "Resource", "Resource Arn", "Task Definition",
                           "Service")
                if not key or not SECRET_KEY_RE.search(str(key)):
                    continue
                tgt = "%s:%s" % (res or "env", key)
                assets["secrets"].append({"secret": tgt, "service": "env-var",
                                          "region": region})
                add_unit("secret", "Suspicious env var %s on %s" % (key, res or "?"),
                         [tgt],
                         dict(base, kind="secret", service="env-var",
                              next_skill="trufflehog"))

    for k in assets:  # dedupe assets, stable order
        seen_a, out = set(), []
        for a in assets[k]:
            j = json.dumps(a, sort_keys=True)
            if j not in seen_a:
                seen_a.add(j)
                out.append(a)
        assets[k] = out

    for p in (args.out, args.assets):
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(units, f, indent=2)   # bare array, nothing else
    with open(args.assets, "w") as f:
        json.dump(assets, f, indent=2)

    print("wrote %d work units -> %s" % (len(units), args.out))
    print("assets: " + ", ".join("%s=%d" % (k, len(v)) for k, v in assets.items())
          + " -> %s" % args.assets)


if __name__ == "__main__":
    main()
