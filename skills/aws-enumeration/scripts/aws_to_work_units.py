#!/usr/bin/env python3
"""aws_to_work_units.py - turn aws_enum.py's inventory.json into rupu work units.

Emits a BARE JSON ARRAY of {"id","title","targets","hints"} — one unit per:
  * public resource: EC2 public IP, internet-facing ELB, API Gateway, CloudFront
    distribution, publicly accessible RDS, 0.0.0.0/0 security group
  * principal with a lead: role with cross-account/wildcard trust, instance
    carrying an instance profile
  * secret: SecretsManager secret, SSM parameter, Lambda env var (suspicious keys)
  * logging gap: no CloudTrail trail in any swept region
Plus an assets file: account, principals, instances, buckets, endpoints, secrets.

Usage:
  python3 scripts/aws_to_work_units.py --inventory out/awsenum/inventory.json \
      --out out/work-units.json --assets out/assets.json
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse

SECRET_KEY_RE = re.compile(
    r"(secret|token|passw|pwd|cred|api[_-]?key|private[_-]?key|auth)", re.I)
ACCT_RE = re.compile(r"\d{12}")


def uid(kind, target):
    return "aws-%s-%s" % (kind, hashlib.sha1(
        ("%s|%s" % (kind, target)).encode()).hexdigest()[:12])


def per_region(results, svc, op):
    """Yield (region, payload) pairs for a service/operation."""
    for region, payload in results.get(svc, {}).get(op, {}).items():
        if payload:
            yield region, payload


def trust_principals(doc):
    """Extract AWS principals from an AssumeRolePolicyDocument (dict or encoded str)."""
    if isinstance(doc, str):
        try:
            doc = json.loads(urllib.parse.unquote(doc))
        except (ValueError, TypeError):
            return []
    if not isinstance(doc, dict):
        return []
    out = []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal", {})
        if pr == "*":
            out.append(("*", bool(st.get("Condition"))))
            continue
        aws = pr.get("AWS") if isinstance(pr, dict) else None
        if aws:
            vals = aws if isinstance(aws, list) else [aws]
            for v in vals:
                out.append((str(v), bool(st.get("Condition"))))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Convert aws_enum inventory.json into rupu work units + assets.")
    ap.add_argument("--inventory", required=True, help="path to inventory.json")
    ap.add_argument("--out", default="out/work-units.json")
    ap.add_argument("--assets", default="out/assets.json")
    args = ap.parse_args()

    try:
        inv = json.load(open(args.inventory))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit("cannot read inventory: %s" % e)

    res = inv.get("results", {})
    account = (inv.get("identity") or {}).get("Account", "")
    units, seen = [], set()
    assets = {"account": account, "principals": [], "instances": [],
              "buckets": [], "endpoints": [], "secrets": []}

    def add(kind, title, targets, hints):
        key = (kind, tuple(targets))
        if key in seen or not targets:
            return
        seen.add(key)
        h = dict(hints)
        h.setdefault("account", account)
        h["kind"] = kind
        units.append({"id": uid(kind, targets[0]), "title": title,
                      "targets": targets, "hints": h})

    # --- EC2 instances ---
    for region, payload in per_region(res, "ec2", "describe-instances"):
        for resv in payload.get("Reservations", []):
            for i in resv.get("Instances", []):
                iid = i.get("InstanceId")
                pub = i.get("PublicIpAddress")
                priv = i.get("PrivateIpAddress")
                prof = (i.get("IamInstanceProfile") or {}).get("Arn")
                assets["instances"].append({"instance": iid, "public_ip": pub,
                                            "private_ip": priv, "profile": prof,
                                            "region": region})
                if pub:
                    add("public-resource", "EC2 %s public IP %s" % (iid, pub),
                        [pub, iid], {"service": "ec2", "region": region,
                                     "next_skill": "cloud-security"})
                if prof:
                    assets["principals"].append({"principal": prof,
                                                 "source": "instance-profile"})
                    add("principal",
                        "Instance %s carries profile %s (IMDS theft)" % (iid, prof),
                        [iid, prof], {"service": "ec2", "region": region,
                                      "lead": "instance-profile",
                                      "next_skill": "metadata-ssrf-pivot"})

    # --- open security groups ---
    for region, payload in per_region(res, "ec2", "describe-security-groups"):
        for sg in payload.get("SecurityGroups", []):
            ports = []
            for perm in sg.get("IpPermissions", []):
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0"
                              for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0"
                              for r in perm.get("Ipv6Ranges", []))
                if open_v4 or open_v6:
                    ports.append("%s-%s/%s" % (perm.get("FromPort", "all"),
                                               perm.get("ToPort", "all"),
                                               perm.get("IpProtocol", "-1")))
            if ports:
                add("public-resource",
                    "Security group %s open to world: %s" % (sg["GroupId"],
                                                             ", ".join(ports)),
                    [sg["GroupId"]], {"service": "ec2-sg", "region": region,
                                      "open_ports": ",".join(ports)})

    # --- S3 ---
    for _r, payload in per_region(res, "s3", "list-buckets"):
        for b in payload.get("Buckets", []):
            assets["buckets"].append({"bucket": b["Name"]})
            add("public-resource", "S3 bucket %s" % b["Name"], [b["Name"]],
                {"service": "s3", "next_skill": "cloud-storage-exposure"})

    # --- Lambda ---
    for region, payload in per_region(res, "lambda", "list-functions"):
        for fn in payload.get("Functions", []):
            name = fn.get("FunctionName")
            env = (fn.get("Environment") or {}).get("Variables") or {}
            role = fn.get("Role")
            if role:
                assets["principals"].append({"principal": role,
                                             "source": "lambda-role"})
            for k in env:
                if SECRET_KEY_RE.search(k):
                    tgt = "%s:%s" % (name, k)
                    assets["secrets"].append({"secret": tgt, "service": "lambda-env",
                                              "region": region})
                    add("secret", "Lambda %s env var %s" % (name, k), [tgt],
                        {"service": "lambda", "region": region,
                         "next_skill": "trufflehog"})

    # --- RDS ---
    for region, payload in per_region(res, "rds", "describe-db-instances"):
        for db in payload.get("DBInstances", []):
            ep = (db.get("Endpoint") or {}).get("Address")
            if db.get("PubliclyAccessible") and ep:
                assets["endpoints"].append({"endpoint": ep, "service": "rds",
                                            "region": region})
                add("public-resource",
                    "RDS %s publicly accessible at %s" % (
                        db.get("DBInstanceIdentifier"), ep),
                    [ep], {"service": "rds", "region": region,
                           "engine": db.get("Engine", "")})

    # --- SecretsManager / SSM ---
    for region, payload in per_region(res, "secretsmanager", "list-secrets"):
        for s in payload.get("SecretList", []):
            name = s.get("ARN") or s.get("Name")
            assets["secrets"].append({"secret": name, "service": "secretsmanager",
                                      "region": region})
            add("secret", "SecretsManager secret %s" % s.get("Name"), [name],
                {"service": "secretsmanager", "region": region,
                 "pull": "aws secretsmanager get-secret-value --secret-id %s" % name,
                 "next_skill": "trufflehog"})
    for region, payload in per_region(res, "ssm", "describe-parameters"):
        for p in payload.get("Parameters", []):
            name = p.get("Name")
            assets["secrets"].append({"secret": name, "service": "ssm",
                                      "region": region, "type": p.get("Type")})
            add("secret", "SSM parameter %s (%s)" % (name, p.get("Type")), [name],
                {"service": "ssm", "region": region,
                 "pull": "aws ssm get-parameter --name '%s' --with-decryption" % name,
                 "next_skill": "trufflehog"})

    # --- IAM roles / trust policies ---
    for _r, payload in per_region(res, "iam", "list-roles"):
        for role in payload.get("Roles", []):
            arn = role.get("Arn")
            trusts = trust_principals(role.get("AssumeRolePolicyDocument"))
            assets["principals"].append({"principal": arn, "source": "iam-role",
                                         "trusts": [t for t, _ in trusts]})
            for principal, has_cond in trusts:
                m = ACCT_RE.search(principal)
                if principal == "*" or "*" in principal:
                    lead = "wildcard-trust"
                elif m and account and m.group(0) != account:
                    lead = "cross-account-trust"
                else:
                    continue
                add("principal",
                    "Role %s trusts %s (%s%s)" % (
                        role.get("RoleName"), principal, lead,
                        "" if has_cond else ", no condition"),
                    [arn],
                    {"service": "iam", "lead": lead,
                     "trusted_principal": principal,
                     "conditioned": str(has_cond).lower(),
                     "try": "aws sts assume-role --role-arn %s --role-session-name x" % arn,
                     "next_skill": "pmapper"})
    for _r, payload in per_region(res, "iam", "list-users"):
        for u in payload.get("Users", []):
            assets["principals"].append({"principal": u.get("Arn"),
                                         "source": "iam-user"})

    # --- Edge: ELBv2, API Gateway, CloudFront, SNS/SQS/ECR as endpoints/assets ---
    for region, payload in per_region(res, "elbv2", "describe-load-balancers"):
        for lb in payload.get("LoadBalancers", []):
            if lb.get("Scheme") == "internet-facing" and lb.get("DNSName"):
                assets["endpoints"].append({"endpoint": lb["DNSName"],
                                            "service": "elbv2", "region": region})
                add("public-resource", "Internet-facing LB %s" % lb["DNSName"],
                    [lb["DNSName"]], {"service": "elbv2", "region": region})
    for region, payload in per_region(res, "apigateway", "get-rest-apis"):
        for api in payload.get("items", []):
            url = "https://%s.execute-api.%s.amazonaws.com" % (api["id"], region)
            assets["endpoints"].append({"endpoint": url, "service": "apigateway",
                                        "region": region})
            add("public-resource", "API Gateway %s (%s)" % (api.get("name"), url),
                [url], {"service": "apigateway", "region": region})
    for region, payload in per_region(res, "apigateway", "get-apis-v2"):
        for api in payload.get("Items", []):
            url = api.get("ApiEndpoint")
            if url:
                assets["endpoints"].append({"endpoint": url, "service": "apigatewayv2",
                                            "region": region})
                add("public-resource", "HTTP API %s (%s)" % (api.get("Name"), url),
                    [url], {"service": "apigatewayv2", "region": region})
    for _r, payload in per_region(res, "cloudfront", "list-distributions"):
        for d in (payload.get("DistributionList") or {}).get("Items", []) or []:
            dn = d.get("DomainName")
            if dn:
                assets["endpoints"].append({"endpoint": dn, "service": "cloudfront"})
                add("public-resource", "CloudFront distribution %s" % dn, [dn],
                    {"service": "cloudfront"})

    # --- CloudTrail logging gap ---
    ct = res.get("cloudtrail", {}).get("describe-trails", {})
    if ct and all(not (p or {}).get("trailList") for p in ct.values()):
        add("logging-gap", "No CloudTrail trail in any swept region",
            [account or "account"],
            {"service": "cloudtrail", "regions_checked": str(len(ct)),
             "next_skill": "finding-report"})

    # dedupe assets
    for k, v in assets.items():
        if isinstance(v, list):
            seen_a, out = set(), []
            for a in v:
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
        json.dump(units, f, indent=2)   # bare array only
    with open(args.assets, "w") as f:
        json.dump(assets, f, indent=2)
    print("wrote %d work units -> %s" % (len(units), args.out))
    print("assets -> %s" % args.assets)


if __name__ == "__main__":
    main()
