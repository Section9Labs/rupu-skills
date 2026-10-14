#!/usr/bin/env python3
"""aws_enum.py - multi-region AWS attack-surface sweep via the aws CLI (no boto).

Shells `aws <svc> <op> --output json` for a chosen set of services across a region
list (or all regions via `aws ec2 describe-regions --all-regions`), saves every raw
response under <outdir>/raw/, and writes a normalized <outdir>/inventory.json:

  { "profile", "identity", "regions", "errors": [...],
    "results": { "<service>": { "<operation>": { "<region>": <payload> } } } }

Usage:
  python3 scripts/aws_enum.py --profile target --regions all --outdir out/awsenum
  python3 scripts/aws_enum.py --profile target --regions us-east-1,eu-west-1 \
      --services ec2,s3,iam,lambda,secretsmanager,ssm --outdir out/awsenum
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

# service -> list of (operation-name, cli args after `aws`)
GLOBAL_SERVICES = {
    "sts": [("get-caller-identity", ["sts", "get-caller-identity"])],
    "iam": [
        ("list-users", ["iam", "list-users"]),
        ("list-roles", ["iam", "list-roles"]),
        ("list-groups", ["iam", "list-groups"]),
        ("list-policies-local", ["iam", "list-policies", "--scope", "Local"]),
        ("list-account-aliases", ["iam", "list-account-aliases"]),
        ("list-open-id-connect-providers", ["iam", "list-open-id-connect-providers"]),
    ],
    "s3": [("list-buckets", ["s3api", "list-buckets"])],
    "route53": [("list-hosted-zones", ["route53", "list-hosted-zones"])],
    "cloudfront": [("list-distributions", ["cloudfront", "list-distributions"])],
}

REGIONAL_SERVICES = {
    "ec2": [
        ("describe-instances", ["ec2", "describe-instances"]),
        ("describe-security-groups", ["ec2", "describe-security-groups"]),
        ("describe-network-interfaces", ["ec2", "describe-network-interfaces"]),
        ("describe-snapshots-self", ["ec2", "describe-snapshots", "--owner-ids", "self"]),
        ("describe-images-self", ["ec2", "describe-images", "--owners", "self"]),
    ],
    "lambda": [("list-functions", ["lambda", "list-functions"])],
    "rds": [("describe-db-instances", ["rds", "describe-db-instances"])],
    "dynamodb": [("list-tables", ["dynamodb", "list-tables"])],
    "secretsmanager": [("list-secrets", ["secretsmanager", "list-secrets"])],
    "ssm": [("describe-parameters", ["ssm", "describe-parameters"])],
    "ecs": [("list-clusters", ["ecs", "list-clusters"]),
            ("list-task-definitions", ["ecs", "list-task-definitions"])],
    "eks": [("list-clusters", ["eks", "list-clusters"])],
    "ecr": [("describe-repositories", ["ecr", "describe-repositories"])],
    "sns": [("list-topics", ["sns", "list-topics"])],
    "sqs": [("list-queues", ["sqs", "list-queues"])],
    "apigateway": [("get-rest-apis", ["apigateway", "get-rest-apis"]),
                   ("get-apis-v2", ["apigatewayv2", "get-apis"])],
    "elbv2": [("describe-load-balancers", ["elbv2", "describe-load-balancers"])],
    "cloudtrail": [("describe-trails", ["cloudtrail", "describe-trails"])],
    "kms": [("list-keys", ["kms", "list-keys"]),
            ("list-aliases", ["kms", "list-aliases"])],
    "cloudformation": [("describe-stacks", ["cloudformation", "describe-stacks"])],
}

ALL_SERVICES = sorted(set(GLOBAL_SERVICES) | set(REGIONAL_SERVICES))


def aws_call(args_list, profile, region, timeout):
    cmd = ["aws"] + args_list + ["--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    if region:
        cmd += ["--region", region]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout after %ss" % timeout
    if proc.returncode != 0:
        return None, (proc.stderr or "exit %d" % proc.returncode).strip()[:400]
    if not proc.stdout.strip():
        return {}, None
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        return None, "unparseable output"


def get_regions(profile, timeout):
    data, err = aws_call(
        ["ec2", "describe-regions", "--all-regions"], profile, "us-east-1", timeout)
    if err or not data:
        sys.exit("cannot list regions (%s); pass --regions explicitly" % err)
    return sorted(r["RegionName"] for r in data.get("Regions", []))


def main():
    ap = argparse.ArgumentParser(
        description="Sweep AWS services across regions via the aws CLI; write a "
                    "normalized inventory.json.")
    ap.add_argument("--profile", default=None, help="AWS profile (else env creds)")
    ap.add_argument("--regions", default="all",
                    help="'all' (describe-regions --all-regions) or comma list")
    ap.add_argument("--services", default=",".join(ALL_SERVICES),
                    help="comma list; available: %s" % ",".join(ALL_SERVICES))
    ap.add_argument("--outdir", default="out/awsenum", help="output directory")
    ap.add_argument("--timeout", type=int, default=120, help="seconds per CLI call")
    args = ap.parse_args()

    if shutil.which("aws") is None:
        sys.exit("aws CLI not on PATH")

    services = [s.strip() for s in args.services.split(",") if s.strip()]
    bad = [s for s in services if s not in ALL_SERVICES]
    if bad:
        sys.exit("unknown services: %s (available: %s)" % (bad, ",".join(ALL_SERVICES)))

    identity, err = aws_call(["sts", "get-caller-identity"], args.profile, None,
                             args.timeout)
    if err:
        sys.exit("sts get-caller-identity failed: %s" % err)
    print("[*] identity: %s" % identity.get("Arn"))

    if args.regions == "all":
        regions = get_regions(args.profile, args.timeout)
    else:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    print("[*] regions: %d" % len(regions))

    rawdir = os.path.join(args.outdir, "raw")
    os.makedirs(rawdir, exist_ok=True)
    results, errors = {}, []

    def record(svc, op, region, payload, err):
        if err:
            errors.append({"service": svc, "operation": op, "region": region,
                           "error": err})
            tag = "denied" if "AccessDenied" in err or "UnauthorizedOperation" in err \
                else "error"
            print("    [%s] %s %s (%s): %s" % (tag, svc, op, region or "global",
                                               err.splitlines()[0][:120]))
            return
        results.setdefault(svc, {}).setdefault(op, {})[region or "global"] = payload
        rdir = os.path.join(rawdir, region or "global")
        os.makedirs(rdir, exist_ok=True)
        with open(os.path.join(rdir, "%s_%s.json" % (svc, op)), "w") as f:
            json.dump(payload, f, indent=2)

    for svc in services:
        if svc in GLOBAL_SERVICES:
            print("[*] %s (global)" % svc)
            for op, cli in GLOBAL_SERVICES[svc]:
                payload, err = aws_call(cli, args.profile, "us-east-1", args.timeout)
                record(svc, op, None, payload, err)
        if svc in REGIONAL_SERVICES:
            print("[*] %s (%d regions)" % (svc, len(regions)))
            for region in regions:
                for op, cli in REGIONAL_SERVICES[svc]:
                    payload, err = aws_call(cli, args.profile, region, args.timeout)
                    record(svc, op, region, payload, err)

    inventory = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profile": args.profile,
        "identity": identity,
        "regions": regions,
        "services": services,
        "errors": errors,
        "results": results,
    }
    path = os.path.join(args.outdir, "inventory.json")
    with open(path, "w") as f:
        json.dump(inventory, f, indent=2)
    print("[*] inventory -> %s (%d errors; denied calls are privesc objectives)"
          % (path, len(errors)))
    print("[*] next: python3 scripts/aws_to_work_units.py --inventory %s "
          "--out out/work-units.json --assets out/assets.json" % path)


if __name__ == "__main__":
    main()
