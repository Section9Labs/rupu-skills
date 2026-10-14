#!/usr/bin/env python3
"""permute_names.py — generate candidate bucket/container/account names.

Combines base org names with common environment/purpose prefixes and suffixes
and separators to build a candidate list for cloud_enum / s3scanner /
GCPBucketBrute / probe_storage.py.

Stdlib only. Example:
  python3 scripts/permute_names.py --bases example,examplecorp,example-com \
      --provider s3 -o out/candidates.txt
"""
import argparse
import sys

DEFAULT_WORDS = [
    "dev", "test", "stage", "staging", "prod", "production", "uat", "qa",
    "backup", "backups", "bak", "data", "assets", "static", "media", "img",
    "images", "files", "logs", "log", "archive", "internal", "private",
    "public", "www", "web", "cdn", "uploads", "upload", "download",
    "terraform", "tfstate", "tf-state", "state", "artifacts", "build",
    "builds", "ci", "cicd", "jenkins", "secrets", "secret", "config",
    "configs", "db", "database", "dump", "dumps", "sql", "export", "exports",
    "reports", "analytics", "ml", "models", "lambda", "functions", "docs",
    "share", "shared", "tmp", "temp", "old", "new", "legacy", "infra", "ops",
    "k8s", "kube", "helm", "docker", "registry", "repo", "git", "svn",
    "email", "mail", "invoices", "billing", "finance", "hr", "customer",
    "customers", "users", "user", "app", "api", "mobile", "ios", "android",
]
REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1",
    "eu-west-2", "eu-central-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "sa-east-1", "us", "eu", "asia", "east", "west",
    "central",
]
YEARS = ["2020", "2021", "2022", "2023", "2024", "2025"]


def valid(name, provider):
    if provider == "azure":
        # storage account names: 3-24 chars, lowercase letters + digits only
        return 3 <= len(name) <= 24 and name.isalnum() and name.islower()
    # s3 / gcs: 3-63 chars, lowercase letters, digits, hyphens, dots
    if not (3 <= len(name) <= 63):
        return False
    if name[0] in ".-" or name[-1] in ".-":
        return False
    return all(c.islower() or c.isdigit() or c in ".-_" for c in name)


def main():
    ap = argparse.ArgumentParser(description="Generate candidate storage names "
                                 "from base org names.")
    ap.add_argument("--bases", required=True,
                    help="comma-separated base names (org, product, domain-ish)")
    ap.add_argument("--words", default=None,
                    help="file of extra prefix/suffix words (one per line); "
                         "merged with the built-in list")
    ap.add_argument("--provider", choices=["s3", "gcs", "azure", "any"],
                    default="any", help="filter names to provider naming rules "
                    "(azure = account names, alnum only)")
    ap.add_argument("--separators", default="-,_,.,",
                    help="comma-separated separators; trailing empty = none "
                         "(default: '-,_,.,' = dash underscore dot none)")
    ap.add_argument("--regions", action="store_true",
                    help="also append region tags (us-east-1, eu, ...)")
    ap.add_argument("--years", action="store_true", help="also append years")
    ap.add_argument("-o", "--output", default="-",
                    help="output file (default: stdout)")
    args = ap.parse_args()

    bases = [b.strip().lower() for b in args.bases.split(",") if b.strip()]
    words = list(DEFAULT_WORDS)
    if args.words:
        with open(args.words) as fh:
            words += [w.strip().lower() for w in fh if w.strip()]
    if args.regions:
        words += REGIONS
    if args.years:
        words += YEARS
    seps = args.separators.split(",")  # may include "" for no separator

    out = []
    seen = set()

    def emit(name):
        prov = args.provider
        if prov == "azure":
            name = name.replace("-", "").replace("_", "").replace(".", "")
        else:
            name = name.replace("_", "-") if prov in ("s3", "gcs") else name
        if name in seen:
            return
        if prov != "any" and not valid(name, prov):
            return
        if prov == "any" and not valid(name, "s3"):
            return
        seen.add(name)
        out.append(name)

    for base in bases:
        emit(base)
        for w in words:
            for sep in seps:
                emit(base + sep + w)
                emit(w + sep + base)

    if args.output == "-":
        sys.stdout.write("\n".join(out) + "\n")
    else:
        import os
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            fh.write("\n".join(out) + "\n")
        print("[+] %d candidates -> %s" % (len(out), args.output))


if __name__ == "__main__":
    main()
