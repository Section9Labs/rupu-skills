#!/usr/bin/env python3
"""gcp_enum.py - GCP resource-plane sweep via the gcloud CLI.

Runs `gcloud ... --format=json` (plus bq/gcloud storage) across all (or
selected) projects and services and writes one normalized inventory JSON.
Python 3 stdlib only.

Examples:
  python3 scripts/gcp_enum.py --all-projects -o out/gcp-inventory.json
  python3 scripts/gcp_enum.py --project project-id-1 --services compute,storage,secrets \
      -o out/gcp-inventory.json
  python3 scripts/gcp_enum.py --all-projects --deep \
      --impersonate admin-sa@project-id-1.iam.gserviceaccount.com -o out/gcp-inventory.json
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

ALL_SERVICES = [
    "iam", "compute", "storage", "functions", "run", "gke", "sql",
    "bigquery", "secrets", "pubsub", "cloudbuild", "artifacts", "network",
]


def run_cmd(cmd, timeout=180):
    """Run a command, return parsed JSON (or None)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] {' '.join(cmd[:5])}...: {e}", file=sys.stderr)
        return None
    if p.returncode != 0:
        err = (p.stderr or "").strip().splitlines()
        print(f"[!] {' '.join(cmd[:5])}... -> {err[0] if err else 'error'}",
              file=sys.stderr)
        return None
    out = p.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out}


def gcloud(args, impersonate=None, timeout=180):
    cmd = ["gcloud"] + args + ["--format=json", "--quiet"]
    if impersonate:
        cmd.append(f"--impersonate-service-account={impersonate}")
    return run_cmd(cmd, timeout)


def enum_project(project, services, deep, imp):
    P = ["--project", project]
    inv = {}

    def grab(key, args, extra_p=True):
        print(f"    [*] {key}", file=sys.stderr)
        data = gcloud(args + (P if extra_p else []), imp)
        if data is not None:
            inv[key] = data

    if "iam" in services:
        grab("iam_policy", ["projects", "get-iam-policy", project], extra_p=False)
        grab("service_accounts", ["iam", "service-accounts", "list"])
        if deep:
            for sa in inv.get("service_accounts") or []:
                email = sa.get("email", "")
                pol = gcloud(["iam", "service-accounts", "get-iam-policy", email], imp)
                if pol is not None:
                    sa["_iam_policy"] = pol
                keys = gcloud(["iam", "service-accounts", "keys", "list",
                               "--iam-account", email], imp)
                if keys is not None:
                    sa["_keys"] = keys
    if "compute" in services:
        grab("instances", ["compute", "instances", "list"])
        grab("addresses", ["compute", "addresses", "list"])
        if deep:
            for inst in inv.get("instances") or []:
                zone = inst.get("zone", "").rsplit("/", 1)[-1]
                full = gcloud(["compute", "instances", "describe", inst["name"],
                               "--zone", zone] + P, imp)
                if full:
                    inst["_metadata"] = full.get("metadata")
                    inst["_serviceAccounts"] = full.get("serviceAccounts")
    if "storage" in services:
        grab("buckets", ["storage", "ls"])
    if "functions" in services:
        grab("functions", ["functions", "list"])
    if "run" in services:
        grab("run_services", ["run", "services", "list", "--platform=managed"])
    if "gke" in services:
        grab("gke_clusters", ["container", "clusters", "list"])
    if "sql" in services:
        grab("sql_instances", ["sql", "instances", "list"])
    if "bigquery" in services and shutil.which("bq"):
        print("    [*] bigquery", file=sys.stderr)
        data = run_cmd(["bq", "ls", "--format=json", f"--project_id={project}"])
        if data is not None:
            inv["bq_datasets"] = data
    if "secrets" in services:
        grab("secrets", ["secrets", "list"])
    if "pubsub" in services:
        grab("pubsub_topics", ["pubsub", "topics", "list"])
        grab("pubsub_subscriptions", ["pubsub", "subscriptions", "list"])
    if "cloudbuild" in services:
        grab("builds", ["builds", "list", "--limit", "50"])
    if "artifacts" in services:
        grab("artifact_repos", ["artifacts", "repositories", "list"])
    if "network" in services:
        grab("firewall_rules", ["compute", "firewall-rules", "list"])
        grab("forwarding_rules", ["compute", "forwarding-rules", "list"])
    return inv


def main():
    ap = argparse.ArgumentParser(
        description="GCP resource-plane sweep via gcloud -> inventory JSON")
    ap.add_argument("--all-projects", action="store_true",
                    help="enumerate every project from `gcloud projects list`")
    ap.add_argument("--project", action="append", default=[],
                    help="project id (repeatable)")
    ap.add_argument("--services", default=",".join(ALL_SERVICES),
                    help=f"comma list (default all = {','.join(ALL_SERVICES)})")
    ap.add_argument("--deep", action="store_true",
                    help="also pull instance metadata/SAs, per-SA IAM policies and keys")
    ap.add_argument("--impersonate", metavar="SA_EMAIL",
                    help="run everything as this SA (--impersonate-service-account)")
    ap.add_argument("-o", "--output", default="out/gcp-inventory.json",
                    help="inventory output path (default out/gcp-inventory.json)")
    args = ap.parse_args()

    if not shutil.which("gcloud"):
        sys.exit("[!] gcloud not found in PATH")
    if not args.all_projects and not args.project:
        sys.exit("[!] pass --all-projects or --project <id>")

    services = [s.strip() for s in args.services.split(",") if s.strip()]
    identity = gcloud(["auth", "list"], args.impersonate)
    if args.all_projects:
        projects = [p["projectId"] for p in gcloud(["projects", "list"],
                                                   args.impersonate) or []]
    else:
        projects = args.project
    orgs = gcloud(["organizations", "list"], args.impersonate)
    print(f"[*] {len(projects)} project(s)", file=sys.stderr)

    inventory = {"identity": identity, "organizations": orgs,
                 "impersonated": args.impersonate, "projects": []}
    for proj in projects:
        print(f"[*] project {proj}", file=sys.stderr)
        data = enum_project(proj, services, args.deep, args.impersonate)
        inventory["projects"].append({"project": proj, "inventory": data})

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(inventory, f, indent=2, default=str)
    total = sum(len(v) if isinstance(v, list) else 1
                for p in inventory["projects"]
                for v in p["inventory"].values())
    print(f"[+] wrote {args.output} ({total} inventory entries across "
          f"{len(projects)} project(s))")
    print("[+] next: python3 scripts/gcp_to_work_units.py "
          f"{args.output} -o out/work-units.json --assets out/assets.json")


if __name__ == "__main__":
    main()
