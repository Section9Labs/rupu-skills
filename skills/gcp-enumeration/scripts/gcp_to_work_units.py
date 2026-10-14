#!/usr/bin/env python3
"""gcp_to_work_units.py - convert gcp_enum.py inventory into rupu work units.

Reads the inventory JSON from scripts/gcp_enum.py and writes:
  - a BARE JSON ARRAY of work units {"id","title","targets","hints"} (rupu
    for_each-compatible: file content starts with '['), and
  - optionally an assets list {"kind","id","attrs"} for coverage-assets.

Unit kinds: instance, bucket, secret, sa_actas, function, run_service, gke,
cloudsql, bq_dataset, pubsub, cloudbuild, public_endpoint, iam_binding.

Example:
  python3 scripts/gcp_to_work_units.py out/gcp-inventory.json \
      -o out/work-units.json --assets out/assets.json
"""
import argparse
import json
import os

ACTAS_ROLES = {
    "roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountKeyAdmin", "roles/iam.workloadIdentityUser",
}
PRIV_PROJECT_ROLES = {
    "roles/owner", "roles/editor", "roles/iam.securityAdmin",
    "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin",
    "roles/cloudbuild.builds.editor", "roles/deploymentmanager.editor",
    "roles/compute.admin", "roles/container.admin",
}


def unit(uid, title, targets, hints):
    return {"id": uid, "title": title,
            "targets": sorted(set(t for t in targets if t)), "hints": hints}


def main():
    ap = argparse.ArgumentParser(
        description="gcloud inventory -> rupu work-units JSON array + assets")
    ap.add_argument("inventory", help="output of scripts/gcp_enum.py")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units array path (default out/work-units.json)")
    ap.add_argument("--assets", help="also write assets list JSON here")
    args = ap.parse_args()

    with open(args.inventory) as f:
        inv = json.load(f)

    units, assets, n = [], [], 0

    def nid(prefix):
        nonlocal n
        n += 1
        return f"gcp-{prefix}-{n:04d}"

    for entry in inv.get("projects", []):
        proj = entry["project"]
        data = entry.get("inventory", {})
        assets.append({"kind": "cloud-account", "id": f"gcp:project:{proj}",
                       "attrs": {}})

        # Instances
        for inst in data.get("instances") or []:
            name = inst.get("name", "")
            zone = inst.get("zone", "").rsplit("/", 1)[-1]
            pub_ips = [ac.get("natIP") for ni in inst.get("networkInterfaces") or []
                       for ac in ni.get("accessConfigs") or [] if ac.get("natIP")]
            sas = inst.get("_serviceAccounts") or inst.get("serviceAccounts") or []
            scopes = [s for sa in sas for s in sa.get("scopes", [])]
            md_keys = [i.get("key") for i in
                       ((inst.get("_metadata") or {}).get("items") or [])]
            assets.append({"kind": "compute-instance",
                           "id": f"gcp:instance:{proj}/{zone}/{name}",
                           "attrs": {"sa": sas[0].get("email", "") if sas else ""}})
            for ip in pub_ips:
                assets.append({"kind": "public-endpoint", "id": f"ip:{ip}",
                               "attrs": {"project": proj, "instance": name}})
            units.append(unit(nid("vm"), f"Instance {name} ({proj})",
                              [name] + pub_ips,
                              {"kind": "instance", "project": proj, "zone": zone,
                               "service_account": sas[0].get("email", "") if sas else "",
                               "cloud_platform_scope":
                                   any("cloud-platform" in s for s in scopes),
                               "metadata_keys": md_keys,
                               "handoff": "describe metadata + serial output; "
                                          "token theft -> metadata-ssrf-pivot"}))

        # Buckets (gcloud storage ls json: [{"url": "gs://bucket/"}] or names)
        for b in data.get("buckets") or []:
            burl = b.get("url", b) if isinstance(b, dict) else b
            bname = str(burl).replace("gs://", "").strip("/")
            if not bname:
                continue
            assets.append({"kind": "storage-bucket", "id": f"gcs:{bname}",
                           "attrs": {"project": proj}})
            units.append(unit(nid("gcs"), f"Bucket gs://{bname}",
                              [bname, f"gs://{bname}"],
                              {"kind": "bucket", "project": proj,
                               "handoff": "cloud-storage-exposure"}))

        # Secrets
        for s in data.get("secrets") or []:
            sname = s.get("name", "").rsplit("/", 1)[-1]
            assets.append({"kind": "secret", "id": f"gcp:secret:{proj}/{sname}",
                           "attrs": {}})
            units.append(unit(nid("sec"), f"Secret {sname} ({proj})",
                              [f"gcp:secret:{proj}/{sname}"],
                              {"kind": "secret", "project": proj, "secret": sname,
                               "handoff": "gcloud secrets versions access latest "
                                          f"--secret={sname} -> trufflehog"}))

        # Service accounts: actAs leads from per-SA IAM policies
        for sa in data.get("service_accounts") or []:
            email = sa.get("email", "")
            assets.append({"kind": "principal", "id": f"gcp:sa:{email}",
                           "attrs": {"project": proj,
                                     "keys": str(len(sa.get("_keys") or []))}})
            actas = [{"role": b.get("role"), "members": b.get("members", [])}
                     for b in (sa.get("_iam_policy") or {}).get("bindings", [])
                     if b.get("role") in ACTAS_ROLES]
            if actas:
                units.append(unit(nid("sa"), f"actAs lead on {email}",
                                  [email],
                                  {"kind": "sa_actas", "project": proj,
                                   "bindings": actas,
                                   "handoff": "cloud-privilege-escalation "
                                              "(impersonate / mint key)"}))

        # Privileged project-level IAM bindings
        for b in (data.get("iam_policy") or {}).get("bindings", []):
            if b.get("role") in PRIV_PROJECT_ROLES:
                units.append(unit(nid("iam"),
                                  f"{b['role']} on {proj}",
                                  b.get("members", []),
                                  {"kind": "iam_binding", "project": proj,
                                   "role": b["role"],
                                   "handoff": "cloud-privilege-escalation"}))
                for m in b.get("members", []):
                    assets.append({"kind": "principal", "id": f"gcp:principal:{m}",
                                   "attrs": {"role": b["role"], "project": proj}})

        # Functions / Cloud Run
        for fn in data.get("functions") or []:
            fname = fn.get("name", "").rsplit("/", 1)[-1]
            cfg = fn.get("serviceConfig") or {}
            units.append(unit(nid("fn"), f"Function {fname} ({proj})",
                              [fname, cfg.get("uri", "")],
                              {"kind": "function", "project": proj,
                               "service_account": cfg.get("serviceAccountEmail", ""),
                               "env_keys": list((cfg.get("environmentVariables") or {}).keys()),
                               "handoff": "env + generateDownloadUrl source -> trufflehog"}))
        for svc in data.get("run_services") or []:
            sname = (svc.get("metadata") or {}).get("name", "")
            url = (svc.get("status") or {}).get("url", "")
            if url:
                assets.append({"kind": "public-endpoint", "id": f"url:{url}",
                               "attrs": {"project": proj, "type": "cloud-run"}})
            units.append(unit(nid("run"), f"Cloud Run {sname} ({proj})",
                              [sname, url],
                              {"kind": "run_service", "project": proj,
                               "handoff": "describe env/SA; identity-token invoke"}))

        # GKE / SQL / BQ / PubSub / Build
        for c in data.get("gke_clusters") or []:
            units.append(unit(nid("gke"), f"GKE {c.get('name','')} ({proj})",
                              [c.get("name", ""), c.get("endpoint", "")],
                              {"kind": "gke", "project": proj,
                               "node_sa": (c.get("nodeConfig") or {}).get("serviceAccount", ""),
                               "handoff": "get-credentials -> k8s attack flow"}))
        for db in data.get("sql_instances") or []:
            ips = [i.get("ipAddress") for i in db.get("ipAddresses") or []]
            units.append(unit(nid("sql"), f"CloudSQL {db.get('name','')} ({proj})",
                              [db.get("name", "")] + ips,
                              {"kind": "cloudsql", "project": proj,
                               "version": db.get("databaseVersion", ""),
                               "handoff": "users list / set-password / export to GCS"}))
        for ds in data.get("bq_datasets") or []:
            dref = (ds.get("datasetReference") or {})
            units.append(unit(nid("bq"), f"BQ dataset {dref.get('datasetId','')} ({proj})",
                              [f"{proj}:{dref.get('datasetId','')}"],
                              {"kind": "bq_dataset", "project": proj,
                               "handoff": "bq ls/head for PII and creds"}))
        for sub in data.get("pubsub_subscriptions") or []:
            sname = sub.get("name", "").rsplit("/", 1)[-1]
            units.append(unit(nid("ps"), f"Pub/Sub sub {sname} ({proj})",
                              [sub.get("name", "")],
                              {"kind": "pubsub", "project": proj,
                               "handoff": "subscriptions pull --auto-ack -> trufflehog"}))
        if data.get("builds"):
            units.append(unit(nid("cb"), f"Cloud Build history ({proj})",
                              [proj],
                              {"kind": "cloudbuild", "project": proj,
                               "build_count": len(data["builds"]),
                               "handoff": "builds log + configs -> trufflehog; "
                                          "builds.create -> cloud-privilege-escalation"}))

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(units, f, indent=2)   # bare array -> rupu for_each
    print(f"[+] wrote {len(units)} work units -> {args.output}")

    if args.assets:
        seen, dedup = set(), []
        for a in assets:
            if a["id"] not in seen:
                seen.add(a["id"])
                dedup.append(a)
        os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
        with open(args.assets, "w") as f:
            json.dump(dedup, f, indent=2)
        print(f"[+] wrote {len(dedup)} assets -> {args.assets} "
              "(loop through rupu assets.mark; see references/rupu.md)")


if __name__ == "__main__":
    main()
