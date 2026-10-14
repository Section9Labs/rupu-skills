#!/usr/bin/env python3
"""whoami_all.py — validate loaded cloud credentials and record identities.

Runs the three providers' whoami commands via subprocess:
  AWS:   aws sts get-caller-identity   (per --aws-profiles, plus env creds)
  Azure: az account show + az ad signed-in-user show
  GCP:   gcloud auth list + gcloud config get-value project

Records each live identity as an asset and emits one work unit per identity
(bare JSON array -> rupu for_each ingestible).

Stdlib only. Example:
  python3 scripts/whoami_all.py --aws-profiles default,stolen --azure --gcp \
      -o out/identities.json --work-units out/whoami-units.json
"""
import argparse
import json
import os
import shutil
import subprocess


def run(cmd, env=None):
    """Run a command, return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "%s: not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def jload(s):
    try:
        return json.loads(s)
    except ValueError:
        return None


def aws_whoami(profiles, results):
    if not shutil.which("aws"):
        print("[-] aws CLI not found, skipping AWS")
        return
    attempts = [(p, ["aws", "sts", "get-caller-identity", "--output", "json",
                     "--profile", p]) for p in profiles]
    if os.environ.get("AWS_ACCESS_KEY_ID"):
        attempts.append(("<env>", ["aws", "sts", "get-caller-identity",
                                   "--output", "json"]))
    for label, cmd in attempts:
        rc, out, err = run(cmd)
        if rc == 0 and (data := jload(out)):
            print("[+] aws %-12s %s" % (label, data.get("Arn")))
            results.append({
                "provider": "aws", "credential": label, "live": True,
                "principal": data.get("Arn"), "account": data.get("Account"),
                "raw": data,
            })
        else:
            print("[-] aws %-12s dead/invalid (%s)" % (label, (err or out).splitlines()[0] if (err or out) else rc))
            results.append({"provider": "aws", "credential": label, "live": False,
                            "error": err or out})


def azure_whoami(results):
    if not shutil.which("az"):
        print("[-] az CLI not found, skipping Azure")
        return
    rc, out, _err = run(["az", "account", "show", "--output", "json"])
    if rc == 0 and (data := jload(out)):
        user = data.get("user", {})
        print("[+] azure %s (%s) sub=%s" % (user.get("name"), user.get("type"),
                                            data.get("id")))
        rec = {"provider": "azure", "credential": "az-context", "live": True,
               "principal": user.get("name"), "principal_type": user.get("type"),
               "tenant": data.get("tenantId"), "subscription": data.get("id"),
               "raw": data}
        rc2, out2, _ = run(["az", "ad", "signed-in-user", "show", "--output", "json"])
        if rc2 == 0 and (me := jload(out2)):
            rec["oid"] = me.get("id")
            rec["upn"] = me.get("userPrincipalName")
        results.append(rec)
        rc3, out3, _ = run(["az", "account", "list", "--all", "--output", "json"])
        if rc3 == 0 and (subs := jload(out3)):
            rec["subscriptions"] = [{"id": s.get("id"), "name": s.get("name"),
                                     "tenant": s.get("tenantId")} for s in subs]
    else:
        print("[-] azure: no live az context")
        results.append({"provider": "azure", "credential": "az-context",
                        "live": False})


def gcp_whoami(results):
    if not shutil.which("gcloud"):
        print("[-] gcloud not found, skipping GCP")
        return
    rc, out, _err = run(["gcloud", "auth", "list", "--format", "json"])
    accounts = jload(out) if rc == 0 else None
    if not accounts:
        print("[-] gcp: no authenticated accounts")
        results.append({"provider": "gcp", "credential": "gcloud", "live": False})
        return
    _rc, proj, _ = run(["gcloud", "config", "get-value", "project"])
    for acct in accounts:
        email = acct.get("account")
        active = acct.get("status") == "ACTIVE"
        print("[+] gcp %s%s project=%s" % (email, " (ACTIVE)" if active else "", proj or "?"))
        results.append({"provider": "gcp", "credential": "gcloud", "live": True,
                        "principal": email, "active": active,
                        "project": proj or "", "raw": acct})
    rc, out, _ = run(["gcloud", "projects", "list", "--format", "json"])
    if rc == 0 and (projects := jload(out)):
        for r in results:
            if r["provider"] == "gcp" and r.get("live"):
                r["projects"] = [p.get("projectId") for p in projects]
        print("[+] gcp projects visible: %s" % ", ".join(p.get("projectId", "?") for p in projects))


def to_assets(results):
    assets = []
    for r in results:
        if not r.get("live"):
            continue
        if r.get("principal"):
            assets.append({"type": "principal", "id": r["principal"],
                           "hints": {"provider": r["provider"],
                                     "credential": str(r.get("credential", ""))}})
        if r.get("account"):
            assets.append({"type": "cloud-account", "id": "aws:" + r["account"],
                           "hints": {"provider": "aws"}})
        for s in r.get("subscriptions", []):
            assets.append({"type": "cloud-account",
                           "id": "azure-subscription:" + str(s["id"]),
                           "hints": {"provider": "azure", "name": str(s.get("name", "")),
                                     "tenant": str(s.get("tenant", ""))}})
        for p in r.get("projects", []):
            assets.append({"type": "cloud-account", "id": "gcp-project:" + p,
                           "hints": {"provider": "gcp"}})
    return assets


def to_units(results):
    units = []
    n = 0
    for r in results:
        if not r.get("live") or not r.get("principal"):
            continue
        n += 1
        hints = {"provider": r["provider"]}
        for k in ("account", "tenant", "subscription", "oid", "upn", "project",
                  "principal_type"):
            if r.get(k):
                hints[k] = str(r[k])
        units.append({
            "id": "identity-%s-%04d" % (r["provider"], n),
            "title": "Live %s identity %s" % (r["provider"], r["principal"]),
            "targets": [r["principal"]],
            "hints": hints,
        })
    return units


def main():
    ap = argparse.ArgumentParser(description="Run AWS/Azure/GCP whoami commands "
                                 "for available credentials and record identities.")
    ap.add_argument("--aws-profiles", default="default",
                    help="comma-separated AWS profile names (default: default)")
    ap.add_argument("--azure", action="store_true", help="check Azure (az) context")
    ap.add_argument("--gcp", action="store_true", help="check GCP (gcloud) context")
    ap.add_argument("--all", action="store_true", help="check all three providers")
    ap.add_argument("-o", "--output", default="out/identities.json",
                    help="assets JSON output (default out/identities.json)")
    ap.add_argument("--work-units", default="out/whoami-units.json",
                    help="work-units JSON array output (default out/whoami-units.json)")
    args = ap.parse_args()

    results = []
    profiles = [p for p in args.aws_profiles.split(",") if p]
    if profiles or args.all:
        aws_whoami(profiles, results)
    if args.azure or args.all:
        azure_whoami(results)
    if args.gcp or args.all:
        gcp_whoami(results)

    assets = to_assets(results)
    units = to_units(results)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(assets, fh, indent=2)
    os.makedirs(os.path.dirname(args.work_units) or ".", exist_ok=True)
    with open(args.work_units, "w") as fh:
        json.dump(units, fh, indent=2)
    print("[+] %d assets -> %s ; %d work units -> %s"
          % (len(assets), args.output, len(units), args.work_units))


if __name__ == "__main__":
    main()
