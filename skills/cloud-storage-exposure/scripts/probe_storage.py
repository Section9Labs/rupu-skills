#!/usr/bin/env python3
"""probe_storage.py — probe S3 / Azure Blob / GCS names for access level.

For each candidate name, probes:
  - anonymous access via raw HTTP (urllib): existence, listing, read
  - authenticated access via the provider CLI (aws / az / gcloud) if available
  - optional write test (--write-test): uploads a small PoC object anonymously
    and/or with the credential

Records an access level per target (none/exists/listable/readable/writable) and
emits:
  - a bare JSON ARRAY of work units for every ACCESSIBLE store (rupu for_each)
  - an assets list including exists-but-denied stores (--assets)

Stdlib only. Examples:
  python3 scripts/probe_storage.py --provider s3 --names-file out/candidates.txt \
      --profile target --write-test -o out/work-units.json --assets out/assets.json
  python3 scripts/probe_storage.py --provider gcs --names example-prod,example-backups
  python3 scripts/probe_storage.py --provider azure --account exampleacct \
      --names-file containers.txt --sas-token 'sv=...&sig=...'
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request

POC_BODY = b"storage probe poc vulture\n"
LEVELS = ["none", "exists", "listable", "readable", "writable", "admin"]


def http(url, method="GET", data=None, timeout=15):
    """Return (status, body_text). Never raises."""
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "probe-storage/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(65536).decode("utf-8", "ignore")
        except Exception:
            return e.code, ""
    except Exception as e:
        return 0, str(e)


def run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def bump(result, level):
    if LEVELS.index(level) > LEVELS.index(result["access"]):
        result["access"] = level


# ---------------- S3 ----------------

def probe_s3(name, args):
    r = {"name": name, "provider": "s3", "access": "none", "anonymous": False,
         "writable": False, "object_count": 0,
         "url": "https://%s.s3.amazonaws.com/" % name, "evidence": []}
    status, body = http(r["url"] + "?list-type=2&max-keys=10")
    if status == 404 and "NoSuchBucket" in body:
        return r
    if status in (301, 400) and ("PermanentRedirect" in body or "IllegalLocation" in body):
        bump(r, "exists")
        r["evidence"].append("anon: exists in another region (HTTP %d)" % status)
    elif status == 403:
        bump(r, "exists")
        r["evidence"].append("anon list: 403 AccessDenied")
    elif status == 200:
        bump(r, "listable")
        r["anonymous"] = True
        r["object_count"] = body.count("<Key>")
        r["evidence"].append("anon list: 200, %d keys in first page" % r["object_count"])
        m = re.search(r"<Key>([^<]+)</Key>", body)
        if m:
            s2, _ = http(r["url"] + urllib.request.quote(m.group(1)))
            if s2 == 200:
                bump(r, "readable")
                r["evidence"].append("anon read of %s: 200" % m.group(1))
    elif status != 0:
        bump(r, "exists")
        r["evidence"].append("anon list: HTTP %d" % status)

    if r["access"] == "none":
        return r

    # authed via aws CLI
    if shutil.which("aws") and args.profile:
        rc, out, err = run(["aws", "s3api", "list-objects-v2", "--bucket", name,
                            "--max-items", "10", "--output", "json",
                            "--profile", args.profile])
        if rc == 0:
            bump(r, "listable")
            try:
                r["object_count"] = max(r["object_count"],
                                        len(json.loads(out).get("Contents", [])))
            except ValueError:
                pass
            r["evidence"].append("authed(%s) list: OK" % args.profile)
        else:
            r["evidence"].append("authed list: %s" % (err.strip().splitlines() or ["denied"])[0])
        rc, out, _ = run(["aws", "s3api", "get-bucket-acl", "--bucket", name,
                          "--profile", args.profile])
        if rc == 0:
            r["evidence"].append("get-bucket-acl: readable")
            if "AllUsers" in out or "AuthenticatedUsers" in out:
                r["evidence"].append("ACL grants to AllUsers/AuthenticatedUsers")

    if args.write_test:
        key = "probe-poc-%d.txt" % os.getpid()
        st, _ = http(r["url"] + key, method="PUT", data=POC_BODY)
        if st in (200, 201):
            bump(r, "writable")
            r["writable"] = True
            r["anonymous"] = True
            r["evidence"].append("anon PUT %s: HTTP %d (CLEAN UP: s3://%s/%s)" % (key, st, name, key))
        elif shutil.which("aws") and args.profile:
            tmp = "/tmp/probe-poc.txt"
            with open(tmp, "wb") as fh:
                fh.write(POC_BODY)
            rc, _, _ = run(["aws", "s3", "cp", tmp, "s3://%s/%s" % (name, key),
                            "--profile", args.profile])
            if rc == 0:
                bump(r, "writable")
                r["writable"] = True
                r["evidence"].append("authed PUT %s: OK (CLEAN UP)" % key)
    return r


# ---------------- GCS ----------------

def probe_gcs(name, args):
    r = {"name": name, "provider": "gcs", "access": "none", "anonymous": False,
         "writable": False, "object_count": 0,
         "url": "https://storage.googleapis.com/%s/" % name, "evidence": []}
    api = "https://storage.googleapis.com/storage/v1/b/%s" % name
    status, body = http(api + "/o?maxResults=10")
    if status == 404:
        return r
    if status == 200:
        bump(r, "listable")
        r["anonymous"] = True
        try:
            items = json.loads(body).get("items", [])
            r["object_count"] = len(items)
            if items:
                s2, _ = http(r["url"] + urllib.request.quote(items[0]["name"]))
                if s2 == 200:
                    bump(r, "readable")
                    r["evidence"].append("anon read of %s: 200" % items[0]["name"])
        except ValueError:
            pass
        r["evidence"].append("anon list: 200")
    else:
        bump(r, "exists")
        r["evidence"].append("anon list: HTTP %d" % status)

    # anonymous testIamPermissions
    perms = ("storage.objects.list", "storage.objects.get",
             "storage.objects.create", "storage.buckets.setIamPolicy")
    st, body = http(api + "/iam/testPermissions?" +
                    "&".join("permissions=" + p for p in perms))
    if st == 200:
        try:
            held = json.loads(body).get("permissions", [])
        except ValueError:
            held = []
        if held:
            r["anonymous"] = True
            r["evidence"].append("anon testPermissions: " + ",".join(held))
            if "storage.objects.list" in held:
                bump(r, "listable")
            if "storage.objects.get" in held:
                bump(r, "readable")
            if "storage.objects.create" in held:
                bump(r, "writable"); r["writable"] = True
            if "storage.buckets.setIamPolicy" in held:
                bump(r, "admin")

    if r["access"] != "none" and shutil.which("gcloud"):
        rc, out, _ = run(["gcloud", "storage", "ls", "gs://%s" % name])
        if rc == 0:
            bump(r, "listable")
            r["object_count"] = max(r["object_count"], len(out.splitlines()))
            r["evidence"].append("authed gcloud ls: OK")
    if args.write_test and r["access"] != "none" and shutil.which("gcloud"):
        tmp = "/tmp/probe-poc.txt"
        with open(tmp, "wb") as fh:
            fh.write(POC_BODY)
        rc, _, _ = run(["gcloud", "storage", "cp", tmp,
                        "gs://%s/probe-poc.txt" % name])
        if rc == 0:
            bump(r, "writable")
            r["writable"] = True
            r["evidence"].append("authed PUT probe-poc.txt: OK (CLEAN UP)")
    return r


# ---------------- Azure Blob ----------------

def probe_azure(name, args):
    acct = args.account
    base = "https://%s.blob.core.windows.net/%s" % (acct, name)
    r = {"name": "%s/%s" % (acct, name), "provider": "azure", "access": "none",
         "anonymous": False, "writable": False, "object_count": 0,
         "url": base, "evidence": []}
    sas = ("&" + args.sas_token.lstrip("?")) if args.sas_token else ""
    status, body = http(base + "?restype=container&comp=list&maxresults=10" + sas)
    if status == 0 and ("getaddrinfo" in body or "Name or service" in body):
        r["evidence"].append("account DNS does not resolve")
        return r
    if status == 404:
        if "ContainerNotFound" in body:
            r["evidence"].append("account exists, container not found")
        return r
    if status == 200:
        bump(r, "listable")
        r["anonymous"] = not bool(sas)
        r["object_count"] = body.count("<Name>")
        r["evidence"].append("%s list: 200, %d blobs in first page"
                             % ("SAS" if sas else "anon", r["object_count"]))
        m = re.search(r"<Name>([^<]+)</Name>", body)
        if m:
            s2, _ = http(base + "/" + urllib.request.quote(m.group(1)) + ("?" + sas[1:] if sas else ""))
            if s2 == 200:
                bump(r, "readable")
                r["evidence"].append("read of %s: 200" % m.group(1))
    else:
        bump(r, "exists")
        r["evidence"].append("list: HTTP %d (container exists; try blob-level anon reads of known names)" % status)

    if r["access"] != "none" and shutil.which("az") and not sas:
        rc, out, _ = run(["az", "storage", "blob", "list", "--account-name", acct,
                          "-c", name, "--auth-mode", "login", "--num-results", "10",
                          "-o", "json"])
        if rc == 0:
            bump(r, "listable")
            try:
                r["object_count"] = max(r["object_count"], len(json.loads(out)))
            except ValueError:
                pass
            r["evidence"].append("authed (--auth-mode login) list: OK")
    if args.write_test and r["access"] != "none":
        st, _ = http(base + "/probe-poc.txt" + ("?" + sas[1:] if sas else ""),
                     method="PUT", data=POC_BODY)
        # anonymous PUT needs x-ms-blob-type; retry with header via Request
        if st in (201, 400):
            req = urllib.request.Request(
                base + "/probe-poc.txt" + ("?" + sas[1:] if sas else ""),
                data=POC_BODY, method="PUT",
                headers={"x-ms-blob-type": "BlockBlob"})
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    st = resp.status
            except urllib.error.HTTPError as e:
                st = e.code
            except Exception:
                st = 0
        if st == 201:
            bump(r, "writable")
            r["writable"] = True
            r["evidence"].append("PUT probe-poc.txt: 201 (CLEAN UP)")
    return r


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="Probe storage names for anonymous "
                                 "and authenticated access; emit rupu work units.")
    ap.add_argument("--provider", required=True, choices=["s3", "gcs", "azure"])
    ap.add_argument("--names", help="comma-separated bucket/container names")
    ap.add_argument("--names-file", help="file of names, one per line")
    ap.add_argument("--account", help="Azure storage account name (provider=azure: "
                    "names are containers within this account)")
    ap.add_argument("--profile", help="AWS CLI profile for authed S3 probes")
    ap.add_argument("--sas-token", help="Azure SAS token (query string) to probe with")
    ap.add_argument("--write-test", action="store_true",
                    help="attempt PoC object upload (leaves probe-poc*.txt — clean up)")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units JSON array output (default out/work-units.json)")
    ap.add_argument("--assets", help="optional assets JSON output")
    args = ap.parse_args()

    names = []
    if args.names:
        names += [n.strip() for n in args.names.split(",") if n.strip()]
    if args.names_file:
        with open(args.names_file) as fh:
            names += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not names:
        ap.error("provide --names or --names-file")
    if args.provider == "azure" and not args.account:
        ap.error("--account is required for provider=azure")

    probe = {"s3": probe_s3, "gcs": probe_gcs, "azure": probe_azure}[args.provider]
    results = []
    for name in names:
        r = probe(name, args)
        results.append(r)
        if r["access"] != "none":
            print("[%s] %-40s %-9s anon=%s write=%s objs=%s"
                  % (r["provider"], r["name"], r["access"], r["anonymous"],
                     r["writable"], r["object_count"]))

    units, assets = [], []
    for r in results:
        if r["access"] == "none":
            continue
        target = ("s3://" + r["name"] if r["provider"] == "s3" else
                  "gs://" + r["name"] if r["provider"] == "gcs" else r["url"])
        assets.append({"type": "storage-bucket", "id": target,
                       "hints": {"provider": r["provider"], "access": r["access"],
                                 "anonymous": str(r["anonymous"]).lower(),
                                 "writable": str(r["writable"]).lower()}})
        if LEVELS.index(r["access"]) < LEVELS.index("listable"):
            continue  # exists-only: asset, not a work unit
        units.append({
            "id": "%s-%s" % (r["provider"], re.sub(r"[^a-z0-9-]+", "-", r["name"].lower()).strip("-")),
            "title": "%s %s: %s%s" % (r["provider"].upper(), r["name"], r["access"],
                                      " (anonymous)" if r["anonymous"] else ""),
            "targets": [target],
            "hints": {"provider": r["provider"], "access": r["access"],
                      "anonymous": str(r["anonymous"]).lower(),
                      "writable": str(r["writable"]).lower(),
                      "object_count": str(r["object_count"]),
                      "url": r["url"],
                      "evidence": " | ".join(r["evidence"])[:900]},
        })

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(units, fh, indent=2)
    print("[+] %d work units -> %s" % (len(units), args.output))
    if args.assets:
        os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
        with open(args.assets, "w") as fh:
            json.dump(assets, fh, indent=2)
        print("[+] %d assets -> %s" % (len(assets), args.assets))


if __name__ == "__main__":
    main()
