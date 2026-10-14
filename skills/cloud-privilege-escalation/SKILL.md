---
name: cloud-privilege-escalation
description: Cross-cloud IAM privilege-escalation technique catalog for AWS, Azure, and GCP with exact exploit commands per method — the execution reference for paths surfaced by pmapper, pacu, ScoutSuite, Prowler, or manual policy review; use whenever a candidate escalation method/permission has been identified and must be exploited and verified.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Cloud privilege escalation — AWS / Azure / GCP method catalog

This skill is the exploitation layer: scanners and graphers (`pmapper`,
`pacu`, policy review) tell you *which* permission combo a principal holds;
this catalog tells you *exactly how* to turn it into a higher-privileged
principal. Full command detail per method: **references/aws.md**,
**references/azure.md**, **references/gcp.md**.

## Workflow

1. **Ingest candidates** — work-units from `pmapper`/`pacu` (or hand-written
   `{"provider","method","targets"}` entries).
2. **Prioritize** — `python3 scripts/parse_privesc_paths.py -i candidates.json -o out/work-units.json`
   ranks by directness/noise and attaches the exploit command template per method.
3. **Exploit** — run the commands (substitute targets), as the compromised principal.
4. **Verify** — prove the new identity: `aws sts get-caller-identity` /
   `az account show` + `az rest --method GET --url https://graph.microsoft.com/v1.0/me` /
   `gcloud auth list` + a privileged read that previously failed.
5. **Report & loop** — record the escalation via the `finding-report` skill;
   feed the new credentials back to `cloud-credential-enumeration` and re-map
   with `pmapper`/`pacu`. Umbrella: `cloud-security`.

## AWS (the canonical Rhino ~20+ methods — full CLI in references/aws.md)

| have | become/do | gist |
|---|---|---|
| `iam:CreateAccessKey` | any user | `aws iam create-access-key --user-name admin-alice` |
| `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` | any user (console) | set/reset a console password |
| `iam:CreatePolicyVersion` | self→admin | new `*:*` version `--set-as-default` on an attached policy |
| `iam:SetDefaultPolicyVersion` | self→admin | flip back to a fatter old version |
| `iam:AttachUserPolicy`/`AttachRolePolicy`/`AttachGroupPolicy` | self→admin | attach `AdministratorAccess` |
| `iam:PutUserPolicy`/`PutRolePolicy`/`PutGroupPolicy` | self→admin | inline `*:*` policy |
| `iam:AddUserToGroup` | admin group member | join an admin group |
| `iam:UpdateAssumeRolePolicy` (+`sts:AssumeRole`) | any role | rewrite the role's trust to allow you, then assume |
| `sts:AssumeRole` (trusted) | any trusting role | assume directly; chain role→role→role |
| `iam:PassRole` + `ec2:RunInstances` | instance-profile role | boot instance, steal creds from IMDS or user-data revshell |
| `iam:PassRole` + `lambda:CreateFunction` (+Invoke or event) | lambda execution role | function body runs IAM calls as the role |
| `lambda:UpdateFunctionCode` | existing function's role | replace code of a privileged function |
| `iam:PassRole` + `glue:CreateDevEndpoint` / `glue:UpdateDevEndpoint` | glue role | SSH to dev endpoint holding the role |
| `iam:PassRole` + `cloudformation:CreateStack` | cfn service role | stack template creates admin user/keys |
| `iam:PassRole` + `datapipeline:CreatePipeline` | pipeline role | ShellCommandActivity runs CLI as role |
| `iam:PassRole` + `sagemaker:CreateNotebookInstance` | sagemaker role | notebook terminal has the role's creds |
| `iam:PassRole` + `codebuild:CreateProject`+`StartBuild` | build role | buildspec exfils role creds |
| `ssm:SendCommand` / `ssm:StartSession` | any managed instance's role | shell on a box with a strong instance profile |

## Azure (references/azure.md)

| have | become/do | gist |
|---|---|---|
| `Microsoft.Authorization/roleAssignments/write` (Owner/UAA) | Owner anywhere in scope | `az role assignment create --assignee <you> --role Owner --scope /subscriptions/<sub>` |
| `Microsoft.Compute/virtualMachines/runCommand/action` | VM's managed identity | `az vm run-command invoke` → steal IMDS token |
| VM extension write | same | Custom Script Extension payload |
| Key Vault access-policy write / data-plane roles | vault secrets/keys/certs | `az keyvault set-policy` then `az keyvault secret show` |
| Automation account contributor | Run-As / identity of the account | malicious runbook, often SP with high RBAC |
| App/SP **Owner** or `Application.ReadWrite.All` | the service principal | `az ad app credential reset` → login as SP |
| Entra **Global Administrator** | all Azure RBAC | `elevateAccess` → User Access Administrator at root `/` |
| `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` + compute write | any user-assigned identity | attach identity to compute you control |

## GCP (references/gcp.md)

| have | become/do | gist |
|---|---|---|
| `iam.serviceAccounts.actAs` + deploy (compute/functions/run/cloudbuild) | the attached SA | deploy workload, read its token from metadata |
| `iam.serviceAccountKeys.create` | any SA, forever | `gcloud iam service-accounts keys create` |
| `iam.serviceAccounts.getAccessToken` | any SA (1h token) | `gcloud auth print-access-token --impersonate-service-account=...` |
| `iam.serviceAccounts.signJwt` / `signBlob` | any SA | self-sign a token/JWT |
| `iam.serviceAccounts.implicitDelegation` | chain SA→SA | delegated token minting |
| `resourcemanager.projects.setIamPolicy` (or org) | project/org owner | `gcloud projects add-iam-policy-binding ... --role roles/owner` |
| `deploymentmanager.deployments.create` | project default SA (Editor) | deployment runs as the DM service account |
| `cloudbuild.builds.create` | cloudbuild SA | build step exfils SA token |
| `compute.instances.setMetadata` / `osLogin` / `osAdminLogin` | instance's SA | inject SSH key, log in, hit metadata server |

## Choosing the method (priority heuristics)

1. **Direct self-grants** (policy attach/put, setIamPolicy, roleAssignments/write)
   — one API call, instant admin.
2. **Credential minting** (CreateAccessKey, SA keys/tokens, SP secret reset)
   — quiet, durable, no new infrastructure.
3. **Trust manipulation** (UpdateAssumeRolePolicy, elevateAccess) — one call,
   but modifies a visible security boundary.
4. **Deploy-compute paths** (PassRole+EC2/Lambda, actAs+deploy, runCommand)
   — always work when permissions exist but create resources: clean up after
   (delete the function/instance/build) and expect CloudTrail/Activity Log/
   Cloud Audit entries.

## Splitter

```
python3 scripts/parse_privesc_paths.py -i candidates.json -o out/work-units.json --assets out/assets.json
```

Accepts a JSON list of candidates — strings (`"aws:CreateAccessKey"`) or dicts
(`{"provider":"gcp","method":"serviceAccountKeys.create","targets":["deploy-sa@example-prj.iam.gserviceaccount.com"]}`),
including raw work-units from `pmapper`/`pacu` (it reads `hints.method`).
Emits a **prioritized bare JSON array** of exploitation tasks
`{"id","title","targets","hints":{"provider","method","priority","commands"}}`
to `out/work-units.json`. Rupu fan-out/dispatch, `assets.mark`, and
`findings.report` wiring: **references/rupu.md**. Record each confirmed
escalation via the `finding-report` skill, then chain back to
`cloud-credential-enumeration` with the new credentials.
