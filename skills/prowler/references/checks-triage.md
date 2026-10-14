# Prowler check → exploit follow-up routing

Map FAILed check ids (`metadata.event_code`) to the concrete next action and the
sibling skill to load. Check-id families below use substring matching — prowler adds
checks constantly, so match on the pattern, not an exact list.

## AWS

| Check id / family | What the FAIL means | Follow-up | Skill |
|---|---|---|---|
| `s3_bucket_public_access`, `s3_bucket_policy_public_write_access`, `s3_bucket_acl_prohibited` | Bucket readable/writable anonymously or by AuthenticatedUsers | `aws s3 ls s3://<bucket> --no-sign-request`; list, pull interesting keys, test anonymous PUT | `cloud-storage-exposure` |
| `ec2_ebs_public_snapshot`, `rds_snapshots_public_access` | Snapshot shared with `all` | Copy snapshot into your account, mount volume / restore DB, loot | `cloud-storage-exposure` |
| `ec2_ami_public` | AMI public | Launch it in your account, mine filesystem for creds | `cloud-storage-exposure` |
| `iam_policy_allows_privilege_escalation`, `iam_policy_with_full_administrative_privileges`, `iam_inline_policy_*_administrative_privileges` | Policy grants `iam:*`, `*:*`, or a known privesc primitive (iam:PassRole+run, CreatePolicyVersion, AttachUserPolicy, UpdateAssumeRolePolicy, ...) | Graph the escalation path, then execute it | `pmapper`, then `pacu` (iam__privesc_scan) |
| `iam_role_cross_account_readonlyaccess_policy`, `iam_role_cross_service_confused_deputy_prevention` | Assumable trust from foreign accounts / confused deputy | `aws sts assume-role` from the trusted side | `pacu` |
| `ec2_securitygroup_allow_ingress_from_internet_to_*` (ssh/rdp/any_port/db ports) | 0.0.0.0/0 → admin/db port | Port-scan the attached public IPs, brute/creds-stuff the service | network-attack tooling via `cloud-security` |
| `ec2_instance_imdsv2_enabled` (FAIL), `ec2_instance_profile_attached` | IMDSv1 reachable + role attached | Any SSRF/RCE on the instance → `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | `metadata-ssrf-pivot` |
| `awslambda_function_url_public`, `awslambda_function_url_cors_policy`, `apigateway*_public`, `apigatewayv2_api_authorizers_enabled` | Unauthenticated invoke endpoint | `curl` the function URL / API stage, fuzz inputs, read env (`awslambda_function_no_secrets_in_variables`) | `cloud-security` |
| `rds_instance_no_public_access` (FAIL), `redshift_cluster_public_access`, `opensearch_service_domains_not_publicly_accessible`, `elasticache_*_public` | Database endpoint on the internet | Resolve endpoint, test default/weak creds, check unauth access (OpenSearch often is) | `cloud-security` |
| `eks_endpoints_not_publicly_accessible`, `eks_control_plane_endpoint_access_restricted` | Public k8s API | `kubectl --server=https://<endpoint>` with stolen token; anonymous enum | `prowler kubernetes` pass + `cloud-security` |
| `cloudtrail_*_enabled` FAILs, `cloudtrail_logs_s3_bucket_access_logging_enabled` | Blind spots in logging | Note for opsec: actions in those regions/services are less observable | — |
| `secretsmanager_*`, `ssm_document_secrets`, `ec2_instance_secrets_user_data`, `cloudformation_stack_outputs_find_secrets` | Secrets in plaintext locations | Pull the secret with current creds, pivot | `pacu` (enum/exfil modules) |
| `organizations_scp_check_deny_regions`, account-level checks | Weak org guardrails | Expansion to member accounts via OrganizationAccountAccessRole | `pacu` |

## Azure

| Check id / family | FAIL means | Follow-up | Skill |
|---|---|---|---|
| `storage_blob_public_access_level_is_disabled`, `storage_*_public` | Anonymous blob/container access | `az storage blob list --container-name <c> --account-name <a> --auth-mode anonymous`; enumerate + download | `cloud-storage-exposure` |
| `keyvault_access_only_through_private_endpoints`, `keyvault_rbac_enabled` (FAIL), broad access-policy checks | Key Vault reachable / loose access policies | `az keyvault secret list --vault-name <v>` with current principal; dump secrets/keys/certs | `cloud-security` |
| `defender_*`, `entra_*_mfa` FAILs, `entra_policy_restricts_user_consent` | Weak identity hardening | Password spray / consent-grant phishing surface; token abuse | `cloud-security` |
| `network_*_rdp_internet`, `network_*_ssh_internet`, `sqlserver_*_firewall` (0.0.0.0) | NSG/firewall open to internet | Scan public IPs, hit the service | `cloud-security` |
| `sqlserver_auditing_enabled` etc. public SQL checks | Public Azure SQL/Postgres/MySQL | Connect, test weak creds | `cloud-security` |
| `vm_*_managed_identity`, app service identity checks | Managed identity attached to exposed compute | RCE/SSRF on the VM/app → `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` (header `Metadata: true`) | `metadata-ssrf-pivot` |
| `aks_*_public`, `app_*_authentication` FAILs | Public AKS API / unauth App Service | kubectl / direct HTTP attack | `cloud-security` |

## GCP

| Check id / family | FAIL means | Follow-up | Skill |
|---|---|---|---|
| `cloudstorage_bucket_public_access` | Bucket IAM has `allUsers`/`allAuthenticatedUsers` | `gsutil ls gs://<bucket>` unauthenticated; download | `cloud-storage-exposure` |
| `iam_sa_*_user_managed_key*`, `iam_role_*` privesc checks | SA keys floating / privesc-capable bindings (iam.serviceAccounts.actAs, setIamPolicy, ...) | Enumerate bindings, impersonate: `gcloud --impersonate-service-account` | `pacu`-equivalent GCP tooling via `cloud-security` |
| `compute_firewall_*_internet_access` (ssh/rdp) | 0.0.0.0/0 firewall rules | Scan external IPs | `cloud-security` |
| `compute_instance_public_ip`, `compute_instance_default_service_account*` | Public VM running as (editor-privileged) default SA | RCE/SSRF → `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (header `Metadata-Flavor: Google`) | `metadata-ssrf-pivot` |
| `cloudsql_instance_public_ip`, `cloudsql_instance_public_access` | Public Cloud SQL | Connect, creds test | `cloud-security` |
| `cloudfunctions_*`/`run_*` public-invoker checks | `allUsers` can invoke | curl the HTTPS trigger, fuzz | `cloud-security` |
| `gke_*` public endpoint / legacy ABAC checks | Public or weakly-authz'd GKE | kubectl attack, then `prowler kubernetes` inside | `cloud-security` |

## Kubernetes

| Check family | FAIL means | Follow-up |
|---|---|---|
| `apiserver_anonymous_requests`, `apiserver_auth_mode_*` | Anonymous / AlwaysAllow API access | `kubectl --token="" get pods -A`; enumerate as system:anonymous |
| `rbac_minimize_wildcard_use_roles`, `rbac_cluster_admin_usage` | Wildcard / cluster-admin bindings | Map which SAs hold them; steal SA tokens from pods |
| `core_minimize_privileged_containers`, `core_minimize_hostPath_*`, `core_minimize_hostPID/hostIPC/hostNetwork` | Container-escape primitives allowed | Deploy/compromise a pod using them → node root |
| `etcd_*` encryption/auth FAILs | etcd readable | Dump secrets straight from etcd |
| `kubelet_*` auth FAILs | Kubelet API open (10250) | `curl -k https://<node>:10250/runningpods/`, exec into containers |

## Severity vs exploitability

Prowler severity is a hygiene rating, not an exploitability rating. A `medium`
`ec2_instance_imdsv2_enabled` FAIL plus any SSRF is a full account compromise; a
`critical` logging FAIL is just opsec intel. Always re-rank by the tables above.
The `parse_prowler.py` exploitable-pattern filter encodes this: pattern-matched
checks are kept at any severity.
