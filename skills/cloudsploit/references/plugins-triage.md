# CloudSploit plugin categories → exploit follow-up

Triage map from the `category` / `plugin` fields of FAIL results to the concrete attack
step and the sibling skill (from the `cloud-security` pack) that executes it. Work units
carry the category in `hints.category`, so a lead agent can route units straight off this
table.

## AWS

| Category / plugins | What a FAIL means | Follow-up | Hand off to |
|---|---|---|---|
| **S3** — `s3BucketAllUsersPolicy`, `s3BucketAllUsersAcl`, `bucketPublicAccessBlock`, `s3BucketWebsiteEnabled` | Bucket readable/writable to AllUsers or AuthenticatedUsers | `aws s3 ls s3://<bucket> --no-sign-request`, pull objects, test anonymous PUT (`echo x > poc; aws s3 cp poc s3://<bucket>/ --no-sign-request`); writable buckets backing websites → stored content injection | `cloud-storage-exposure`; run `trufflehog` over pulled objects |
| **EC2** — `openSSH`, `openRDP`, `openAllPortsPublic`, `ec2OpenCustomPorts`, `publicAmi` | Security group world-open; AMI shared publicly | Collect public IPs from the saved `--collection`, port-scan and attack the exposed services; copy public AMIs into your account and mount for secrets (`aws ec2 copy-image`) | `cloudfox` (endpoint/instance map), then the `cloud-security` exposure flow |
| **EC2 snapshots / EBS** — `ebsSnapshotPublic`, `ebsEncryptionEnabled` | Snapshot public or shareable, volumes unencrypted | `aws ec2 describe-snapshot-attribute`, copy snapshot cross-account, create volume, mount, loot `/etc/shadow`, app configs, keys | `pacu` (`ebs__download_snapshots`) |
| **RDS** — `rdsPubliclyAccessible`, `rdsSnapshotPublic`, `rdsEncryptionEnabled` | DB endpoint internet-reachable or snapshot public | Resolve endpoint, test default/bruteforce creds; restore public snapshots into your account and dump | `pacu` (rds modules) |
| **IAM** — `iamUserAdmins`, `usersMfaEnabled`, `accessKeysLastUsed`, `accessKeysRotated`, `rootAccessKeys`, `iamRolePolicies`, `crossAccountAccess` | Admin `*:*` policies, console users with no MFA, stale keys, over-broad trust policies | Enumerate the exact policy docs, map privesc chains (iam:PassRole, iam:CreatePolicyVersion, sts:AssumeRole on wildcard trust); password-spray no-MFA console users | `pmapper` (IAM graph), `cloud-privilege-escalation`, `pacu` |
| **Lambda / API Gateway** — `lambdaPublicAccess`, `openApiGateway` | Function/API invokable anonymously | Invoke, fuzz input, look for SSRF/injection into the execution role's creds | `pacu` (lambda modules), `metadata-ssrf-pivot` |
| **KMS / Secrets** — `kmsKeyPolicy`, `secretsManager*` | Key policy grants wide decrypt; secrets unrotated | Attempt `kms:Decrypt`/`secretsmanager:GetSecretValue` with current principal | `trufflehog` (native secret stores) |
| **CloudTrail / Config / GuardDuty** — `cloudtrailEnabled`, `guarddutyEnabled` | Logging/detection gaps per region | Not exploitable directly — note which regions are blind for noisy follow-up actions | (opsec note) |
| **ElasticSearch / Redshift / SQS / SNS** — `esHttpsOnly`, `openElasticsearch`, `sqsPublicAccess`, `snsTopicPolicies` | Service endpoint or topic/queue policy public | Query ES indices unauthenticated; publish/subscribe to open topics/queues | `aws-enumeration` for full endpoint detail, then direct attack |

## Azure

| Category / plugins | FAIL means | Follow-up | Hand off |
|---|---|---|---|
| **Blob Service / Storage Accounts** — `blobContainerPrivateAccess`, `storageAccountsHttps` | Container access level Blob/Container (anonymous) | `https://<account>.blob.core.windows.net/<container>?restype=container&comp=list`, download blobs | `cloud-storage-exposure`, then `trufflehog` on the loot |
| **Network Security Groups** — `openSSH`, `openRDP`, `openAllPorts` (azure tree) | NSG inbound rule from `*`/`0.0.0.0/0`/`Internet` | Map rule → attached NIC/subnet → public IP (via `azure-enumeration`); attack the exposed service | `azure-enumeration`, `cloud-security` exposure flow |
| **SQL / PostgreSQL / MySQL servers** — `sqlServerPublicAccess`, firewall `0.0.0.0` start/end rules | DB firewall open to all of Azure or internet | Connect to `<server>.database.windows.net`, bruteforce SQL auth | direct attack; `azure-enumeration` for endpoint detail |
| **Active Directory / Entra** — guest access, legacy auth plugins | Weak tenant auth posture | Password spray, device-code phishing against no-MFA users | `azure-entra-id` |
| **Key Vaults** — access-policy plugins | Over-broad vault policies | `az keyvault secret list/show` as current principal | `trufflehog` (native secret stores) |

## GCP

| Category / plugins | FAIL means | Follow-up | Hand off |
|---|---|---|---|
| **Storage** — `bucketAllUsersPolicy` | `allUsers`/`allAuthenticatedUsers` on bucket IAM | `gsutil ls gs://<bucket>` unauthenticated; test write | `cloud-storage-exposure` |
| **VPC Network** — `openSSH`, `openRDP`, `openAllPorts`, `defaultVpcInUse` | Firewall rule source `0.0.0.0/0` | Map rule target tags → instances → external IPs; attack services | `gcp-enumeration`, `cloud-security` exposure flow |
| **IAM** — `serviceAccountAdmin`, `serviceAccountKeyRotation`, `corporateEmailsOnly` | SAs with owner/editor, stale user-managed keys | Enumerate `iam.serviceAccounts.getAccessToken` / `actAs` privesc paths; stale keys = long-lived creds to steal | `cloud-privilege-escalation`, `gcp-enumeration` |
| **SQL** — `dbPubliclyAccessible`, `dbSSLEnabled` | Cloud SQL with public IP / authorized network 0.0.0.0/0 | Connect and bruteforce | direct attack |
| **Compute** — `instancePublicAccess`, `instanceDefaultServiceAccount`, `osLoginEnabled` | Instances with external IPs on default SA (often editor) | SSRF/compromise of instance → metadata token → project-wide editor | `metadata-ssrf-pivot` |

## OCI

| Category | FAIL means | Follow-up |
|---|---|---|
| **Object Store** — public buckets | Anonymous bucket access | List/pull via `https://objectstorage.<region>.oraclecloud.com/n/<ns>/b/<bucket>/o/` |
| **Networking** — security list `0.0.0.0/0` ingress | World-open ports | Standard network exposure flow |
| **Identity** — policy/API-key plugins | Over-broad policies, stale API keys | Map `manage all-resources` grants, test key reuse |

## General triage rules

1. Work **FAIL** units in this order: public data (S3/Blob/GCS, snapshots) → open network
   (SG/NSG/firewall) → IAM privesc → everything else.
2. Pair every unit with the raw `--collection` file: the collection contains the resource
   detail (IPs, policy documents, principal lists) the result row only hints at.
3. **UNKNOWN** clusters mark services the scanning principal can't read — record them as
   enumeration gaps and retry with a stronger principal after privesc.
4. Cross-check against `steampipe` (live SQL answers the "which exact resources / what
   are the IPs" questions), `prowler` and `scoutsuite` for scanner consensus.
5. Chain results back into the `cloud-security` umbrella skill's engagement flow.
