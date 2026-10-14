# Offensive Steampipe query library

Extended SQL for attack-surface and privesc hunting, grouped by provider. All queries run
via `steampipe query file.sql --output json` or inline. Table schemas:
`steampipe query` → `.inspect <table>`, or hub.steampipe.io/plugins. JSON policy columns
use Postgres `jsonb` operators: `->` (get), `->>` (get as text), `?` (key/element exists),
`?|` (any of), `@>` (contains), `jsonb_array_elements`.

The `*_std` policy columns (e.g. `policy_std`, `assume_role_policy_std`) are normalized —
actions lowercased, Statement always an array — so string matching is reliable.

## AWS

### Storage and data exposure

```sql
-- buckets with a policy statement granting Principal "*"
select name, arn, s ->> 'Action' as actions
from aws_s3_bucket, jsonb_array_elements(policy_std -> 'Statement') s
where s ->> 'Effect' = 'Allow'
  and (s -> 'Principal' ->> 'AWS' = '*' or s ->> 'Principal' = '*');

-- public EBS snapshots (restore cross-account, mount, loot)
select snapshot_id, volume_size, encrypted, region, account_id
from aws_ebs_snapshot
where create_volume_permissions @> '[{"Group":"all"}]';

-- public AMIs owned by the target
select image_id, name, region from aws_ec2_ami where public;

-- EFS file systems with wide-open policies
select name, arn from aws_efs_file_system
where policy_std is null or policy_std::text like '%"Principal":"*"%';
```

### Network exposure

```sql
-- SGs open to the world on sensitive ports, joined to the instances using them
select i.instance_id, i.public_ip_address, r.from_port, r.to_port, r.group_id
from aws_vpc_security_group_rule r
join aws_ec2_instance i
  on i.security_groups @> jsonb_build_array(jsonb_build_object('GroupId', r.group_id))
where not r.is_egress and r.cidr_ipv4 = '0.0.0.0/0'
  and i.public_ip_address is not null;

-- internet-facing anything: ELBv2, classic ELB, API Gateway, CloudFront origins
select name, dns_name from aws_ec2_application_load_balancer where scheme = 'internet-facing';
select name, dns_name from aws_ec2_classic_load_balancer where scheme = 'internet-facing';
select name, api_endpoint from aws_api_gatewayv2_api;
select id, domain_name, origins from aws_cloudfront_distribution;

-- public ElasticSearch/OpenSearch domains
select domain_name, endpoint from aws_opensearch_domain where vpc_options is null;
```

### IAM privesc hunting

```sql
-- roles assumable by ANY AWS principal (cross-account backdoors / confused deputy)
select name, arn, s -> 'Principal' ->> 'AWS' as trusts
from aws_iam_role, jsonb_array_elements(assume_role_policy_std -> 'Statement') s
where s ->> 'Effect' = 'Allow'
  and (s -> 'Principal' ->> 'AWS' = '*'
       or s -> 'Principal' ->> 'AWS' not like '%' || account_id || '%');

-- classic privesc primitives in attached policies
select p.name, p.arn, a as action
from aws_iam_policy p,
     jsonb_array_elements(p.policy_std -> 'Statement') s,
     jsonb_array_elements_text(s -> 'Action') a
where p.is_attached and s ->> 'Effect' = 'Allow'
  and a in ('iam:passrole','iam:createpolicyversion','iam:setdefaultpolicyversion',
            'iam:attachuserpolicy','iam:attachrolepolicy','iam:putuserpolicy',
            'iam:putrolepolicy','iam:createaccesskey','iam:createloginprofile',
            'iam:updateloginprofile','iam:updateassumerolepolicy',
            'sts:assumerole','lambda:updatefunctioncode');

-- who can read secrets
select p.name, a from aws_iam_policy p,
  jsonb_array_elements(p.policy_std -> 'Statement') s,
  jsonb_array_elements_text(s -> 'Action') a
where p.is_attached and s ->> 'Effect' = 'Allow'
  and a in ('secretsmanager:getsecretvalue','ssm:getparameter','ssm:getparameters',
            'ssm:getparametersbypath','kms:decrypt','*');

-- credential report: root key usage, password/key ages, MFA — one table
select user_name, password_enabled, mfa_active,
       access_key_1_active, access_key_1_last_rotated
from aws_iam_credential_report;
```

### Chains (joins that find the kill chain in one query)

```sql
-- public instance + instance-profile role with AdministratorAccess
select i.instance_id, i.public_ip_address, r.name as role_name
from aws_ec2_instance i
join aws_iam_role r
  on r.instance_profile_arns ? i.iam_instance_profile_arn
where i.public_ip_address is not null
  and r.attached_policy_arns ? 'arn:aws:iam::aws:policy/AdministratorAccess';

-- Lambda functions whose role can PassRole (SSRF/injection → privesc)
select f.name, f.role, r.attached_policy_arns
from aws_lambda_function f
join aws_iam_role r on r.arn = f.role
where r.attached_policy_arns::text ilike '%admin%';

-- secrets hiding in EC2 user data (base64 in launch config)
select instance_id, user_data from aws_ec2_instance
where user_data is not null
  and (user_data ilike '%password%' or user_data ilike '%secret%'
       or user_data ilike '%aws_access_key%' or user_data ilike '%token%');
```

## Azure

```sql
-- anonymous blob containers
select name, account_name, public_access, resource_group, subscription_id
from azure_storage_container where public_access <> 'None';

-- storage accounts allowing public blob access + plain HTTP
select name, allow_blob_public_access, enable_https_traffic_only
from azure_storage_account
where allow_blob_public_access or not enable_https_traffic_only;

-- NSG rules open to Internet (see scripts/queries/azure_open_nsgs.sql)
-- VMs with public IPs
select name, public_ips, resource_group from azure_compute_virtual_machine
where jsonb_array_length(coalesce(public_ips, '[]'::jsonb)) > 0;

-- SQL servers open to all (0.0.0.0 firewall start = AllowAllWindowsAzureIps or world)
select s.name, r -> 'properties' ->> 'startIpAddress' as from_ip,
       r -> 'properties' ->> 'endIpAddress' as to_ip
from azure_sql_server s, jsonb_array_elements(firewall_rules) r
where (r -> 'properties' ->> 'startIpAddress') = '0.0.0.0';

-- Key Vaults with wide access policies / no RBAC
select name, enable_rbac_authorization, access_policies from azure_key_vault
where not coalesce(enable_rbac_authorization, false);

-- role assignments granting Owner/Contributor at subscription scope
select a.principal_id, d.role_name, a.scope
from azure_role_assignment a
join azure_role_definition d on d.id = a.role_definition_id
where d.role_name in ('Owner','Contributor','User Access Administrator')
  and a.scope like '/subscriptions/%' and a.scope not like '%/resourceGroups/%';

-- Entra users without MFA registered (azuread plugin: steampipe plugin install azuread)
select display_name, user_principal_name from azuread_user where account_enabled;
```

## GCP

```sql
-- public buckets (bindings to allUsers/allAuthenticatedUsers)
select b.name, binding ->> 'role' as role
from gcp_storage_bucket b, jsonb_array_elements(iam_policy -> 'bindings') binding
where binding -> 'members' ?| array['allUsers','allAuthenticatedUsers'];

-- project-level IAM: who is owner/editor; external members
select entity, role from gcp_iam_policy p,
  jsonb_array_elements(p.bindings) b,
  jsonb_array_elements_text(b -> 'members') entity,
  lateral (select b ->> 'role' as role) r
where b ->> 'role' in ('roles/owner','roles/editor','roles/iam.serviceAccountTokenCreator');

-- firewall 0.0.0.0/0 + the instances tagged into those rules
select f.name as fw, f.allowed, i.name as instance,
       nic -> 'accessConfigs' -> 0 ->> 'natIP' as external_ip
from gcp_compute_firewall f
join gcp_compute_instance i on (f.target_tags is null or i.tags -> 'items' ?| 
     (select array_agg(t) from jsonb_array_elements_text(f.target_tags) t))
join lateral jsonb_array_elements(i.network_interfaces) nic on true
where f.direction = 'INGRESS' and not f.disabled and f.source_ranges ? '0.0.0.0/0';

-- instances running as default compute SA with full cloud-platform scope
select name, sa ->> 'email' as sa_email, sa -> 'scopes' as scopes
from gcp_compute_instance, jsonb_array_elements(service_accounts) sa
where sa ->> 'email' like '%-compute@developer.gserviceaccount.com'
  and sa -> 'scopes' ? 'https://www.googleapis.com/auth/cloud-platform';

-- user-managed SA keys (exportable long-lived creds)
select service_account_name, name, valid_after_time
from gcp_service_account_key where key_type = 'USER_MANAGED';

-- Cloud SQL open to the world / public IP
select name, database_version, ip_addresses from gcp_sql_database_instance i,
  jsonb_array_elements(ip_configuration -> 'authorizedNetworks') net
where net ->> 'value' = '0.0.0.0/0';

-- Cloud Functions / Run invokable by allUsers
select name from gcp_cloudfunctions_function f,
  jsonb_array_elements(iam_policy -> 'bindings') b
where b -> 'members' ? 'allUsers';
```

## Cross-provider sweep patterns

- Prefix tables with an aggregator (`aws_all.aws_s3_bucket`) or set
  `--search-path-prefix aws_all` to hit every account in one query; `account_id` /
  `subscription_id` / `project` columns attribute each row.
- `_ctx ->> 'connection_name'` on any row tells you which connection produced it.
- Steampipe caches API responses (default 5 min); `.cache clear` in the shell when
  re-querying after making changes.
- `select * from steampipe_connection` lists configured connections — quick credential
  inventory of what the foothold can see.

## Follow-up routing (query family → sibling skill)

| Query family | Hand off to |
|---|---|
| public buckets/blobs/snapshots/AMIs | `cloud-storage-exposure`; `pacu` for snapshot restore; `trufflehog` on the loot |
| open SG/NSG/firewall, public IPs/LBs | `cloudfox`, `aws-enumeration` / `azure-enumeration` / `gcp-enumeration` for endpoint detail, then the `cloud-security` exposure flow |
| admin policies, PassRole, wildcard trust, SA keys | `pmapper` (AWS graph), `cloud-privilege-escalation`, `pacu` |
| no-MFA users, stale keys, credential report | `cloud-credential-enumeration`, `azure-entra-id` (Entra spraying) |
| public RDS/SQL/OpenSearch | direct attack; `pacu` rds modules |
| user_data secrets, Key Vault, Secrets Manager | `trufflehog` (native secret stores) |
| default-SA instances with cloud-platform scope | `metadata-ssrf-pivot` |
