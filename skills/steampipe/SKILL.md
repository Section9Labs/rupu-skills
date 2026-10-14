---
name: steampipe
description: Query live AWS/Azure/GCP APIs as SQL with Steampipe for offensive attack-surface mapping (public buckets, open security groups, weak IAM, exposed databases) and run Powerpipe CIS/NIST benchmarks, then split results into exploit-ready work units.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Steampipe — SQL over live cloud APIs for attack-surface and posture work

Steampipe exposes cloud provider APIs as **PostgreSQL tables**: `select * from
aws_s3_bucket` makes the live API calls behind the scenes. It runs an embedded Postgres;
**plugins** (per-provider) define the table schemas and translate SQL into API calls.
Offensively this means: with any set of read creds you can write precise SQL for exactly
the exposure you're hunting — public storage, 0.0.0.0/0 security groups, admin
principals, exposed databases — across every account/subscription/project at once, and
get JSON out. **Powerpipe** is the companion benchmark runner for CIS/NIST compliance
mods built on the same tables.

Part of the `cloud-security` pack: query → parse → fan out to exploitation skills
(see `references/queries.md` for the full query library, `references/rupu.md` for wiring).

## 1. Setup

```bash
# install (Linux/macOS)
sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
sudo /bin/sh -c "$(curl -fsSL https://powerpipe.io/install/powerpipe.sh)"

steampipe plugin install aws azure gcp
steampipe plugin list
```

Plugins read the normal provider credential chains: AWS env vars / `~/.aws` profiles /
instance roles; Azure CLI login or `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/
`AZURE_CLIENT_SECRET`/`AZURE_SUBSCRIPTION_ID`; GCP ADC or
`GOOGLE_APPLICATION_CREDENTIALS` / `gcloud auth`.

### Connections and aggregators — `~/.steampipe/config/*.spc`

Each plugin install drops a default `.spc`. Define one **connection** per account /
subscription / project, then an **aggregator** connection to query them all as one table:

```hcl
# ~/.steampipe/config/aws.spc
connection "aws_prod" {
  plugin  = "aws"
  profile = "prod"            # ~/.aws profile; or access_key/secret_key/session_token inline
  regions = ["*"]             # all regions — always use this offensively
}
connection "aws_dev" {
  plugin  = "aws"
  profile = "dev"
  regions = ["*"]
}
connection "aws_all" {
  plugin      = "aws"
  type        = "aggregator"
  connections = ["aws_*"]     # wildcard match
}
```

```hcl
# azure.spc — one per subscription          # gcp.spc — one per project
connection "azure_sub1" {                   connection "gcp_proj1" {
  plugin          = "azure"                   plugin  = "gcp"
  subscription_id = "00000000-...-0002"       project = "example-project-123456"
}                                           }
connection "azure_all" {                    connection "gcp_all" {
  plugin      = "azure"                       plugin      = "gcp"
  type        = "aggregator"                  type        = "aggregator"
  connections = ["azure_*"]                   connections = ["gcp_*"]
}                                           }
```

Query the aggregator (`select account_id, name from aws_all.aws_s3_bucket`) to sweep the
whole estate; the first connection alphabetically is also the default search path, so set
`options "database" { search_path_prefix = "aws_all" }` or qualify tables explicitly.
Inspect schemas interactively: `steampipe query` then `.tables`, `.inspect aws_s3_bucket`.

## 2. Querying for attack surface

Two invocation modes — inline SQL and files, always `--output json` for parsing:

```bash
steampipe query "select name, region from aws_s3_bucket where bucket_policy_is_public" --output json
steampipe query scripts/queries/aws_open_sgs.sql --output json > out/aws_open_sgs.json
steampipe query            # interactive psql-style shell (.tables / .inspect / .cache clear)
```

Core offensive queries (full library with explanations in `references/queries.md`):

```sql
-- public S3 buckets
select name, region, account_id from aws_s3_bucket
where bucket_policy_is_public or not block_public_acls or not block_public_policy;

-- security group rules open to the world
select group_id, ip_protocol, from_port, to_port, cidr_ipv4
from aws_vpc_security_group_rule
where not is_egress and (cidr_ipv4 = '0.0.0.0/0' or cidr_ipv6 = '::/0');

-- internet-facing compute / LB / DB
select instance_id, public_ip_address from aws_ec2_instance where public_ip_address is not null;
select name, dns_name from aws_ec2_application_load_balancer where scheme = 'internet-facing';
select db_instance_identifier, endpoint_address from aws_rds_db_instance where publicly_accessible;

-- console users without MFA; keys older than 90 days
select name from aws_iam_user where login_profile is not null and not mfa_enabled;
select user_name, access_key_id, create_date from aws_iam_access_key
where create_date < now() - interval '90 days' and status = 'Active';

-- customer policies granting *:*
select name, arn from aws_iam_policy
where is_attached and exists (
  select 1 from jsonb_array_elements(policy_std -> 'Statement') s
  where s ->> 'Effect' = 'Allow'
    and s -> 'Action' ? '*' and s -> 'Resource' ? '*');

-- GCP: public buckets and world-open firewalls
select name from gcp_storage_bucket, jsonb_array_elements(iam_policy -> 'bindings') b
where b -> 'members' ?| array['allUsers','allAuthenticatedUsers'];
select name, source_ranges, allowed from gcp_compute_firewall
where direction = 'INGRESS' and source_ranges ? '0.0.0.0/0';

-- Azure: open NSG rules and anonymous blob containers
select name, sg.name as nsg from azure_network_security_group sg,
  jsonb_array_elements(security_rules) r
where r -> 'properties' ->> 'access' = 'Allow'
  and r -> 'properties' ->> 'direction' = 'Inbound'
  and r -> 'properties' ->> 'sourceAddressPrefix' in ('*','0.0.0.0/0','Internet');
select name, account_name from azure_storage_container where public_access <> 'None';
```

JSON columns (`policy_std`, `security_rules`, `iam_policy`) are first-class — use
Postgres `jsonb` operators (`->`, `->>`, `?`, `?|`, `jsonb_array_elements`) to dig into
policies. **Join tables** for kill-chain queries, e.g. instance ↔ open SG ↔ instance
profile role to find "public box with an admin role" in one statement
(see `references/queries.md` §Chains).

## 3. Benchmarks and compliance — Powerpipe

Powerpipe runs **mods** (packaged controls/benchmarks) against the Steampipe database:

```bash
mkdir pipes && cd pipes
powerpipe mod init
powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance
powerpipe mod install github.com/turbot/steampipe-mod-azure-compliance
powerpipe mod install github.com/turbot/steampipe-mod-gcp-compliance

steampipe service start          # powerpipe connects to steampipe's Postgres

powerpipe benchmark list
powerpipe benchmark run aws_compliance.benchmark.cis_v300 --output json > out/cis.json
powerpipe benchmark run aws_compliance.benchmark.cis_v300_2_1   # one CIS section
powerpipe control run aws_compliance.control.cis_v300_5_2 --output json
powerpipe benchmark run aws_compliance.benchmark.cis_v300 --export out/cis.html  # report
```

Benchmark JSON nests `groups` → `controls` → `results`, each result having `status`
(`alarm`|`ok`|`info`|`skip`|`error`), `resource`, `reason`, `dimensions` (account_id,
region). **`alarm` = your FAIL list.** Also useful: `steampipe-mod-aws-insights` /
`-perimeter` mods and NIST/PCI benchmarks inside the compliance mods
(`powerpipe benchmark run aws_compliance.benchmark.nist_800_53_rev_5`).

> Older Steampipe (<0.22) bundled this as `steampipe check all` /
> `steampipe check benchmark.cis_v150 --output json` with mods installed via
> `steampipe mod install`. Same mods, same output shape; use `steampipe check` only on
> legacy installs.

## 4. Scripted sweep + parse (handoff)

The skill ships `scripts/queries/` — ready attack-surface `.sql` files across all three
providers (public buckets, open SGs/NSGs/firewalls, admin principals, stale keys, public
DBs/compute). Run them all and split the rows:

```bash
# run every bundled query (or --provider aws, or --query aws_public_s3)
python3 scripts/run_steampipe_queries.py --queries-dir scripts/queries \
    --out-dir out/queries --provider aws azure gcp

# rows -> work units + assets
python3 scripts/parse_steampipe.py out/queries \
    --out out/work-units.json --assets out/assets.json
```

`run_steampipe_queries.py` executes each `.sql` via `steampipe query <file> --output json`
and saves one `<query_name>.json` of rows per query. `parse_steampipe.py` extracts
resource identifiers from the rows (arn/id/name/url columns), groups by query, and writes
`out/work-units.json` — a **bare JSON array** of `{"id","title","targets","hints"}` units
with `hints = {query_name, provider, columns, rows}` — plus `out/assets.json`.

**Handoff:** every parse step ends with `out/work-units.json`. Wire it into rupu
(`for_each`/`dispatch`, `assets.mark`, `findings.report`) per `references/rupu.md`.
Route units to sibling skills by query family — storage queries →
`cloud-storage-exposure` (then `trufflehog` on the loot), open-SG/NSG/firewall →
`cloudfox` / the provider enumeration skills (`aws-enumeration`, `azure-enumeration`,
`gcp-enumeration`) for endpoint detail, IAM/admin-key → `pmapper` /
`cloud-privilege-escalation` / `pacu`, Entra weaknesses → `azure-entra-id` — and
cross-check posture against the `cloudsploit` and `prowler` skills. Chain back to the
`cloud-security` umbrella skill for the engagement flow.
