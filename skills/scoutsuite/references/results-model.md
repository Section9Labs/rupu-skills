# The scoutsuite_results data model

Everything the HTML report shows lives in one file:
`<report-dir>/scoutsuite-results/scoutsuite_results_<provider>-<name>.js`.

## Stripping the JS wrapper

The file is a JavaScript assignment, not JSON:

```
scoutsuite_results =
{"account_id": "123456789012", "provider_code": "aws", ...}
```

Strip through the first `=` and parse the rest:

```python
raw = open(path, encoding="utf-8").read()
data = json.loads(raw[raw.index("=") + 1:])
```

The companion `scoutsuite_exceptions_*.js` wraps the exceptions dict the same way
(`scoutsuite_exceptions =`); it maps `service -> finding_id -> [item paths]` that the
operator chose to suppress — worth reading, suppressed findings are often the ones a
previous assessor already proved exploitable.

## Top level

| Key | Content |
|---|---|
| `provider_code` / `provider_name` | `aws` / `azure` / `gcp` / `aliyun` / `oci` |
| `account_id` | AWS account id (Azure: subscription info under services/subscription metadata; GCP: project ids inside `services.<svc>.projects`) |
| `last_run` | `time`, `version`, `ruleset_name`, `ruleset_about`, and `summary` — per-service `{checked_items, flagged_items, max_level, rules_count, resources_count}` |
| `service_list` | services inventoried on this run |
| `services` | the whole inventory + findings (below) |
| `metadata` | provider display metadata driving the HTML dashboard (service → resource paths, counts) — handy for discovering which collections exist |

`last_run.summary` is the fastest "where is the damage" view: sort services by
`flagged_items` / check `max_level == "danger"`.

## services.<svc>.findings.<finding_id>

Finding ids are rule names like `s3-bucket-world-readable`,
`ec2-security-group-opens-SSH-port-to-all`, `iam-assume-role-policy-allows-all`.

| Field | Meaning |
|---|---|
| `level` | `danger` (red) or `warning` (yellow) |
| `description` | one-line title shown in the dashboard |
| `rationale` | why it is a problem (quote this in findings) |
| `remediation`, `references`, `compliance` | report material |
| `checked_items` / `flagged_items` | evaluated vs failing counts — **skip findings with `flagged_items == 0`** |
| `items` | list of dotted paths to each offending attribute (concrete, one per flagged resource/attribute) |
| `display_path` / `path` | the resource-level path *pattern* with `id` placeholders, e.g. `s3.buckets.id` or `ec2.regions.id.vpcs.id.security_groups.id` |
| `dashboard_name`, `service` | UI grouping |

### From item path to resource id

Item paths descend past the resource into the offending attribute:

```
ec2.regions.us-east-1.vpcs.vpc-0a1b2c3d.security_groups.sg-0d3e4f5a.rules.ingress.protocols.TCP.ports.22.cidrs.0.CIDR
s3.buckets.example-com-backups.grantees.AllUsers.permissions.READ
iam.policies.a1b2c3d4e5.PolicyDocument.Statement.0
```

Truncate each item to the component-depth of `display_path`/`path` to get the
resource identifier (`parse_scoutsuite.py` does exactly this):

```python
depth = len(finding["display_path"].split("."))
resource = ".".join(item.split(".")[:depth])
# -> "ec2.regions.us-east-1.vpcs.vpc-0a1b2c3d.security_groups.sg-0d3e4f5a"
```

### From path to resource object

Walk `data["services"]` with the path components to reach the full model:

```python
def resolve(data, item_path):
    node = data["services"]
    for part in item_path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        else:
            node = node[part]
    return node

sg = resolve(data, "ec2.regions.us-east-1.vpcs.vpc-0a1b2c3d.security_groups.sg-0d3e4f5a")
# sg["name"], sg["rules"]["ingress"], sg["instances"]...
```

## The resource model (recon gold, independent of findings)

Everything ScoutSuite inventoried is under `services.<svc>.<collections>` even when
no rule flagged it. High-value reads:

- **AWS** — `iam.policies.<id>.PolicyDocument` (full JSON policy docs — grep for
  `"Action": "*"`, `iam:PassRole`, `sts:AssumeRole`),
  `iam.roles.<id>.assume_role_policy` (trust relationships → cross-account paths),
  `iam.users.<id>.AccessKeys`, `iam.credential_report`,
  `ec2.regions.<r>.vpcs.<v>.instances.<i>` (`metadata_options` → IMDSv1,
  `iam_instance_profile`, public IP, `user_data` when captured),
  `s3.buckets.<b>` (`grantees`, `policy`, `web_hosting`),
  `rds.regions.<r>.vpcs.<v>.instances.<i>.Endpoint`,
  `awslambda.regions.<r>.functions.<f>` (`env variables`, role).
- **Azure** — `storageaccounts.subscriptions.<sub>.storage_accounts.<sa>`
  (`public_traffic_allowed`, blob containers + `public_access`),
  `keyvault.subscriptions.<sub>.vaults.<v>.access_policies`,
  `network.subscriptions.<sub>.security_groups.<nsg>.security_rules`,
  `rbac.subscriptions.<sub>.roles` / `role_assignments`.
- **GCP** — `cloudstorage.projects.<p>.buckets.<b>.bindings` (`allUsers`!),
  `iam.projects.<p>.bindings` / `service_accounts.<sa>.keys`,
  `computeengine.projects.<p>.zones.<z>.instances.<i>`
  (`service_accounts`, `access_configs` → external IPs, metadata),
  `cloudsql.projects.<p>.instances.<i>.authorized_networks`.

Extraction pattern — dump every IAM policy document:

```python
for pid, pol in data["services"]["iam"]["policies"].items():
    doc = json.dumps(pol.get("PolicyDocument", {}))
    if '"Action": "*"' in doc or "PassRole" in doc:
        print(pid, pol.get("name"), doc[:200])
```

## Dashboard triage recap

report.html home page = services × (resources / rules / flagged). Red (danger)
findings first; a danger finding with few flagged items is usually the sharpest
target (one weird public bucket beats 400 untagged instances). Warnings matching
public/wildcard/cross-account keywords are promoted by `parse_scoutsuite.py`
automatically. The level of each finding comes from the ruleset — with
`--ruleset` you can author rules (JSON conditions over these same paths) to flag
engagement-specific patterns, e.g. trust policies naming an account you control.
