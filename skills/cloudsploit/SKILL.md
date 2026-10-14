---
name: cloudsploit
description: Run Aqua's open-source CloudSploit scanner (Node, aquasecurity/cloudsploit) against AWS, Azure, GCP and OCI to enumerate misconfigurations, parse the JSON results, and split FAIL findings into exploit-ready work units for follow-up attacks.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# CloudSploit — multi-cloud misconfiguration scanning for offensive posture work

CloudSploit is Aqua Security's open-source cloud security posture scanner. It is a Node.js
CLI (`index.js`, aliased as `./scan` in older docs) with hundreds of **plugins** — one
per-service check each (e.g. `s3BucketAllUsersPolicy`, `openSSH`, `sqlServerPublicAccess`).
It collects raw cloud API data once per run, evaluates every plugin against that collection,
and emits per-resource results. Offensively, it is a fast way to turn a stolen/granted set
of cloud credentials into a prioritized list of exploitable misconfigurations: public
storage, world-open security groups, weak IAM, unencrypted and shareable snapshots.

This skill is part of the `cloud-security` pack. Scan → parse → fan out findings to the
sibling exploitation skills (see `references/plugins-triage.md` and `references/rupu.md`).

## 1. Setup

```bash
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install
chmod +x index.js
./index.js -h          # full flag reference
```

Node 14+ required. The scanner is read-only against the cloud APIs: it only needs
list/describe/get permissions (AWS `SecurityAudit` managed policy is sufficient; equivalent
Reader roles on Azure/GCP/OCI).

### Credentials — config.js

Copy and edit the shipped template:

```bash
cp config_example.js config.js
```

`config.js` exports a `credentials` object; fill in only the clouds you have keys for:

```javascript
module.exports = {
    credentials: {
        aws: {
            access_key: 'AKIAEXAMPLEKEYID',
            secret_access_key: 'examplesecretkey',
            session_token: '',            // set for STS/temporary creds
            plugins_remediate: []
        },
        azure: {
            application_id: '00000000-0000-0000-0000-000000000000',   // app (client) ID
            key_value: 'client-secret-value',                          // KeyValue
            directory_id: '00000000-0000-0000-0000-000000000001',      // tenant / DirectoryID
            subscription_id: '00000000-0000-0000-0000-000000000002'
        },
        google: {
            project: 'example-project-123456',
            client_email: 'scanner@example-project-123456.iam.gserviceaccount.com',
            private_key: '-----BEGIN PRIVATE KEY-----\n...'
            // or: credential_file: '/path/to/service-account.json'
        },
        oracle: {
            tenancy_id: 'ocid1.tenancy.oc1..example',
            compartment_id: 'ocid1.compartment.oc1..example',
            user_id: 'ocid1.user.oc1..example',
            key_fingerprint: 'aa:bb:cc:...',
            key_value: '-----BEGIN RSA PRIVATE KEY-----\n...'
        }
    }
};
```

Each credential field also supports **environment-variable indirection** and
**file indirection** in config.js:

```javascript
access_key: process.env.AWS_ACCESS_KEY_ID,
secret_access_key: process.env.AWS_SECRET_ACCESS_KEY,
// or point at a file containing the secret:
key_value: { 'file': '/path/to/azure-client-secret' }
```

With no `--config` at all, the AWS collector falls back to the default SDK credential
chain — `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` env vars,
`~/.aws/credentials`, or an instance/task role. That makes CloudSploit trivially usable
from any foothold that already has ambient AWS creds (EC2 metadata creds, CI runners).

### Cross-account AWS role

For scanning other accounts in an org from one set of keys, create/assume a role
(trust policy allowing your principal, `SecurityAudit` attached, optionally an ExternalId)
and feed CloudSploit the resulting STS keys as `access_key`/`secret_access_key`/
`session_token`. Loop over accounts by re-running with each assumed-role credential set —
`scripts/run_cloudsploit.py` takes `--config` per run so you can template one config per
account.

## 2. Running scans

Canonical full run, machine-readable output, console noise off:

```bash
./index.js --config ./config.js --console none --json ./out/cloudsploit.json
```

Key flags (all documented in `./index.js -h`):

| Flag | Use |
|---|---|
| `--config <path>` | credentials file (omit to use env/default AWS chain) |
| `--json <file>` | write results as a JSON array — always set this |
| `--csv <file>` | CSV output if you want spreadsheets |
| `--console none\|text\|table` | terminal output format; `none` for scripted runs |
| `--plugin <name>` | run a single plugin, e.g. `--plugin s3BucketAllUsersPolicy` |
| `--compliance <program>` | restrict to a compliance mapping: `hipaa`, `pci`, `cis`, `cis1`, `cis2` (`--compliance=cis` form also accepted; repeatable) |
| `--govcloud` / `--china` | AWS partition selection |
| `--collection <file>` | **save** the raw API collection to a file |
| `--ignore-ok` | suppress PASS results — only WARN/FAIL/UNKNOWN in output |
| `--exit-code` | nonzero exit status when any FAIL exists (CI/loop-friendly) |
| `--cloud aws\|azure\|google\|oracle` | limit which cloud(s) to collect/scan |

**Collections are gold.** `--collection out/collection.json` persists every raw API
response the collector gathered (all buckets, users, groups, instances, snapshots, keys —
far more than the pass/fail results show). Reuse it to re-run plugins without touching the
API again, and mine it directly for enumeration data (IAM principal lists, instance IPs,
bucket names) that feeds other skills.

Compliance-scoped runs when you want CIS/PCI-mapped evidence or a smaller plugin set:

```bash
./index.js --config ./config.js --compliance cis --console table --json out/cis.json
./index.js --config ./config.js --compliance pci --compliance hipaa --json out/pci-hipaa.json
```

Single-plugin iteration while chasing one issue:

```bash
./index.js --config ./config.js --plugin ec2OpenAllPortsPublic --console table
```

### Plugins and extensibility

Each check lives in `plugins/<cloud>/<service>/<plugin>.js` and declares the API calls it
needs plus a `run()` that emits results per resource. The project is plugin-extensible:
copy an existing plugin, change the `apis` list and logic, drop it in the tree, and it is
picked up automatically — useful for engagement-specific checks (e.g. flag any role
trusting an external account ID). `exports.js` indexes plugin names if you need the
authoritative list; `grep -r "exports.title" plugins/aws/` is a quick catalog.

## 3. Reading output

`--json` emits a JSON array; each element:

```json
{
  "plugin": "s3BucketAllUsersPolicy",
  "category": "S3",
  "title": "S3 Bucket All Users Policy",
  "description": "Ensures S3 bucket policies do not allow global write/delete/read",
  "resource": "arn:aws:s3:::example-public-bucket",
  "region": "us-east-1",
  "status": "FAIL",
  "message": "Bucket policy allows global read access"
}
```

Status semantics (numeric codes 0–3 internally; the JSON writes the words):

| Code | Status | Meaning |
|---|---|---|
| 0 | OK | check passed |
| 1 | WARN | risky but not definitively broken |
| 2 | FAIL | misconfiguration confirmed — your attack list |
| 3 | UNKNOWN | collection error / insufficient permission — note as blind spots |

Triage order for FAILs — exploitability first, not severity labels:

1. **Public resources** — public S3/GCS/blob buckets and objects, public AMIs, public
   EBS/RDS snapshots, public SQL/RDS endpoints: direct data access, often unauthenticated.
2. **Open network ports** — `open*` plugins (openSSH, openRDP, openAllPortsPublic, NSG
   open rules, GCP firewall 0.0.0.0/0): hand targets to network exploitation.
3. **Weak IAM** — admin `*:*` policies, users without MFA, stale access keys, root key
   usage, over-broad trust policies: privilege-escalation paths from the creds you hold.
4. **Unencrypted / shareable data** — unencrypted volumes and snapshots that can be
   copied or shared cross-account for offline looting.

`UNKNOWN` across a whole category usually means the scanning principal lacks that
service's read permission — record it; the gap itself is intel about the role.

## 4. Scripted run + parse (handoff)

```bash
# run the scanner and keep raw results + collection
python3 scripts/run_cloudsploit.py \
    --cloudsploit-dir ./cloudsploit --config ./config.js \
    --json out/cloudsploit.json --collection out/collection.json

# or re-parse an existing results file without running node
python3 scripts/run_cloudsploit.py --skip-run --json out/cloudsploit.json

# split FAILs (and optionally WARNs) into rupu work units + asset list
python3 scripts/parse_cloudsploit.py out/cloudsploit.json \
    --out out/work-units.json --assets out/assets.json --include-warn
```

`parse_cloudsploit.py` groups results by plugin, deduplicates resources, and writes
`out/work-units.json` — a **bare JSON array** of
`{"id","title","targets","hints"}` units where `targets` are the failing resource
ARNs/IDs and `hints` carry `{plugin, category, region, status, message}`. It also writes
`out/assets.json` listing every distinct resource seen (including passing ones, for
coverage marking).

**Handoff:** each parse ends with `out/work-units.json`. Wire it into rupu
(`for_each`/`dispatch`, `assets.mark`, `findings.report`) exactly as documented in
`references/rupu.md`. Map each unit's plugin category to the exploitation step and the
sibling skill named in `references/plugins-triage.md`, and chain back to the
`cloud-security` umbrella skill for the overall engagement flow.
