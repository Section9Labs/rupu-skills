---
name: scoutsuite
description: Run and triage ScoutSuite (NCC Group `scout` CLI) multi-cloud audits across AWS, Azure and GCP (plus Aliyun/OCI) — authenticate per provider, generate the HTML report, parse scoutsuite_results JS into danger/warning findings, and emit flagged resources as rupu work units for exploitation.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# ScoutSuite — multi-cloud audit for offensive triage

ScoutSuite pulls a full read-only inventory of a cloud environment, runs a ruleset
over it, and renders an offline HTML report. Offensively it gives you two things
Prowler doesn't: a browsable **resource model of the whole estate** (every SG rule,
bucket ACL, IAM policy document, in one JSON blob) and a second, independent rule
engine to cross-check findings. Umbrella skill: `cloud-security`. Peer: `prowler`.

## 1. Install & providers

```bash
pipx install scoutsuite        # or: pip install scoutsuite
scout --help                   # providers: aws, azure, gcp, aliyun, oci
```

`aliyun` and `oci` exist with the same pattern (`--access-keys`, `--config-file`);
coverage is thinner — use them when those estates show up, same parsing applies.

## 2. Run per provider

### AWS
```bash
scout aws --profile target --report-dir ./out/scout --no-browser
scout aws                                           # env creds / default chain
scout aws --access-keys --access-key-id AKIA... --secret-access-key ... --session-token ...
scout aws --profile target --regions us-east-1 eu-west-1     # region scope
scout aws --profile target --services s3 iam ec2 rds lambda  # service scope
scout aws --profile target --skip-services cloudtrail config # or skip noisy ones
```
Needs `ReadOnlyAccess`-equivalent; partial creds degrade gracefully (errors logged,
inventory continues).

### Azure
```bash
scout azure --cli --report-dir ./out/scout --no-browser       # reuse `az login`
scout azure --user-account                                    # interactive login
scout azure --service-principal --tenant-id 00000000-0000-0000-0000-000000000000 \
    --client-id <app-id> --client-secret <secret>
scout azure --msi                                             # managed identity (from Azure compute)
scout azure --cli --subscription-ids SUB-ID-1 SUB-ID-2        # or --all-subscriptions
```

### GCP
```bash
scout gcp --service-account ./sa.json --project-id proj-example-1 \
    --report-dir ./out/scout --no-browser
scout gcp --user-account --all-projects                       # ADC creds, every visible project
scout gcp --service-account ./sa.json --organization-id 123456789012
scout gcp --service-account ./sa.json --folder-id 987654321098
```

### Universal knobs
```bash
--report-dir ./out/scout      # where report.html + scoutsuite-results/ land
--report-name target-aws      # filename stem (default embeds account/sub/project id)
--no-browser                  # don't auto-open report (always use in automation)
--force                       # overwrite an existing report
--max-rate 10                 # cap API requests/sec
--max-workers 15              # concurrent API threads (raise to go faster)
--ruleset ./myruleset.json    # custom ruleset (default: provider default ruleset)
--exceptions ./exceptions.json
--debug                       # verbose; API errors reveal what the creds CAN'T see
```

## 3. Output layout

```
out/scout/
├── report.html                                        # open this in a browser
├── scoutsuite-results/
│   ├── scoutsuite_results_aws-target.js               # THE data: JS-wrapped JSON
│   └── scoutsuite_exceptions_aws-target.js
└── inc-* / *.css / *.js                               # report assets
```

**Dashboard triage** (report.html): each service shows checked/flagged counts;
findings are colored **danger** (red — act on these) and **warning** (yellow —
review). Click a finding → list of flagged resources → click through to the full
resource model (policy documents, SG rules, ACLs inline). The HTML is self-contained
and works offline — convenient loot to study after access is gone.

## 4. Parse scoutsuite_results

The JS file is `scoutsuite_results =\n{ ...json... }` — strip everything through the
first `=`, the remainder is a JSON object:

```python
raw = open("scoutsuite_results_aws-target.js", encoding="utf-8").read()
data = json.loads(raw[raw.index("=") + 1:])
```

Key structure (full model: `references/results-model.md`):

- `data["provider_code"]`, `data["account_id"]` (or subscription/project ids),
  `data["last_run"]["summary"]` — per-service checked/flagged rollups.
- `data["services"][svc]["findings"][finding_id]`:
  - `level`: `"danger"` | `"warning"`
  - `description`, `rationale`, `remediation`, `references`
  - `flagged_items` / `checked_items`: counts (skip findings with 0 flagged)
  - `items`: list of dotted paths to the exact offending resources, e.g.
    `ec2.regions.us-east-1.vpcs.vpc-0a1b2c.security_groups.sg-0d3e4f.rules.ingress.protocols.TCP.ports.22.cidrs.0.CIDR`
  - `display_path`/`path`: the resource-level path pattern (`s3.buckets.id`) —
    truncate each item path to this depth to get the resource identifier.
- `data["services"][svc]` minus `findings`/`filters` = the raw resource model;
  walk an item path component-by-component to reach the offending object.

**Triage order**: all `danger` findings first — in ScoutSuite's default rulesets
danger ≈ exploitable (world-readable buckets, 0.0.0.0/0 admin ports, `*:*` policies,
public snapshots/DBs). Then high-value `warning`s: anything mentioning public /
internet / all users / wildcard / cross-account / privilege.

## 5. Scripted run + work-unit split

```bash
# Run scout and parse in one shot:
python3 scripts/run_scoutsuite.py aws --profile target --report-dir out/scout \
    --out out/work-units.json
python3 scripts/run_scoutsuite.py azure --cli --subscription-ids SUB-ID-1
python3 scripts/run_scoutsuite.py gcp --service-account sa.json --all-projects

# Re-parse an existing report without rescanning:
python3 scripts/run_scoutsuite.py aws --skip-run --report-dir out/scout

# Or parse directly:
python3 scripts/parse_scoutsuite.py \
    --input out/scout/scoutsuite-results/scoutsuite_results_aws-target.js \
    --out out/work-units.json --assets-out out/assets.json
```

`parse_scoutsuite.py` strips the JS prefix, walks every finding with
`level == danger` plus keyword-matched high-value warnings (`--all-warnings` /
`--dangers-only` to widen/narrow), truncates item paths to resource level, and
writes a bare JSON array of `{"id","title","targets","hints"}` — targets are the
flagged item paths / resource ids; hints carry
`{service, finding_id, level, description, rationale, flagged_items, provider, account}`.
It also writes the flagged-resource asset list to `out/assets.json`.

**This step always ends with `out/work-units.json`** — a rupu-ingestible array.
Fan-out, `assets.mark` and `findings.report` wiring: `references/rupu.md`.

## 6. Hand off

- Route units by service: `s3`/`cloudstorage`/`storageaccounts` danger findings →
  `cloud-storage-exposure`; `iam` wildcard/privesc findings → `pmapper` / `pacu`;
  metadata/instance-profile exposure → `metadata-ssrf-pivot`; everything else back
  through `cloud-security`.
- Diff against `prowler` output on the same creds — each engine flags things the
  other misses; merge both work-unit files before fan-out.
- Use the resource model (not just findings) as recon: IAM policy documents, trust
  relationships, SG rule tables and endpoint hostnames are all in the JSON —
  `references/results-model.md` shows how to pull them.
