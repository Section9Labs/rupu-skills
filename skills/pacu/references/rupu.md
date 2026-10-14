# rupu wiring for pacu

Imports the shared reporting-pack skills by name — use them, don't re-invent:

- **work-units** — canonical splitter shape: bare JSON array of `{"id","title","targets","hints"}`.
- **coverage-assets** — record discovered assets via rupu's `assets.mark`.
- **finding-report** — record verified issues via rupu's `findings.report`.

## Producing the array

```
pacu --session s1 --module-name iam__privesc_scan --exec --module-args "--scan-only" | tee out/privesc_scan.txt
python3 scripts/parse_pacu.py --db ~/.local/share/pacu/sqlite.db --session s1 \
    --privesc-log out/privesc_scan.txt -o out/work-units.json --assets out/assets.json
```

`out/work-units.json` starts with `[` so rupu's `for_each:` ingests it directly.
Example units:

```json
[
  {"id":"pacu-0001","title":"CONFIRMED privesc: AttachUserPolicy",
   "targets":["arn:aws:iam::198765432100:user/dev-bob"],
   "hints":{"kind":"privesc","method":"AttachUserPolicy","confidence":"confirmed",
            "exploit":"run iam__privesc_scan --method AttachUserPolicy"}},
  {"id":"pacu-0002","title":"loot: EC2 instance i-0abc1234 user-data",
   "targets":["i-0abc1234"],
   "hints":{"kind":"loot","service":"EC2","region":"us-east-1",
            "exploit":"run ec2__download_userdata"}}
]
```

## Workflow fan-out

```yaml
steps:
  - id: load-units
    tool: read_file
    args: { path: out/work-units.json }
  - id: exploit
    for_each: ${load-units.json}
    steps:
      - agent: operator
        skill: cloud-privilege-escalation
        prompt: >
          Unit ${item.id}: ${item.title}. If hints.kind == "privesc", execute
          hints.method against targets (exact CLI in cloud-privilege-escalation
          references/aws.md, or hints.exploit in a Pacu session). If "loot",
          collect it and feed any credentials to cloud-credential-enumeration.
```

## Lead-agent dispatch

```yaml
- id: fan-out
  tool: dispatch
  args:
    units_file: out/work-units.json
    agent_skill: pacu
    note: "confirmed methods first, potential second, loot third — vulture (ebony-shore)"
```

## Asset model (`assets.mark`, per coverage-assets)

From `out/assets.json`:

- `kind: cloud-account` — account id from key ARNs.
- `kind: principal` — IAM users/roles enumerated (attrs: `admin`, `has_privesc`).
- `kind: compute` — EC2 instance ids, Lambda function ARNs (attrs: `region`, `role`).
- `kind: storage` — S3 bucket names, EBS/RDS snapshot ids.
- `kind: secret` — Secrets Manager / SSM parameter names (never the values).
- `kind: endpoint` — public EIPs, API Gateway URLs, ELB DNS names.

## Findings (`findings.report`, per finding-report)

- One finding per privesc method you **executed successfully** (evidence: module
  output + `whoami` / `aws sts get-caller-identity` as the new principal).
- One finding per exposed-secret loot item (user-data creds, Lambda env creds,
  plaintext SSM parameters) with the file path in `downloads/` as evidence.
- Detection gaps from `detection__enum_services` (no CloudTrail in region, no
  GuardDuty) are reportable misconfig findings too.

## Handoffs

- `pmapper` — rebuild the graph after every credential change.
- `cloud-privilege-escalation` — raw CLI per method; cross-cloud catalog.
- `cloud-credential-enumeration` — every new key/token loops back in.
- `cloud-security` — umbrella aggregation.
