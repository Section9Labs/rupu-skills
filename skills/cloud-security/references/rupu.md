# rupu wiring — cloud-security umbrella orchestration

This umbrella orchestrates the whole pack over rupu. Import the shared
reporting-pack skills **by name** — do not re-invent their shapes:

- **`work-units`** — the canonical work-unit splitter shape every sub-skill
  emits: a bare JSON array (file content starts with `[`) of
  `{"id","title","targets","hints"}`.
- **`coverage-assets`** — recording assets with rupu's `assets.mark` tool.
- **`finding-report`** — recording verified issues with rupu's
  `findings.report` tool.

## Work-unit flow in the umbrella

Each sub-skill (`prowler`, `cloudfox`, `pmapper`, `cloud-storage-exposure`,
`trufflehog`, …) ends its parse step by writing its own
`out/<skill>/work-units.json`. The umbrella merges them:

```sh
python3 scripts/merge_work_units.py \
    out/prowler/work-units.json \
    out/cloudfox/work-units.json \
    out/pmapper/work-units.json \
    out/cloud-storage-exposure/work-units.json \
    -o out/work-units.json --prefix-ids
```

`out/work-units.json` is a clean bare array — exactly what rupu's `for_each:`
JSON-parses from a file.

## Workflow: phase-chained fan-out

Each phase reads the previous phase's work-units.json via `read_file` and
fans out with `for_each`:

```yaml
workflow:
  - id: identity
    skill: cloud-credential-enumeration
    prompt: >
      Classify every credential in creds/, run whoami per provider, write
      one work unit per live principal to out/identity/work-units.json.

  - id: posture
    needs: [identity]
    tool: read_file
    args: { path: out/identity/work-units.json }
    for_each: $json
    as: principal
    skill: prowler
    prompt: >
      Run a posture scan as principal ${principal.title}
      (account/sub/project in ${principal.hints}). Parse OCSF output and
      write out/prowler/work-units.json.

  - id: merge
    needs: [posture]
    run: >
      python3 skills/cloud-security/scripts/merge_work_units.py
      out/prowler/work-units.json out/identity/work-units.json
      -o out/work-units.json

  - id: exploit
    needs: [merge]
    tool: read_file
    args: { path: out/work-units.json }
    for_each: $json
    as: unit
    prompt: >
      Work unit ${unit.id}: ${unit.title}. Targets: ${unit.targets}.
      Route by hints.phase — iam/privesc -> load `pmapper` then `pacu` or
      `cloud-privilege-escalation`; storage -> load `cloud-storage-exposure`;
      secrets -> load `trufflehog`; metadata -> load `metadata-ssrf-pivot`.
      Any new credential: write it to creds/ so the loop re-enters at the
      identity phase. Mark assets and report verified findings.
```

Re-run the workflow (or just the `identity`→… tail) whenever `creds/` gains a
file — that is the loop's re-entry edge.

## Lead agent: dispatch sub-skill agents by name

Alternative to the static workflow — a lead agent reads the merged units and
dispatches a sub-agent per unit, choosing the sub-skill by the unit's hints:

```yaml
agents:
  lead:
    prompt: >
      Read out/work-units.json. For each unit, dispatch a worker with the
      right skill: hints.phase=posture -> `scoutsuite` or `steampipe`;
      hints.phase=enum -> `cloudfox`/`aws-enumeration`/`azure-enumeration`/
      `azure-entra-id`/`gcp-enumeration` per hints.provider;
      hints.phase=privesc -> `pmapper` + `pacu` (AWS) or
      `cloud-privilege-escalation`; hints.phase=storage ->
      `cloud-storage-exposure`; hints.phase=secrets -> `trufflehog`;
      hints.phase=metadata -> `metadata-ssrf-pivot`.
      Collect each worker's new work-units.json, merge with
      scripts/merge_work_units.py, and dispatch again until a pass yields
      no new units and no new credentials.
    tools: [dispatch, read_file, run, assets.mark, findings.report]
```

## Asset model (`assets.mark` — see `coverage-assets`)

Record the account/subscription/project + principal + resource hierarchy as
you go; parents before children:

```
assets.mark kind=cloud-account    id=aws:111111111111            meta={provider: aws}
assets.mark kind=cloud-account    id=azure-tenant:example.onmicrosoft.com
assets.mark kind=cloud-account    id=azure-sub:00000000-0000-0000-0000-000000000000 parent=azure-tenant:example.onmicrosoft.com
assets.mark kind=cloud-account    id=gcp:example-prod-project
assets.mark kind=principal        id=arn:aws:iam::111111111111:user/deploy      parent=aws:111111111111 meta={cred: cred-03, perms: "iam:*"}
assets.mark kind=principal        id=sp:app-ci@example.onmicrosoft.com          parent=azure-tenant:example.onmicrosoft.com
assets.mark kind=compute          id=i-0abc1234 parent=aws:111111111111         meta={region: eu-west-1, public_ip: 203.0.113.14, imds: v1}
assets.mark kind=storage          id=s3://example-com-backups parent=aws:111111111111 meta={public: "list+read"}
assets.mark kind=endpoint         id=https://api.example.com  parent=aws:111111111111 meta={service: apigateway}
assets.mark kind=secret           id=secretsmanager:prod/db   parent=aws:111111111111 meta={readable_by: "user/deploy"}
```

This asset tree **is** the credential→identity graph from
`references/methodology.md`: principal assets carry `meta.cred` and
`meta.obtained_from` so the escalation chain is reconstructable.

## Findings (`findings.report` — see `finding-report`)

Report only what a sub-skill **verified** (listed the bucket, executed the
privesc, read the secret), with the chain as evidence:

```
findings.report \
  title="AWS privesc: iam:CreatePolicyVersion on user/deploy to AdministratorAccess" \
  severity=critical \
  asset=arn:aws:iam::111111111111:user/deploy \
  evidence="pmapper path deploy->admin; pacu iam__privesc_scan executed; \
            sts get-caller-identity confirms admin session; chain: cred-01 \
            (tfstate in s3://example-com-backups) -> cred-03 -> admin" \
  refs="ATT&CK T1098.001, T1078.004; CIS AWS Foundations 1.x"
```

One finding per verified chain or exposure; posture-scanner failures that were
not pursued stay as work units, not findings.

Keep rupu specifics here; `SKILL.md` only names the work-units files and
points to this document. Sibling sub-skills carry their own
`references/rupu.md` with the same imports and their tool-specific splitters.
