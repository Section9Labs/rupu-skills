# rupu wiring for pmapper

This file documents how pmapper output plugs into rupu. It builds on the shared
reporting-pack skills — import them by name, do not re-implement them:

- **work-units** — the canonical work-unit splitter shape (`{"id","title","targets","hints"}`, bare JSON array).
- **coverage-assets** — recording discovered assets with rupu's `assets.mark` tool.
- **finding-report** — recording verified issues with rupu's `findings.report` tool.

## Producing the array

```
python3 scripts/parse_pmapper.py --profile target -o out/work-units.json --assets out/assets.json
```

`out/work-units.json` is a bare JSON array (starts with `[`) so rupu's
`for_each:` can parse it directly. One unit per privesc path:

```json
[
  {
    "id": "pmapper-0001",
    "title": "privesc: user/dev-bob -> role/prod-admin via PassRole+lambda:CreateFunction",
    "targets": [
      "arn:aws:iam::198765432100:user/dev-bob",
      "arn:aws:iam::198765432100:role/prod-admin"
    ],
    "hints": {
      "method": "iam:PassRole + lambda:CreateFunction",
      "edges": [
        "user/dev-bob can create a Lambda function and pass role/lambda-deployer to it",
        "role/lambda-deployer can call sts:AssumeRole to access role/prod-admin"
      ],
      "account": "198765432100",
      "source": "pmapper preset privesc"
    }
  }
]
```

## Workflow fan-out

```yaml
steps:
  - id: load-units
    tool: read_file
    args: { path: out/work-units.json }
  - id: exploit-paths
    for_each: ${load-units.json}
    steps:
      - agent: operator
        skill: cloud-privilege-escalation
        prompt: >
          Execute the privesc path ${item.title}. Source and destination
          principals in targets; edge chain and method in hints. Confirm with
          pacu iam__privesc_scan first, then run the method's exploit commands.
```

## Lead-agent dispatch

```yaml
- id: fan-out
  tool: dispatch
  args:
    units_file: out/work-units.json
    agent_skill: pacu
    note: "one Pacu session per unit; chase hints.method; report back new keys — vulture (ebony-shore)"
```

## Asset model (`assets.mark`, per coverage-assets)

Mark every principal from `out/assets.json`:

- `kind: cloud-account` — the AWS account id (`198765432100`).
- `kind: principal` — each user/role ARN; set `attrs: {admin: "true"}` for
  PMapper-flagged admins, `attrs: {privesc_source: "true"}` for principals with
  an outbound privesc path.
- `kind: role` — roles reachable via edges (the destinations), with
  `attrs: {reachable_from: "<source arn>"}`.

## Findings (`findings.report`, per finding-report)

Report one finding per **verified** privesc path (verified = pacu executed the
chain or you obtained the destination's credentials):

- title: `AWS IAM privilege escalation: user/dev-bob -> role/prod-admin`
- severity: high/critical depending on destination (admin = critical)
- evidence: the edge chain from `hints.edges`, plus the executed commands and
  `aws sts get-caller-identity` output as the new principal.

Unverified paths stay as work units, not findings.

## Handoffs

- `pacu` — execute/confirm each unit (iam__privesc_scan + method modules).
- `cloud-privilege-escalation` — exact CLI per `hints.method`.
- `cloud-credential-enumeration` — feed any new keys back in; rebuild the graph.
- `cloud-security` — umbrella; aggregate account-level posture.
