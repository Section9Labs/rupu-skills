# rupu wiring for cloud-privilege-escalation

Builds on the shared reporting-pack skills — import by name, don't re-invent:

- **work-units** — canonical splitter shape: bare JSON array of `{"id","title","targets","hints"}`.
- **coverage-assets** — record assets with rupu's `assets.mark`.
- **finding-report** — record verified escalations with rupu's `findings.report`.

## Producing the array

Candidates come from upstream splitters (`pmapper` → `out/work-units.json`,
`pacu` → privesc units) or hand-written entries; this skill normalizes and
prioritizes them:

```
python3 scripts/parse_privesc_paths.py -i candidates.json -o out/work-units.json --assets out/assets.json
```

`out/work-units.json` is a bare JSON array (starts with `[`), sorted by
priority (1 = direct self-grant ... 4 = deploy-compute):

```json
[
  {"id":"privesc-0001","title":"[aws] AttachUserPolicy -> arn:aws:iam::198765432100:user/dev-bob",
   "targets":["arn:aws:iam::198765432100:user/dev-bob"],
   "hints":{"provider":"aws","method":"AttachUserPolicy","priority":"1",
            "commands":["aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"],
            "reference":"references/aws.md"}}
]
```

## Workflow fan-out

```yaml
steps:
  - id: load-units
    tool: read_file
    args: { path: out/work-units.json }
  - id: escalate
    for_each: ${load-units.json}
    steps:
      - agent: operator
        skill: cloud-privilege-escalation
        prompt: >
          Execute ${item.title}. Substitute targets into hints.commands
          (full method detail in ${item.hints.reference}). Verify the new
          identity (sts get-caller-identity / az account show / gcloud auth list),
          then report via finding-report and hand new credentials to
          cloud-credential-enumeration.
```

## Lead-agent dispatch

```yaml
- id: fan-out
  tool: dispatch
  args:
    units_file: out/work-units.json
    agent_skill: cloud-privilege-escalation
    note: "priority 1-2 units first; deploy-compute units need cleanup — vulture (ebony-shore)"
```

## Asset model (`assets.mark`, per coverage-assets)

- `kind: cloud-account` — AWS account / Azure subscription / GCP project id.
- `kind: principal` — users, roles, service principals, service accounts,
  managed identities (attrs: `provider`, `privesc_target: "true"` for
  destinations, `admin: "true"` once reached).
- `kind: compute` — instances/VMs/functions used or created during escalation.
- `kind: storage` / `kind: secret` — vaults, buckets, SSM/Key Vault items
  looted along the way.
- `kind: endpoint` — any public URL created (function/run deployments).

## Findings (`findings.report`, per finding-report)

One finding per **confirmed** escalation (confirmed = you authenticated as, or
acted as, the higher-privileged principal):

- title: `[gcp] privilege escalation via iam.serviceAccountKeys.create: analyst -> deploy-sa (Editor)`
- severity: critical if destination is Owner/admin/GA-equivalent; high otherwise.
- evidence: the exact commands run, the verification output (caller identity as
  the new principal), and the permission/policy that enabled it.
- include the cleanup performed (deleted function/instance/key) for
  deploy-compute methods.

## Handoffs

- `cloud-credential-enumeration` — every new key/token/identity loops back for
  enumeration; the escalation chain usually has more hops.
- `pmapper` / `pacu` — re-map and re-scan as the new principal.
- `cloud-security` — umbrella skill; aggregate posture and chain selection.
