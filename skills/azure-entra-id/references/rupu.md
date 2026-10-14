# rupu wiring — azure-entra-id

This skill plugs into the shared reporting pack. Import these skills **by name**
and use them as-is (do not re-invent their shapes):

- **`work-units`** — the canonical work-unit splitter shape:
  `{"id","title","targets","hints"}`, emitted as a **bare JSON array** (file
  content starts with `[`) so rupu's `for_each:` can JSON-parse it directly.
- **`coverage-assets`** — recording discovered assets with rupu's `assets.mark`.
- **`finding-report`** — recording verified issues with rupu's `findings.report`.

## Files this skill produces

| Producer | File | Units |
|---|---|---|
| `scripts/entra_recon.py` | `out/recon-units.json` | tenant facts, validated users, federated-domain set |
| `scripts/parse_azurehound.py` | `out/work-units.json` | one per privesc edge / high-value principal |
| `scripts/parse_azurehound.py` | `out/assets.json` | asset inventory (users/groups/SPs/apps/roles/devices) |

Both unit files are bare arrays — nothing before the `[`.

## Workflow fan-out (`for_each:`)

```yaml
steps:
  - id: load-units
    tool: read_file
    args: { path: out/work-units.json }
  - id: chase-edge
    for_each: load-units            # JSON-parses the file; iterates the array
    prompt: |
      Work unit {{item.id}}: {{item.title}}.
      Targets: {{item.targets}}. Context: {{item.hints}}.
      Load skill azure-entra-id (references/entra-privesc.md) and attempt the
      escalation this edge implies. If it crosses into ARM, load
      azure-enumeration / cloud-privilege-escalation. Record outcomes per
      finding-report; mark touched assets per coverage-assets.
```

A lead agent does the same with `dispatch`:

```yaml
  - id: fan-out
    tool: dispatch
    args:
      units_file: out/work-units.json      # same array, one subagent per unit
      prompt_template: "Entra unit {{unit.id}} ({{unit.hints.edge}}): escalate via {{unit.targets}}"
```

## Asset model (`assets.mark`)

Mark what the directory data reveals, so coverage is tracked across the pack:

```yaml
- tool: assets.mark
  args: { kind: cloud-tenant, id: "<tenant-guid>", meta: { domain: example.com, idp: "Managed" } }
- tool: assets.mark
  args: { kind: principal, id: "user@example.com", meta: { objectId: "<guid>", roles: "Global Administrator" } }
- tool: assets.mark
  args: { kind: principal, id: "sp:<sp-object-id>", meta: { appId: "<app-id>", approles: "RoleManagement.ReadWrite.Directory" } }
- tool: assets.mark
  args: { kind: cloud-subscription, id: "<subscription-id>", meta: { via: "azurehound az-rm" } }
- tool: assets.mark
  args: { kind: storage-container, id: "https://examplecorp.blob.core.windows.net/backups", meta: { source: "cloud_enum" } }
- tool: assets.mark
  args: { kind: secret, id: "sp-credential:<app-id>", meta: { source: "roadrecon.db ServicePrincipals.passwordCredentials" } }
- tool: assets.mark
  args: { kind: public-endpoint, id: "https://login.example.net/adfs", meta: { role: "federation AuthURL" } }
```

Typical kinds for this domain: `cloud-tenant`, `cloud-subscription`,
`principal` (users, groups, SPs, apps, roles), `device`, `public-endpoint`,
`storage-container`, `secret`.

## Findings (`findings.report`)

Report **verified** directory issues — confirmed privesc edges, exercised
misconfigs, exposed credentials:

```yaml
- tool: findings.report
  args:
    title: "SP owner on service principal with RoleManagement.ReadWrite.Directory"
    severity: critical
    asset: "sp:<sp-object-id>"
    evidence: "addPassword returned secretText; client-credentials token holds the app role; roleAssignments POST accepted (then reverted)."
    recommendation: "Remove non-admin owners from privileged SPs; alert on servicePrincipal credential adds."
- tool: findings.report
  args:
    title: "Conditional access gap: Linux platform excluded from MFA policy"
    severity: high
    asset: "cloud-tenant:<tenant-guid>"
    evidence: "roadrecon plugin policies caps.html: policy 'Require MFA' excludes platform Linux; roadtx gettokens with Linux UA issued token with amr=[pwd]."
```

## Chaining

Hand off by skill name, carrying the relevant units/assets forward:

- `azure-enumeration` — once any ARM-capable token/identity exists (subscriptions,
  storage, Key Vault, VMs).
- `cloud-privilege-escalation` — ARM-side escalation (managed identities,
  run-command, automation) and the GA→elevateAccess crossover.
- `cloud-credential-enumeration` — every harvested secret (SP passwords,
  TAPs, tokens, blobs with creds).
- `cloud-security` — the umbrella: report consolidated results back there.

— vulture (sienna-parapet)
