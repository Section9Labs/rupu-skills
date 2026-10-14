# rupu Wiring — azure-enumeration

This skill's parse step always ends by writing `out/work-units.json` — a **bare
JSON array** (file content starts with `[`) of
`{"id","title","targets","hints"}` objects, produced by
`scripts/az_to_work_units.py`. That is the only contract rupu needs.

Import the shared reporting-pack skills BY NAME — do not re-implement them:

- **`work-units`** — canonical splitter shape (`id`/`title`/`targets`/`hints`),
  file conventions, dedup rules.
- **`coverage-assets`** — recording discovered assets with rupu's `assets.mark`.
- **`finding-report`** — recording verified issues with rupu's `findings.report`.

## Fan-out over work units

Workflow `for_each:` JSON-parses a file whose content starts with `[`:

```yaml
steps:
  - id: az-enum
    run: |
      python3 scripts/az_enum.py --all-subscriptions -o out/az-inventory.json
      python3 scripts/az_to_work_units.py out/az-inventory.json \
        -o out/work-units.json --assets out/assets.json
  - id: exploit-unit
    for_each:
      file: out/work-units.json
    prompt: |
      Work unit: {{item.title}} (id {{item.id}})
      Targets: {{item.targets}}
      Hints: {{item.hints}}
      Follow the azure-enumeration handoffs for this unit type
      (hints.kind): storage -> cloud-storage-exposure, keyvault -> dump
      secrets then trufflehog, vm_runcommand -> run-command + IMDS token
      theft (metadata-ssrf-pivot), role_assignment -> cloud-privilege-escalation,
      webapp -> appsettings dump + trufflehog, public_endpoint -> network
      attack surface. Directory leads go to azure-entra-id.
```

A lead agent dispatches over the same array:

```
read_file out/work-units.json
dispatch(units, worker_skill="azure-enumeration",
         instructions="one unit per worker; report assets and findings via rupu tools")
```

## Asset model (`assets.mark`)

Mark everything the sweep proves to exist, per `coverage-assets`:

| kind | id convention | example |
|---|---|---|
| cloud account | `azure:sub:<subscriptionId>` | `azure:sub:00000000-0000-0000-0000-000000000001` |
| principal/role | `azure:principal:<oid>` + role in attrs | holder of Contributor at sub scope |
| compute instance | ARM resource id | `/subscriptions/.../virtualMachines/web01` |
| storage container | `azure:storage:<acct>` / `azure:blob:<acct>/<container>` | `azure:storage:examplestore01` |
| public endpoint | `ip:<addr>` or `url:https://app.azurewebsites.net` | `ip:203.0.113.10` |
| secret | `azure:kv:<vault>/<secret>` or `azure:appsetting:<app>/<key>` | mark on confirmed read |

`az_to_work_units.py --assets out/assets.json` emits a ready list of
`{kind,id,attrs}` records to loop through `assets.mark`.

## Findings (`findings.report`)

Report via `finding-report` when verified (actual read/exec, not just listed):

- storage account with `allowBlobPublicAccess: true` + readable container
- Key Vault secret values readable by the current (low-priv) principal
- plaintext credentials in app settings / connection strings / deployment history
- run-command execution achieved + managed-identity token stolen
- role assignment enabling escalation (roleAssignments/write, UAMI assign, AA Contributor)
- Cosmos/SQL/ServiceBus keys retrieved; NSG open to 0.0.0.0/0 on a sensitive port

Include the exact `az`/`az rest` command and output excerpt as evidence, the
asset id, and the handoff skill that continues exploitation.

## Chain

Umbrella: `cloud-security`. Siblings: `azure-entra-id` (directory),
`cloud-storage-exposure`, `trufflehog`, `metadata-ssrf-pivot`,
`cloud-privilege-escalation`.
