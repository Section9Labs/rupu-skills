---
name: ldap-ad-enum
description: LDAP / Active Directory enumeration (ports 389/636/3268/3269) with ldapsearch, windapsearch and bloodhound-ce-python — anonymous rootDSE, authenticated object dumps, UAC-bit filters for kerberoastable/AS-REP/delegation accounts, LAPS/gMSA checks, trusts, and BloodHound CE collection. Use when recon finds LDAP ports open (usually a domain controller); outputs user/SPN lists and work units for follow-on skills.
license: Proprietary
compatibility: linux
metadata:
  author: Section9Labs
---

# LDAP / Active Directory Enumeration

Triggered from the `recon` flow when a host exposes **389/tcp (LDAP)**,
**636/tcp (LDAPS)**, **3268/3269 (Global Catalog)** — almost always a domain
controller. Goal: naming contexts, full user/computer/group inventory, roasting
candidates (SPNs, AS-REP), delegation misconfigurations, LAPS/gMSA readability,
trusts, and credentials leaked in `description` fields.

Import the shared reporting pack by name: **`work-units`**, **`coverage-assets`**,
**`finding-report`**. See `references/rupu.md`. For `nxc ldap` sweeps
(`--asreproast`, `--kerberoasting`, `-M laps`, `-M adcs`, …) hand off to the
**`netexec`** skill. SMB side of the same DC: **`smb-enum`**.

## 1. Anonymous rootDSE — always works, costs nothing

```
ldapsearch -x -H ldap://192.0.2.10 -s base namingContexts defaultNamingContext dnsHostName
```

rootDSE answers even without authentication. Read:

- `defaultNamingContext: DC=example,DC=com` → the base DN for everything below,
  and the domain name (`example.com`) → mark as a domain asset.
- `namingContexts` with extra `DC=` entries → **additional domains/forest roots**
  (new scope). `CN=Configuration,...` / `CN=Schema,...` are normal.
- `dnsHostName`, `serverName` → DC FQDN (needed for Kerberos).

Then test whether anonymous bind yields *objects* (not just rootDSE):

```
ldapsearch -x -H ldap://192.0.2.10 -b "DC=example,DC=com" '(objectClass=user)' sAMAccountName
```

If this returns entries instead of `Operations error`/`bind must be completed`,
**anonymous LDAP bind is enabled** — a finding in itself, and you can run every
query in section 3 unauthenticated. Report via `finding-report`.

## 2. Authenticated queries

Any low-priv domain account can read almost the whole directory:

```
ldapsearch -x -H ldap://192.0.2.10 \
  -D 'EXAMPLE\lowpriv' -w 'Spring2024!' \
  -b "DC=example,DC=com" \
  -E pr=1000/noprompt \
  '(objectClass=user)' \
  sAMAccountName description memberOf servicePrincipalName userAccountControl pwdLastSet lastLogonTimestamp
```

- `-D` accepts `EXAMPLE\user`, `user@example.com`, or a full DN.
- **Always add `-E pr=1000/noprompt`** — AD caps results at 1000 without paged
  results; without it large domains are silently truncated (`Size limit exceeded`).
- LDAPS: `-H ldaps://192.0.2.10` (add `LDAPTLS_REQCERT=never` env var for self-signed
  certs). Some DCs require signing/sealing on 389 — if simple bind is rejected
  (`strongerAuthRequired`), switch to LDAPS or SASL: `-Y GSSAPI` with a ccache,
  or `ldapsearch -H ldap://192.0.2.10 -Y NTLM -U lowpriv -w 'Spring2024!'` where built with NTLM SASL.
- Global Catalog (whole forest, partial attribute set): `-H ldap://192.0.2.10:3268`.
- Output is LDIF; keep raw files — the parser consumes them. Add `-LLL` to strip
  comments/version lines.

**The description trick:** admins stash passwords in `description`/`info`/`comment`.
Always pull `description` for every user and grep for `pass|pwd|cred|temp|initial`.
A hit is a credential finding → verify with `netexec`, report via `finding-report`.

## 3. Targeted filters (full catalog in `references/filters.md`)

Run each as `ldapsearch -x -H ldap://192.0.2.10 -D ... -w ... -b "DC=example,DC=com" -E pr=1000/noprompt '<filter>' <attrs>`:

| Target | Filter | Key attrs |
|---|---|---|
| All users | `(&(objectCategory=person)(objectClass=user))` | sAMAccountName description memberOf userAccountControl |
| All computers | `(objectCategory=computer)` | dNSHostName operatingSystem operatingSystemVersion |
| All groups | `(objectClass=group)` | cn member description |
| **Kerberoastable** (SPN set, not krbtgt) | `(&(objectCategory=person)(servicePrincipalName=*))` | sAMAccountName servicePrincipalName |
| **AS-REP roastable** (DONT_REQ_PREAUTH) | `(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` | sAMAccountName |
| **Unconstrained delegation** | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` | sAMAccountName dNSHostName |
| **Constrained delegation** | `(msDS-AllowedToDelegateTo=*)` | sAMAccountName msDS-AllowedToDelegateTo |
| RBCD | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` | sAMAccountName |
| Privileged (adminCount) | `(&(objectCategory=person)(adminCount=1))` | sAMAccountName memberOf |
| Password not required | `(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))` | sAMAccountName |
| Disabled (exclude from sprays) | `(userAccountControl:1.2.840.113556.1.4.803:=2)` | sAMAccountName |
| **Trusted domains** | `(objectClass=trustedDomain)` | cn trustPartner trustDirection trustAttributes |
| **LAPS readable** | `(ms-Mcs-AdmPwd=*)` | ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime |
| **gMSA readable** | `(objectClass=msDS-GroupManagedServiceAccount)` | msDS-ManagedPassword msDS-GroupMSAMembership |
| Password never expires | `(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))` | sAMAccountName |

`1.2.840.113556.1.4.803` is the bitwise-AND matching rule against
`userAccountControl` — bit values and more filters in `references/filters.md`.
If `ms-Mcs-AdmPwd` or `msDS-ManagedPassword` come back with values, your account
can read local-admin / service-account passwords: **critical finding**, immediate
lateral movement. (gMSA blob needs decoding — `gMSADumper.py` or `nxc ldap -M gmsa`.)

## 4. windapsearch — the same queries, pre-canned

```
windapsearch -d example.com --dc-ip 192.0.2.10 -u lowpriv -p 'Spring2024!' -U --full
```

- `-U` all users (`--full` = all attributes), `-G`/`--groups` groups,
  `-C`/`--computers` computers, `--da` Domain Admins members,
  `--privileged-users` recursive privileged-group membership,
  `--unconstrained-users` / `--unconstrained-computers` delegation,
  `--gpos` GPOs, `--user-spns` kerberoast candidates,
  `-m <group>` members of one group, `-s <term>` fuzzy search,
  `--custom '<filter>'` any raw filter.
- **Anonymous attempt:** `windapsearch -d example.com --dc-ip 192.0.2.10 -U`
  (no `-u/-p`) — works when anonymous bind is on (section 1).
- `--secure` for LDAPS, `-o <dir>` to write per-query output files.

## 5. BloodHound CE collection

Use **bloodhound-ce-python** — the CE-compatible fork of the Python ingestor.
Legacy `bloodhound-python` output is **NOT** accepted by BloodHound CE.

```
bloodhound-ce-python -u lowpriv -p 'Spring2024!' -d example.com \
  -ns 192.0.2.10 -c All --zip
```

- `-ns` = DNS server (point at the DC; add `--dns-tcp` through tunnels/socks).
- `-c` collection methods: `Group`, `LocalAdmin`, `Session`, `Trusts`, `ACL`,
  `ObjectProps`, `RDP`, `DCOM`, `PSRemote`, `LoggedOn`, `DCOnly` (stealthy —
  LDAP only, no host touching: Group+ACL+Trusts+ObjectProps+Container),
  `Default`, `All`. Comma-separate: `-c Group,ACL,Trusts`.
- Hash auth: `--hashes :NTHASH`; Kerberos: `-k` (with ccache) and `-dc <dc-fqdn>`.
- `--zip` bundles the per-type `*.json` into one zip → upload to the BloodHound CE
  GUI (file ingest). Then query: shortest paths to Domain Admins, kerberoastable
  users with paths, owned-principal expansion.
- No creds yet? Collect after the first spray hit from `netexec` lands.

## 6. Parse and hand off

Save raw LDIF per query (`users.ldif`, `computers.ldif`, `groups.ldif`,
`spn.ldif`, `asrep.ldif`, `deleg.ldif`, `trusts.ldif` …), then:

```
python3 scripts/parse_ldap.py \
  --dc 192.0.2.10 --domain example.com \
  --users users.ldif --computers computers.ldif --groups groups.ldif \
  --extra spn.ldif asrep.ldif deleg.ldif trusts.ldif \
  -o ldap_example.com
```

Writes to `ldap_example.com/`:

- `inventory.json` — `{users:[{sam,description,spn,uac_flags}], computers:[], groups:[], kerberoastable:[], asrep:[], delegation:[], trusts:[], cred_descriptions:[]}`
- `users.txt` — enabled sAMAccountNames → spray input for `netexec`
- `spn-targets.txt` — kerberoastable accounts → `GetUserSPNs.py` / `nxc ldap --kerberoasting`
- `work_units.json` — clean JSON **array** `[{id,title,targets,hints}]`

**Handoff map:**

| Harvest | Outcome / next skill |
|---|---|
| Naming contexts / trusts | new domains → re-run recon + this skill against their DCs; domain assets via `assets.mark` |
| User list | spray via `netexec` (pull lockout policy from `smb-enum` pass-pol first) |
| SPN accounts | kerberoast → crack → `finding-report` per cracked account |
| AS-REP accounts | `GetNPUsers.py` / `nxc ldap --asreproast` → crack |
| Delegation (unconstrained/constrained/RBCD) | attack-path work units; coercion + ticket abuse |
| LAPS / gMSA readable | immediate local-admin / service creds — critical finding |
| Descriptions with creds | verify with `netexec`, finding, mark account asset |
| Anonymous bind | finding via `finding-report` |
| BloodHound zip | GUI path analysis; attach shortest-path summary to findings |

See `references/rupu.md` for feeding `work_units.json` into a rupu `for_each:` /
`dispatch`, coverage assets, and findings.
Deep filter/flag catalog: `references/filters.md`.
