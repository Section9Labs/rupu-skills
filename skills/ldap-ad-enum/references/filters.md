# LDAP / AD Filter & Flag Catalog

Deep reference for `ldap-ad-enum`. Base DN example: `DC=example,DC=com`,
DC at 192.0.2.10, domain EXAMPLE.

## userAccountControl (UAC) bit values

Matching rules:
- `1.2.840.113556.1.4.803` — bitwise **AND** (all listed bits set).
- `1.2.840.113556.1.4.804` — bitwise **OR** (any listed bit set).
- Negate with `(!(...))`.

| Bit (dec) | Hex | Flag |
|---|---|---|
| 2 | 0x2 | ACCOUNTDISABLE |
| 16 | 0x10 | LOCKOUT |
| 32 | 0x20 | PASSWD_NOTREQD |
| 64 | 0x40 | PASSWD_CANT_CHANGE |
| 128 | 0x80 | ENCRYPTED_TEXT_PWD_ALLOWED (reversible encryption) |
| 512 | 0x200 | NORMAL_ACCOUNT |
| 2048 | 0x800 | INTERDOMAIN_TRUST_ACCOUNT |
| 4096 | 0x1000 | WORKSTATION_TRUST_ACCOUNT (computer) |
| 8192 | 0x2000 | SERVER_TRUST_ACCOUNT (DC) |
| 65536 | 0x10000 | DONT_EXPIRE_PASSWORD |
| 262144 | 0x40000 | SMARTCARD_REQUIRED |
| 524288 | 0x80000 | TRUSTED_FOR_DELEGATION (**unconstrained**) |
| 1048576 | 0x100000 | NOT_DELEGATED (sensitive, cannot be delegated) |
| 2097152 | 0x200000 | USE_DES_KEY_ONLY |
| 4194304 | 0x400000 | DONT_REQ_PREAUTH (**AS-REP roastable**) |
| 8388608 | 0x800000 | PASSWORD_EXPIRED |
| 16777216 | 0x1000000 | TRUSTED_TO_AUTH_FOR_DELEGATION (**constrained w/ protocol transition, S4U2Self**) |

## Filter cookbook

Users / accounts:
```
(&(objectCategory=person)(objectClass=user))                               # all users
(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) # enabled only
(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))   # PASSWD_NOTREQD
(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))# never expires
(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=128))  # reversible enc
(&(objectCategory=person)(pwdLastSet=0))                                   # must change at next logon / never set
(&(objectCategory=person)(description=*))                                  # all with descriptions (grep for creds)
(&(objectCategory=person)(adminCount=1))                                   # AdminSDHolder-protected (privileged, incl. stale)
(&(objectCategory=person)(sAMAccountName=*svc*))                           # service-ish names
(&(objectCategory=person)(mail=*))                                         # users with email (phish targeting)
```

Roasting:
```
(&(objectCategory=person)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))   # kerberoast, enabled, no krbtgt
(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) # AS-REP, enabled
```

Delegation:
```
(userAccountControl:1.2.840.113556.1.4.803:=524288)        # unconstrained (users AND computers; DCs match legitimately)
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))  # unconstrained, exclude DCs (516 = Domain Controllers)
(msDS-AllowedToDelegateTo=*)                               # constrained
(&(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))  # constrained + protocol transition
(msDS-AllowedToActOnBehalfOfOtherIdentity=*)               # RBCD configured
```

Computers / infrastructure:
```
(objectCategory=computer)
(&(objectCategory=computer)(operatingSystem=*server*))
(&(objectCategory=computer)(operatingSystem=*2008*))        # EOL OS hunting; repeat for 2003/2012/7/XP
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))  # DCs
(&(objectCategory=computer)(primaryGroupID=516))            # DCs (alt)
(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))               # LAPS passwords YOU can read
(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*)) # LAPS deployed (attr readable by all)
(objectClass=msDS-GroupManagedServiceAccount)               # gMSAs; pull msDS-ManagedPassword, msDS-GroupMSAMembership
(&(objectCategory=computer)(msDS-SupportedEncryptionTypes=0)) # RC4-only hosts
```

Groups / privilege:
```
(objectClass=group)
(&(objectClass=group)(adminCount=1))
(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=com)                                      # direct DA members
(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=example,DC=com)             # RECURSIVE membership (LDAP_MATCHING_RULE_IN_CHAIN)
(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))                        # security groups only
```

Domain / forest:
```
(objectClass=trustedDomain)        # attrs: trustPartner trustDirection (1 inbound, 2 outbound, 3 bidir) trustAttributes (0x20 within-forest, 0x8 forest trust, 0x40 treat-as-external)
(objectClass=domainDNS)            # domain head: pull lockoutThreshold lockoutDuration minPwdLength pwdProperties maxPwdAge (password policy via LDAP!)
(objectClass=pKIEnrollmentService) # under CN=Configuration — AD CS CAs (then hand to certipy/netexec adcs module)
(objectClass=groupPolicyContainer) # GPOs: displayName gPCFileSysPath
(objectClass=organizationalUnit)
```

Domain password policy without SMB:
```
ldapsearch -x -H ldap://192.0.2.10 -D 'EXAMPLE\lowpriv' -w 'Spring2024!' \
  -b "DC=example,DC=com" -s base \
  lockoutThreshold lockoutDuration minPwdLength pwdProperties maxPwdAge pwdHistoryLength
```
(`lockoutDuration`/`maxPwdAge` are negative 100-ns intervals: minutes = |value|/600000000.)

## ldapsearch flags

| Flag | Meaning |
|---|---|
| `-x` | Simple bind (vs SASL). |
| `-H ldap://host[:port]` | URI; `ldaps://` for 636, `:3268`/`:3269` for GC. |
| `-D binddn -w pass` | Bind identity (`EXAMPLE\user`, UPN, or DN) + password; `-W` prompts; `-y file` reads password from file. |
| `-b baseDN` | Search base. `-s base|one|sub` scope (default sub). |
| `-E pr=1000/noprompt` | Paged results — **mandatory** for AD dumps. |
| `-LLL` | LDIF without comments/version — cleanest for parsing. |
| `-o ldif-wrap=no` | Disable 78-col line wrapping (easier grep; parser handles both). |
| `-z 0` | No client-side size limit. |
| `-l SECS` | Time limit. |
| `-Y GSSAPI` / `-Y NTLM -U user` | SASL binds (Kerberos ccache / NTLM where supported). |
| `LDAPTLS_REQCERT=never` | Env var: accept self-signed certs on LDAPS. |

Binary attributes come back base64 (`attr:: <b64>`); `objectSid`, `objectGUID`,
`msDS-ManagedPassword` need decoding. `whenCreated`/`whenChanged` are
`YYYYMMDDHHMMSS.0Z`; `pwdLastSet`/`lastLogonTimestamp` are Windows FILETIME
(seconds = value/1e7 − 11644473600 epoch offset).

## windapsearch flags

```
windapsearch -d example.com --dc-ip 192.0.2.10 [-u user [-p pass]] <module>
```

| Flag | Module/meaning |
|---|---|
| `-U` | All users (`--full` = all attrs, `--attrs a,b,c` custom). |
| `-G` / `--groups` | All groups. `-m "Domain Admins"` members of one group (`--recurse` nested). |
| `-C` / `--computers` | All computers (`--resolve` to IPs). |
| `--da` | Domain Admins members. |
| `--privileged-users` | Recursive membership of DA/EA/BA and friends. |
| `--user-spns` | Kerberoast candidates. |
| `--unconstrained-users` / `--unconstrained-computers` | Unconstrained delegation. |
| `--gpos` | GPO names + paths. |
| `--admin-objects` | adminCount=1 objects. |
| `-s TERM` | Fuzzy search cn/name/sAMAccountName. |
| `--custom 'FILTER'` | Arbitrary filter. |
| `--secure` | LDAPS. `-p ''` / omit creds entirely = anonymous attempt. |
| `-o DIR` | Write results to files. |

## bloodhound-ce-python flags

| Flag | Meaning |
|---|---|
| `-u USER -p PASS` | Creds. `--hashes LM:NT` or `:NT` for PtH. `-k` Kerberos (ccache via KRB5CCNAME), `--aesKey` AES. |
| `-d example.com` | Domain (FQDN). |
| `-ns IP` | Nameserver — point at the DC. `--dns-tcp` for tunneled DNS, `--dns-timeout N`. |
| `-dc FQDN` / `-gc FQDN` | Override DC/GC host selection. |
| `-c METHODS` | `Default` (Group,LocalAdmin,Session,Trusts), `Group`, `LocalAdmin`, `Session`, `LoggedOn` (needs admin), `Trusts`, `ACL`, `ObjectProps`, `RDP`, `DCOM`, `PSRemote`, `Container`, `DCOnly` (LDAP-only, no host connections), `All`. Comma-separate. |
| `--zip` | Single zip of all JSON — upload as-is to BloodHound CE file ingest. |
| `-w N` | Worker threads for host-based collection (default 10). |
| `--computerfile FILE` | Restrict host collection to listed computers. |
| `--use-ldaps` | LDAPS for collection. |
| `-op PREFIX` | Output filename prefix. |

**CE vs legacy:** BloodHound CE's ingest schema differs from legacy 4.x. Use
`bloodhound-ce-python` (and SharpHound ≥ CE versions) for CE; legacy
`bloodhound-python` output will be rejected or mis-ingested.

Suggested CE Cypher starters after ingest: `Shortest paths to Domain Admins`,
`Kerberoastable users`, `Unconstrained delegation systems`, mark cracked accounts
as Owned and re-run `Shortest paths from Owned principals`.

— vulture (silver-pinnacle)
