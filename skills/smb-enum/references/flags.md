# SMB Enumeration — Flag Catalog

Deep flag reference for the tools used in `smb-enum`. Example target: 192.0.2.10,
domain EXAMPLE / example.com.

## enum4linux-ng

```
enum4linux-ng [options] <target>
```

| Flag | Meaning |
|---|---|
| `-A` | All *simple* enumeration: `-U -G -S -P -O -L -I -N` equivalent. **Does not include** `-R` (RID cycling) or `-Gm` (group members). |
| `-As` | Like `-A` but skips NetBIOS/session checks that need 139. |
| `-U` | Users via SAMR (`enumdomusers`). |
| `-G` | Groups via SAMR. |
| `-Gm` | Group members (slow on big domains, worth it). |
| `-S` | Shares via srvsvc. |
| `-P` | Password policy via SAMR. |
| `-O` | OS info via srvinfo + SMB negotiation. |
| `-L` | LSA policy / domain SID (`lsaquery`). |
| `-I` | Printers (`enumprinters`). |
| `-N` | LDAP/NetBIOS domain name info. |
| `-R [range]` | RID cycling. Default `500-550,1000-1050`. Big domain: `-R 500-10000`. Needs the domain SID (fetched automatically via lsaquery or known-SID brute). |
| `-u USER` / `-p PASS` | Credentials. Empty strings = explicit null session: `-u '' -p ''`. |
| `-w DOMAIN` | Workgroup/domain for the bind (`EXAMPLE`). |
| `-K USER` | Use Kerberos (needs ccache). |
| `-H NTHASH` | Pass-the-hash instead of `-p`. |
| `-oY/-oJ/-oA FILE` | YAML / JSON / both. No extension — tool appends `.yaml`/`.json`. |
| `-d` | Detailed/verbose output. |
| `-t SECS` | Per-request timeout (default 5). Raise on slow links. |
| `-k USERS` | Known usernames for session checks (comma-separated, default `administrator,guest,krbtgt,domain admins,root,bin,none`). |

Behavior notes:
- SIGINT (Ctrl-C) triggers a graceful dump of everything collected so far into
  the `-oY/-oJ` files. Abort long RID cycles freely.
- Null, guest and credentialed attempts can be compared by running three times
  with different `-u/-p` and separate `-oY` files.

### YAML keys worth grepping

```
grep -E 'signing|dialect|SMB1|domain|os_|nativ' e4l_192.0.2.10.yaml
```

`smb1_supported`, `smb_signing_required`, `os_version`/`os_build`,
`domain`, `workgroup`, `users:`, `groups:`, `shares:`, `policy:` (lockout
threshold/duration/reset, min length, complexity, history), `printers:`,
`sessions:`, `domain_sid`.

## smbmap

| Flag | Meaning |
|---|---|
| `-H HOST` / `--host-file FILE` | Target(s). |
| `-u USER -p PASS` | Creds. Null: `-u '' -p ''`. Guest: `-u guest -p ''`. Hash: `-p 'LMHASH:NTHASH'` or `aad3b435b51404eeaad3b435b51404ee:NTHASH`. |
| `-d DOMAIN` | Domain (default WORKGROUP). |
| `-P PORT` | SMB port (default 445). |
| `-r [PATH]` | List one directory level (`-r 'C$\Users'`). |
| `-R [PATH]` | Recursive listing. `--depth N` limits recursion (default 5). |
| `-A REGEX` | Auto-download files whose name matches the pattern during `-r/-R`. |
| `-g FILE` | Grep-able output; `--csv FILE` CSV output — both parse-friendly. |
| `-x CMD` | Execute command (wmiexec-style; needs admin). `--mode wmi|psexec`. |
| `--download PATH` | Download one file: `--download 'Share\dir\file.txt'` (saved locally with path mangled). |
| `--upload SRC DST` | Upload: `--upload '/tmp/x.exe' 'C$\Windows\Temp\x.exe'`. |
| `--delete PATH` / `--skip` | Delete remote file / skip delete confirmation. |
| `-q` | Only show readable/writable shares (quieter sweeps). |
| `--exclude SHARE` | Skip shares (e.g. `--exclude IPC$ print$`). |
| `--no-banner`, `--no-color` | Clean output for parsing. |

Permission strings in output: `NO ACCESS`, `READ ONLY`, `READ, WRITE` — the parser
maps these to `access` values `none|read|read,write`.

## smbclient

| Flag | Meaning |
|---|---|
| `-L //HOST` | List shares. |
| `-N` | No password (null). |
| `-U 'DOM\user%pass'` | Creds inline (`%` separates password). |
| `-m SMB2` / `-m SMB3` / `-m NT1` | Force max dialect. `-m NT1` succeeding = SMBv1 enabled. |
| `-c 'cmds'` | Semicolon-separated commands, non-interactive. |
| `-k` / `--use-kerberos=required` | Kerberos auth from ccache. |
| `--pw-nt-hash` | Treat `%pass` as an NT hash (pass-the-hash). |
| `-p PORT`, `-I IP` | Alt port, force IP while keeping NetBIOS name. |
| `-t SECS` | Timeout. |

Internal commands: `ls`, `cd`, `get`, `put`, `mget`, `mput`, `recurse ON`,
`prompt OFF`, `mask <glob>` (filter for mget/mput), `tar c backup.tar *`
(tar a whole tree), `allinfo file` (timestamps/streams — look for ADS),
`showacls` toggle, `rename`, `rm`, `mkdir`, `logon` (re-auth as another user).

## rpcclient

Connection: `rpcclient -U 'DOM\user%pass' 192.0.2.10`, null = `-U '' -N`,
hash = `--pw-nt-hash -U 'user%NTHASH'`, batch = `-c 'cmd1;cmd2'`.

### SAMR
- `enumdomusers` — RID + name of every user.
- `enumdomgroups` / `enumalsgroups builtin|domain` — groups / aliases.
- `querygroup 0x200`, `querygroupmem 0x200` — group detail/members (0x200 = Domain Admins, 0x201 Domain Users, 0x203 Domain Computers, 0x208 is not standard — use `enumdomgroups` for real RIDs).
- `queryuser <rid>` — full user record: logon count, bad pw count, last logon, description, home dir, profile. `0x1f4` = 500 Administrator, `0x1f5` = 501 Guest, `0x1f6` = 502 krbtgt.
- `querydispinfo` — users with full names + descriptions in one call (often where description-passwords show up).
- `getdompwinfo` — min length + password properties bitmask (complexity).
- `getusrdompwinfo <rid>` — effective policy for one user.
- `querydominfo` — domain name, user/group totals, lockout data on some levels.
- `createdomuser`, `deletedomuser`, `setuserinfo2 <user> 23 'NewPass!'` — write ops (admin; `setuserinfo2 ... 23` = force-set password, destructive to the old one).

### LSARPC
- `lsaquery` — domain name + SID.
- `lookupnames administrator guest krbtgt` — names → SIDs.
- `lookupsids S-1-5-21-...-500 S-1-5-21-...-501` — SIDs → names. Manual RID cycle:
  ```
  for r in $(seq 500 4000); do rpcclient -U '' -N 192.0.2.10 -c "lookupsids S-1-5-21-1111111111-2222222222-3333333333-$r" ; done | grep -v unknown
  ```
- `enumtrust` / `enumdomains` — trusts.
- `lsaenumsid` — SIDs with privileges on the box; `lookupsids` them.
- `dsroledominfo` — DS role: primary DC, backup DC, member, standalone.

### SRVSVC / spooler
- `srvinfo` — platform, version major.minor, server type bits (0x8000 = NT server, 0x8 = DC flags visible in combined masks).
- `netshareenumall` / `netsharegetinfo <share>` — shares with path + remark; getinfo level 502 shows the security descriptor.
- `netsessenum`, `netconnenum` — active sessions/connections (who is on the box).
- `enumprinters` — print spooler reachable ⇒ PrinterBug/coercion candidate.

## nbtscan / nmblookup

```
nbtscan 192.0.2.0/24
nbtscan -v -s : 192.0.2.0/24     # verbose, ':'-separated → script-friendly
nbtscan -r 192.0.2.0/24          # use local port 137 (needed for some old stacks)
nmblookup -A 192.0.2.10          # node status: full name table
nmblookup 'EXAMPLE'              # resolve a NetBIOS name via broadcast
```

Name-table suffixes (`nmblookup -A`):

| Suffix | Type | Meaning |
|---|---|---|
| `<00>` | UNIQUE | Workstation/computer name |
| `<00>` | GROUP | Domain/workgroup name |
| `<03>` | UNIQUE | Messenger — frequently the logged-on user |
| `<20>` | UNIQUE | File server service (SMB active) |
| `<1b>` | UNIQUE | Domain master browser = **PDC emulator (DC)** |
| `<1c>` | GROUP | Domain controllers group |
| `<1d>` | UNIQUE | Local master browser |
| `<1e>` | GROUP | Browser elections |

`MAC Address: 00-00-00-00-00-00` usually means Samba, a real vendor MAC means Windows.

## Signing / SMBv1 quick checks

```
nmap -p445 --script smb2-security-mode 192.0.2.0/24          # "Message signing enabled but not required" = relayable
nmap -p445 --script smb-security-mode 192.0.2.10             # SMB1-era signing field
nmap -p139,445 --script smb-protocols 192.0.2.10             # dialects incl. NT LM 0.12 (SMBv1)
nmap -p445 --script smb-vuln-ms17-010 192.0.2.10             # EternalBlue check
smbclient -L //192.0.2.10 -N -m NT1                          # succeeds ⇒ SMBv1 on
```

DCs require signing by default — a DC with signing not required is doubly notable.
Member servers/workstations default to "enabled but not required" ⇒ typical relay fodder.

— vulture (silver-pinnacle)
