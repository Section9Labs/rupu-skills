---
name: smb-enum
description: SMB / MSRPC / NetBIOS enumeration (ports 139/445, 135, 137) with enum4linux-ng, smbmap, smbclient, rpcclient and nbtscan — null/guest/authenticated sessions, share walking, RID cycling, password policy, signing and SMBv1 checks. Use when recon finds 445/139/135/137 open on a target; outputs user lists, relay targets and work units for follow-on skills.
license: Apache-2.0
compatibility: linux
metadata:
  author: Section9Labs
---

# SMB / MSRPC / NetBIOS Enumeration

Triggered from the `recon` flow when a host exposes **445/tcp or 139/tcp (SMB)**,
**135/tcp (MSRPC endpoint mapper)** or **137/udp (NetBIOS-NS)**. Goal: extract the
domain picture (domain name, DC role, OS build), the share landscape (names + R/W),
the account landscape (users, groups, password policy), and the relay/exploit
posture (signing state, SMBv1) — then hand clean work units to the next skill.

Import the shared reporting pack by name: **`work-units`**, **`coverage-assets`**,
**`finding-report`**. Do not re-implement their formats. See `references/rupu.md`
for how this skill's output feeds them.

For credentialed sweeps and password spraying across many hosts, hand off to the
**`netexec`** skill — do not duplicate it here. For NSE depth
(`smb-vuln-*`, `smb-os-discovery`, `smb-security-mode`, …) see the **`nmap`** skill.

## 1. Session types — try all three, in order

| Session | Flags | Typically yields |
|---|---|---|
| **Null** | `-u '' -p ''` (enum4linux-ng/smbmap), `-N` (smbclient/rpcclient) | On old/misconfigured hosts and many DCs: domain info, user list via RID cycling, pass-pol, share list. On hardened hosts: nothing but the negotiation (still gives signing/dialect). |
| **Guest** | `-u 'guest' -p ''` or any random user + empty/any password where guest is enabled | Share list and often READ on open shares; sometimes RID cycling where null fails. |
| **Authenticated** | `-u user -p pass [-d EXAMPLE]`, or hashes where the tool supports them | Full SAMR/LSA enumeration, all readable shares, group memberships. Any domain account works against a DC — low-priv is enough. |

A null session that returns *anything* (users, shares, policy) is itself a finding.
Report it via `finding-report`.

## 2. enum4linux-ng — the all-in-one first pass

```
enum4linux-ng -A -R -Gm 192.0.2.10 -oY e4l_192.0.2.10
```

- `-A` = "do everything" **except** RID cycling and group members. Always add
  `-R` (RID cycling, default range 500-550,1000-1050 — widen with `-R 500-4000`)
  and `-Gm` (group members).
- Credentialed: `-u lowpriv -p 'Spring2024!' -w EXAMPLE` (`-w` = workgroup/domain).
- Output: `-oY file` (YAML), `-oJ` (JSON), `-oA` (both). **Ctrl-C still writes the
  state collected so far** — safe to abort a slow RID cycle.
- Useful extras: `-S` shares only, `-U` users only, `-P` pass-pol only,
  `-O` OS info only, `-d` detailed output, `-t 10` timeout per request.

Read the YAML (`e4l_192.0.2.10.yaml`):

- `smb_dialects` → highest/lowest dialect; `SMB 1.0` supported ⇒ **SMBv1 finding**
  (EternalBlue candidate — confirm with `nmap --script smb-vuln-ms17-010`).
- `smb_signing_required: false` ⇒ **relay target** (goes on relay-targets.txt).
- `os_info` → OS version/build (exploit selection), server type flags (DC role).
- `domain`, `workgroup`, `naming_context`-style fields → feeds `ldap-ad-enum`.
- `users` (from SAMR and/or RID cycling) → spray list for `netexec`.
- `groups` + members → who is in Domain Admins / Administrators.
- `shares` → candidates for walking (section 4).
- `policy` → lockout threshold/duration, min length, complexity. **Read lockout
  threshold before any spray** and pass it in the work-unit hints.
- `printers`, `sessions` → logged-on users and spooler presence (PrinterBug/
  coercion angle).

## 3. smbmap — permissions at a glance

```
smbmap -H 192.0.2.10                          # null
smbmap -H 192.0.2.10 -u guest -p ''           # guest
smbmap -H 192.0.2.10 -u lowpriv -p 'Spring2024!' -d EXAMPLE
```

Output is a table: `Disk  Permissions  Comment` with `READ ONLY`, `READ, WRITE`,
`NO ACCESS`. WRITE on a share = payload-drop / lateral candidate; WRITE on
`SYSVOL`/`NETLOGON` is a critical finding on its own.

Deeper:

```
smbmap -H 192.0.2.10 -u lowpriv -p 'Spring2024!' -r 'Public'          # list one level
smbmap -H 192.0.2.10 -u lowpriv -p 'Spring2024!' -R 'Public' --depth 10
smbmap -H 192.0.2.10 -u lowpriv -p 'Spring2024!' -R 'Public' -A '\.(kdbx|config|xml|ps1|vbs|bat|ini|txt)$'   # auto-download matches
smbmap -H 192.0.2.10 -u lowpriv -p 'Spring2024!' --download 'Public\web.config'
smbmap -H 192.0.2.10 -u admin -p 'pass' --upload '/tmp/shell.exe' 'C$\Windows\Temp\shell.exe'
smbmap -H 192.0.2.10 -u admin -p 'pass' -x 'ipconfig /all'            # exec (admin needed)
```

`-x` executing a command means you have admin — stop enumerating, you own the box;
record it and hand off to post-exploitation. Hash auth: `-u admin -p 'LMHASH:NTHASH'`.
Many hosts: `--host-file hosts.txt` (but prefer `netexec` for sweeps).

## 4. smbclient — list and walk shares

```
smbclient -L //192.0.2.10 -N                          # share list, null
smbclient -L //192.0.2.10 -U 'EXAMPLE\lowpriv%Spring2024!'
```

Walk a share non-interactively:

```
smbclient //192.0.2.10/Public -N -c 'recurse ON; prompt OFF; ls'
```

Mass download / targeted fetch:

```
smbclient //192.0.2.10/Public -N -c 'recurse ON; prompt OFF; mget *'
smbclient //192.0.2.10/Public -N -c 'cd scripts; get login.ps1'
smbclient //192.0.2.10/Public -N -c 'recurse ON; prompt OFF; mask *.config; mget *'
smbclient //192.0.2.10/Public -U 'EXAMPLE\user%pass' -c 'put /tmp/note.txt note.txt'
```

Force dialect when needed: `-m SMB2` / `-m NT1` (NT1 succeeding ⇒ SMBv1 present).
Kerberos: `-k` with a valid ccache. Interesting share priorities:
`SYSVOL`/`NETLOGON` (GPP passwords, logon scripts), `C$`/`ADMIN$` (admin test),
IT/backup/home shares (creds in configs, `unattend.xml`, `web.config`, `.kdbx`).

## 5. rpcclient — raw SAMR / LSARPC over MSRPC

```
rpcclient -U '' -N 192.0.2.10                         # null bind
rpcclient -U 'EXAMPLE\lowpriv%Spring2024!' 192.0.2.10
```

Core command sequence inside the shell (or batch via
`rpcclient -U '' -N 192.0.2.10 -c 'srvinfo;enumdomusers;...'`):

| Command | Yields |
|---|---|
| `srvinfo` | OS version + server type bitmask (0x9003 etc. — DC role) |
| `querydominfo` | domain name, total users/groups counts |
| `enumdomusers` | all users with RIDs → spray list |
| `enumdomgroups` / `querygroup 0x200` / `querygroupmem 0x200` | groups, Domain Admins (RID 0x200) membership |
| `queryuser 0x1f4` | RID 500 = built-in Administrator (even if renamed): last logon, bad pw count, description |
| `getdompwinfo` / `getusrdompwinfo 0x1f4` | password policy — min length, complexity, lockout |
| `lsaquery` | domain SID (needed for RID cycling / sid-brute) |
| `lookupnames administrator` / `lookupsids S-1-5-21-...-500` | name↔SID resolution; manual RID cycling: loop `lookupsids <domainSID>-{500..4000}` |
| `enumdomains` / `dsroledominfo` | trusted/hosted domains, DC role |
| `netshareenumall` / `netsharegetinfo <share>` | shares + paths + ACL hints |
| `enumprinters` | spooler/printers (coercion angle) |
| `createdomuser` / `setuserinfo2` | only with admin rights — account manipulation |

If `enumdomusers` is denied but `lookupsids` works, RID-cycle manually or rerun
enum4linux-ng with `-R`.

## 6. NetBIOS (137/udp)

```
nbtscan 192.0.2.0/24                 # sweep: name, workgroup, MAC, logged user
nbtscan -v -s : 192.0.2.0/24         # verbose, parse-friendly separator
nmblookup -A 192.0.2.10              # single host name table
```

Suffix decoding in `nmblookup -A` output: `<00>` workstation name / (group) =
domain, `<20>` file server service running, `<1b>` domain master browser (**PDC
emulator — this is a DC**), `<1c>` (group) = domain controllers group, `<03>`
messenger (often logged-on username). NetBIOS gives you hostnames and DC
identification even with zero SMB access.

## 7. Signing + SMBv1 posture

enum4linux-ng reports both, but confirm/sweep fast:

```
nmap -p445 --script smb-security-mode,smb2-security-mode,smb-protocols,smb-os-discovery 192.0.2.0/24 -oA smb_posture
```

(Full NSE detail in the `nmap` skill.) For a one-liner sweep across a subnet,
`netexec smb 192.0.2.0/24` prints `signing:False` and `SMBv1:True` per host —
see the `netexec` skill.

- `message_signing: disabled` / `Message signing enabled but not required` ⇒
  host belongs on **relay-targets.txt** (ntlmrelayx targets).
- SMBv1 enabled ⇒ run `smb-vuln-ms17-010`; a vulnerable result is a critical finding.

## 8. Parse and hand off

```
python3 scripts/parse_smb.py \
  --host 192.0.2.10 \
  --e4l e4l_192.0.2.10.yaml \
  --smbmap smbmap_192.0.2.10.txt \
  --rpc rpcclient_192.0.2.10.txt \
  -o smb_192.0.2.10
```

Writes to `smb_192.0.2.10/`:

- `inventory.json` — `{host, domain, signing, smbv1, os, shares:[{name,access}], users:[], groups:[], pass_pol:{...}}`
- `users.txt` — one sAMAccountName per line → spray input for `netexec`
- `relay-targets.txt` — hosts with signing not required → ntlmrelayx `-tf`
- `work_units.json` — clean JSON **array** `[{id,title,targets,hints}]`

Work units generated: walk each readable share, spray the user list
(lockout threshold embedded in hints), relay against unsigned hosts, MS17-010
check when SMBv1, pivot to `ldap-ad-enum` when a DC was identified.

**Handoff map:**

| Harvest | Outcome / next skill |
|---|---|
| Domain name + DC role | `ldap-ad-enum` against the DC; domain asset via `assets.mark` |
| `signing: false` | relay-targets.txt → ntlmrelayx; finding via `finding-report` |
| Shares + R/W | share-walk work units; WRITE share → payload drop / lateral |
| User list | spray via `netexec`; kerberoast/AS-REP checks via `ldap-ad-enum` |
| Pass-pol | lockout-safe spray parameters in hints |
| OS build | exploit selection |
| SMBv1 | ms17-010 verification work unit; finding if confirmed |
| Null session worked | finding via `finding-report` |

See `references/rupu.md` for feeding `work_units.json` into a rupu `for_each:` /
`dispatch`, marking coverage assets, and reporting findings.
Deep flag catalog: `references/flags.md`.
