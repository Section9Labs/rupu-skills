# recon — detailed phased methodology

This is the long-form companion to `SKILL.md`. Same five phases, more depth,
plus the framework mapping and the full routing table.

## Framework mapping

| Phase | PTES | OSSTMM | MITRE ATT&CK |
|---|---|---|---|
| 1. Discovery | Intelligence Gathering — footprinting, external/internal | Visibility audit (which targets exist on each channel) | T1595 Active Scanning, T1590 Gather Victim Network Info |
| 2. Port scanning | Intelligence Gathering — port scanning | Access verification (which access points respond) | T1595.001 Scanning IP Blocks, T1046 Network Service Discovery |
| 3. Service/OS detect | Intelligence Gathering — service identification, OS fingerprinting | Access verification depth | T1046 Network Service Discovery |
| 4. Per-protocol enum | Vulnerability Analysis boundary; feeds Threat Modeling | Trust verification, controls verification | TA0007 Discovery: T1087 Account Discovery, T1135 Network Share Discovery, T1018 Remote System Discovery, T1482 Domain Trust Discovery, T1016 System Network Configuration Discovery |
| 5. Normalize & hand off | Transition into Vulnerability Analysis / Exploitation | Metrics: what was actually verified (rav-style coverage) | — (reporting/coverage) |

OSSTMM's useful discipline here: track **coverage**, not just hits. Every
host×port×channel in scope is either verified-open, verified-closed, filtered,
or not-yet-tested. The `coverage-assets` skill plus `assets.mark` implements
exactly that ledger; feed it from phase 5.

## Phase 1 — Scope intake & host discovery

Intake artifacts: CIDR list, explicit host lists, domain names, sometimes VPN
or VLAN access notes. Normalize all of it into per-segment target files first.

**Internal segments** — load **`host-discovery`**:

- `arp-scan -I eth0 --localnet` — authoritative on the local L2 segment;
  finds ICMP-dropping hosts, reveals vendor OUIs (printers, cameras, ESXi).
- `fping -a -q -g 192.0.2.0/24` — fast ICMP sweep for routed segments.
- `zmap -p 445 198.51.100.0/16 -o hits.txt` — single-port async discovery at
  /16+ scale (pick a port that is near-universally open in the environment:
  445 on Windows estates, 22 on Unix estates).
- `netdiscover -r 192.0.2.0/24 -P` — passive-capable ARP alternative.
- Passive bonus: watch broadcast traffic (LLMNR/NBNS/mDNS/DHCP) for hosts
  that announce themselves; the `host-discovery` skill covers this.

**Multi-probe discovery through filtering** — load **`nmap`**:

```
nmap -sn -PE -PP -PS21,22,25,80,443,445,3389 -PA80,443 -PU40125,53 \
     -n 192.0.2.0/24 -oA discovery
```

ICMP echo + timestamp + TCP SYN/ACK probes + UDP catches most filtered hosts.
As root, nmap also ARP-scans local segments automatically during `-sn`.

**External / domain scope** — load **`dns-recon`** first:

- Subdomain enumeration (brute force + passive sources + cert transparency).
- Zone transfer attempts against every NS (`dig axfr example.com @ns1.example.com`).
- PTR sweeps across the netblocks the org owns.
- SRV discovery when any AD exposure is suspected.
- Resolve everything, dedupe to IPs, and feed those into phase 2 alongside
  any literal CIDRs in scope.

**Output contract:** `live-hosts.txt` per segment, one IP per line, plus a
hostname→IP map from the DNS leg. If discovery is unreliable (strict
filtering), do NOT trust it — fall through to scanning the full scope in
phase 2 with masscan/naabu; dead space is cheap at high rates.

## Phase 2 — Port scanning (two-pass)

**Why two passes:** `-sV`/NSE against closed-or-filtered space is where scans
go to die. Pass A answers "which (host, port) pairs are open" as fast as
possible; pass B spends the expensive probes only on confirmed-open pairs.

**Pass A tool choice:**

| Situation | Tool / skill |
|---|---|
| /16 or larger, or 65k-port sweeps across many hosts | **`masscan`** — `masscan -iL live-hosts.txt -p1-65535 --rate 20000 -oJ out.json`; add `U:53,U:161,U:500,U:1900` for UDP; tune `--rate` to the pipe |
| Host-list driven, want JSON + CDN awareness | **`naabu`** — `naabu -list live-hosts.txt -p - -rate 10000 -json -o naabu.json` (`-p -` = full range, `-top-ports 1000` for a quick pass) |
| Small/medium host list, want speed + direct nmap chaining | **`rustscan`** — `rustscan -a live-hosts.txt --ulimit 5000 -g > rustscan.txt`, or `rustscan -a 192.0.2.10 -- -sV -sC -oA deep` to pipe hits straight into nmap |
| Small scope, want one authoritative pass | **`nmap`** — `nmap -sS -p- --min-rate 2000 -T4 -iL live-hosts.txt -oA full` |

**Pass B — authoritative confirmation.** Masscan/naabu/rustscan race the
network; always re-verify hits with nmap and get `-oA` XML for phase 5:

```
nmap -sS -p 22,80,135,139,389,445,1433,3389,5985 192.0.2.10 -sV -O -sC -oA 192.0.2.10-deep
```

**UDP is mandatory, not optional.** `nmap -sU --top-ports 100 -iL live-hosts.txt
-oA udp` at minimum; prioritize 53 (DNS), 69 (TFTP), 111 (portmap), 123 (NTP),
161 (SNMP), 500/4500 (IKE), 1900 (SSDP). Mark `open|filtered` UDP ports as
"probe with the protocol's own tool" — snmp-enum and ike-scan resolve the
ambiguity better than nmap retries do.

## Phase 3 — Service, version, OS detection

Load **`nmap`**. On pass-B targets:

- `-sV` version probes; `--version-intensity 9` on nonstandard ports; read
  `servicefp` in the XML when nmap can't match (raw banner is still gold).
- `-O` / `-A` OS detection; corroborate with TTLs, SMB `smb-os-discovery`,
  and service banners.
- `-sC` default scripts, then targeted NSE per service:
  `smb-os-discovery,smb-security-mode,smb2-security-mode`, `ssl-cert`,
  `rdp-ntlm-info`, `nfs-ls,nfs-showmount`, `snmp-info`, `ldap-rootdse`,
  `dns-nsid`, `banner`.
- Keep every run as `-oA` — phase 5's normalizer eats the XML, including
  script output, hostnames, and OS matches.

Read the output with intent: product+version strings route exploitation
(Samba vs Windows, OpenSSH version, IIS vs nginx), `smb2-security-mode:
signing not required` is a relay finding on the spot, an `ldap` port with a
rootDSE naming context identifies the AD domain and DC role immediately.

## Phase 4 — Per-protocol enumeration

Full routing table (primary + secondary ports):

| Port(s) | Proto | Service | Skill | What you're after |
|---|---|---|---|---|
| 445, 139 | tcp | SMB | **`smb-enum`** | null/guest sessions, shares, spidered files, RID-cycled users, signing, dialects, OS build |
| 135 (+49152-65535) | tcp | MSRPC | **`smb-enum`** | endpoint mapper, interface enum, rpcclient queries |
| 389, 636, 3268, 3269 | tcp | LDAP(S) / Global Catalog | **`ldap-ad-enum`** | rootDSE, naming contexts, anonymous bind, users, groups, SPNs (kerberoast targets), delegation, LAPS/gMSA readability, domain/forest layout |
| 88, 464 | tcp/udp | Kerberos | **`ldap-ad-enum`** | confirms DC; user enum / pre-auth checks per that skill |
| 53 | tcp/udp | DNS | **`dns-recon`** | zone transfers, SRV records (`_ldap._tcp.dc._msdcs.<domain>`), PTR sweeps, subdomains, internal namespace map |
| 111 | tcp/udp | portmap/rpcbind | **`nfs-enum`** | registered RPC programs (mountd, nfs, nlockmgr) |
| 2049 | tcp/udp | NFS | **`nfs-enum`** | exports, mountability, no_root_squash, loot (keys, configs, backups) |
| 161 (162) | udp | SNMP | **`snmp-enum`** | community strings, full walks, interfaces/routes/ARP, running processes & software, often plaintext creds in config MIBs |
| 500, 4500 | udp | IKE/IPsec | **`ike-scan`** | gateway fingerprint, supported transforms, aggressive mode, PSK hash capture |
| 22 | tcp | SSH | **`netexec`** | banner/auth-method recon, credential testing |
| 1433 | tcp | MSSQL | **`netexec`** | instance info, auth testing, xp_cmdshell reach |
| 3389 | tcp | RDP | **`netexec`** | NLA state, cred validation, screenshotting |
| 5985, 5986 | tcp | WinRM | **`netexec`** | credentialed exec surface |
| 123 | udp | NTP | (nmap NSE `ntp-info`/`ntp-monlist`) | version, monlist amplification, internal addresses |
| 25, 587 | tcp | SMTP | (nmap NSE + manual VRFY/EXPN) | user enum, open relay |
| 21 | tcp | FTP | (nmap NSE `ftp-anon`) | anonymous access, writable dirs |
| 80, 443, 8080... | tcp | HTTP(S) | hand to the web pack | out of this pack's scope; still goes into inventory + work units |

**`netexec` is cross-cutting, not port-bound.** Run it at three moments:

1. Uncredentialed, right after phase 3: `nxc smb targets.txt` for signing/
   OS/domain triage; null and guest session checks across the estate.
2. First credential obtained (SNMP leak, NFS loot, default creds, spray hit):
   sweep **every** protocol with it — smb, ldap, winrm, mssql, rdp, ssh, wmi —
   to map where that identity reaches (`nxc smb targets.txt -u user -p pass`,
   `--shares`, `--sessions`, `--loggedon-users`, ldap `--kerberoasting`...).
3. Password spraying windows, per the netexec skill's lockout-aware guidance.

**Recon is a loop.** Phase 4 output (new hostnames from SMB, new subnets from
SNMP route tables, new DCs from DNS SRV) feeds back into phase 1/2 for the
newly discovered space. Iterate until no new assets appear.

## Phase 5 — Normalize & hand off

1. Collect raw outputs: all nmap `-oX`/`-oA` XML, masscan `-oJ/-oL/-oG/-oX`,
   naabu JSON or `host:port` lines, rustscan `-g` lines.
2. `python3 scripts/normalize_inventory.py <files...> -o inventory.json` —
   merges on (host, port, proto), prefers the record with service/version
   detail, tracks per-entry `source`.
3. `python3 scripts/inventory_to_workunits.py inventory.json -o work-units.json`
   — one unit per enumerable service grouping, hints naming the sub-skill;
   plus an aggregate netexec-sweep unit over all netexec-capable hosts. The
   file is a bare JSON array (first byte `[`) by contract.
4. Wire into rupu per `references/rupu.md`:
   - `read_file` + `for_each:` over `work-units.json` (or lead-agent
     `dispatch`, one subagent per unit),
   - `assets.mark` for every host/service (coverage ledger),
   - `findings.report` for every verified issue found during recon
     (SMB signing disabled, null sessions, AXFR allowed, public/private SNMP,
     world-mountable NFS, IKE aggressive mode with PSK hash captured,
     anonymous LDAP binds, guest shares...).
5. Load the shared skills **`work-units`**, **`coverage-assets`**, and
   **`finding-report`** for the exact schemas — this pack conforms to them,
   it does not redefine them.

The handoff consumers: exploitation pack (per-service attack skills keyed by
product/version in inventory), credential-attack pack (spray/roast targets
from ldap-ad-enum + netexec units), and reporting (findings + coverage).
