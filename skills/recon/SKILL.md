---
name: recon
description: Umbrella orchestrator for network reconnaissance and enumeration — drives the full phased flow (host discovery, port scanning, service/OS detection, per-protocol enumeration, inventory normalization) and routes each phase to the right sub-skill; load it at the start of any internal or external assessment to plan and sequence the recon pack.
license: Proprietary
metadata:
  author: Section9Labs
  pack: recon
  phase-model: PTES Intelligence Gathering / MITRE ATT&CK TA0007
---

# recon — umbrella skill for network reconnaissance & enumeration

This is the index skill for the recon pack. It does not replace the sub-skills;
it tells you **which one to load, when, and what to feed it**. The flow below maps
to PTES *Intelligence Gathering* and the standard internal/external network
methodology; the per-protocol phase is MITRE ATT&CK **Discovery (TA0007)** in
practice, and the channel-by-channel coverage discipline comes from OSSTMM
(enumerate every channel you can reach, measure what you actually verified).

Depth lives in `references/flow.md` (full methodology + routing table) and
`references/rupu.md` (handoff wiring). Helper scripts live in `scripts/`.

## The five phases

```
1. Scope intake & host discovery   -> live-host list
2. Port scanning (fast -> deep)    -> open-port map
3. Service / version / OS detect   -> fingerprinted services
4. Per-protocol enumeration        -> shares, users, zones, configs, creds
5. Normalize & hand off            -> inventory.json + work-units.json (rupu)
```

Each phase's output is the next phase's input. Never skip a phase forward
(e.g. deep-scanning a range you haven't swept) — you waste hours and miss hosts.

---

## Phase 1 — Scope intake & host discovery

Turn the engagement scope (CIDRs, host lists, domains) into a **live-host list**.

- Internal CIDRs / LAN segments: load the **`host-discovery`** skill for
  fping, zmap, arp-scan and netdiscover sweeps (ARP on the local segment is
  authoritative — it finds hosts that drop ICMP). Also load the **`nmap`**
  skill for `nmap -sn` combined probes (`-PE -PS22,80,443,445 -PA80 -PU53`)
  when you need multi-probe discovery through filtering.
- External / domain scope: load the **`dns-recon`** skill first — subdomain
  enumeration, zone transfers, PTR sweeps and cert transparency turn
  `example.com` into IP ranges and host lists before you ever send a SYN.

Output of this phase: `live-hosts.txt` (one IP per line) per scope segment.

## Phase 2 — Port scanning (two-pass, always)

**Pass A — fast and wide.** Find open ports across the whole live-host list:

- Load the **`masscan`** skill for very large ranges (/16 and up, or full
  65k-port sweeps) — its async engine covers huge space at a chosen rate.
- Load the **`rustscan`** skill for fast full-port scans of small-to-medium
  host lists with direct nmap handoff (`rustscan -a hosts.txt -- -sV ...`).
- Load the **`naabu`** skill for CDN-aware, host-list-driven sweeps with
  clean JSON output that pipes into later tooling.

**Pass B — deep per host.** Feed only the hosts and ports that came back open
into authoritative scans. Load the **`nmap`** skill:
`nmap -sS -p <open-ports> -sV -O -sC` per host (and `-sU --top-ports 100`
for UDP — don't forget 53, 123, 161, 500).

**Rule: never run `-sV` blind across a whole range.** Version probes are slow
and noisy; fast sweep first, then version-probe only confirmed-open ports.
The decision guide below picks the pass-A tool.

## Phase 3 — Service & version detection + OS detection

Load the **`nmap`** skill. On the pass-B targets run `-sV` (version probes,
raise `--version-intensity 9` on odd ports), `-O` (OS fingerprinting), and
`-sC` / targeted NSE scripts (`smb-os-discovery`, `ssl-cert`, `banner`,
`*-info`). Always keep `-oA` output — the XML is what phase 5 ingests.
Fingerprints decide the phase-4 routing: an open 445 that is Samba routes
differently in exploitation than Windows Server 2019, so capture product
and version strings, not just port state.

## Phase 4 — Per-protocol enumeration (route by discovered service)

Pick the enumerator by what phase 3 found. Routing table:

| Port / proto              | Service          | Load this skill   |
|---------------------------|------------------|-------------------|
| 135, 139, 445 /tcp        | MSRPC, SMB       | **`smb-enum`**    |
| 389, 636, 3268, 3269 /tcp | LDAP / AD GC     | **`ldap-ad-enum`**|
| 53 /tcp+udp               | DNS              | **`dns-recon`**   |
| 111, 2049 /tcp+udp        | portmap, NFS     | **`nfs-enum`**    |
| 161 /udp                  | SNMP             | **`snmp-enum`**   |
| 500, 4500 /udp            | IKE / IPsec VPN  | **`ike-scan`**    |
| 22, 445, 389, 1433, 3389, 5985-5986 /tcp (cred sweeps) | ssh/smb/ldap/mssql/rdp/winrm/wmi | **`netexec`** |

- **`smb-enum`** — null/guest sessions, share listing and spidering, RID
  cycling, MSRPC endpoint enumeration, SMB signing and dialect checks.
- **`ldap-ad-enum`** — anonymous and authenticated LDAP, rootDSE, naming
  contexts, users/groups/SPNs/delegation, AD domain mapping.
- **`snmp-enum`** — community brute force, full MIB walks, interface/route/
  process/software extraction; SNMP read often leaks credentials outright.
- **`nfs-enum`** — showmount exports, mount and loot, UID/GID squashing checks.
- **`dns-recon`** — internal AD-integrated DNS enumeration, zone transfers,
  SRV records (`_ldap._tcp`, `_kerberos._tcp`) to map domain controllers.
- **`ike-scan`** — VPN gateway fingerprinting, aggressive-mode handshakes,
  PSK hash capture for offline cracking.
- **`netexec`** — the multi-protocol workhorse once you have *any* credential
  (or want to test null/guest/default): sweeps smb, ldap, winrm, mssql, ssh,
  rdp and wmi across the whole host list, sprays passwords, dumps what the
  cred reaches. Run it both uncredentialed (signing/null-session recon) and
  again every time the credential set grows.

Run every applicable enumerator against every host that exposes the service.
The full per-protocol checklists are in each sub-skill; `references/flow.md`
has the extended routing table including secondary ports.

## Phase 5 — Normalize & hand off

Fold every tool's output into **one** host→service inventory, then cut it into
work units the exploitation and credential-attack phases can consume.

```sh
# merge everything: nmap XML, masscan (-oJ/-oL/-oG/-oX), naabu, rustscan -g
python3 scripts/normalize_inventory.py \
    nmap-deep.xml masscan.json naabu.json rustscan.txt \
    -o inventory.json

# emit a rupu-ingestible JSON array of work units (first byte is '[')
python3 scripts/inventory_to_workunits.py inventory.json -o work-units.json
```

`inventory.json` is keyed by host: `{address, hostnames, os, ports:[{port,
proto, state, service, product, version, scripts, source}]}`. Every downstream
skill in the fleet reads this shape.

`work-units.json` is a clean JSON array `[{id,title,targets,hints}, ...]` —
one unit per enumerable service grouping ("Enumerate SMB on 192.0.2.10",
hints naming the sub-skill to load). A rupu workflow reads it with
`read_file` and fans out with `for_each:`; a lead agent can `dispatch` one
subagent per unit instead. Mark discovered hosts/services as coverage assets
with `assets.mark`, and report verified issues (null sessions, open NFS
exports, SNMP public, signing disabled...) with `findings.report`.

**Do not re-invent the handoff machinery.** Load the shared reporting-pack
skills by name: **`work-units`** (work-unit splitter contract),
**`coverage-assets`** (asset model), **`finding-report`** (finding writeup).
`references/rupu.md` shows the exact `for_each:`/`dispatch` wiring and the
`assets.mark` / `findings.report` calls for this domain's output.

---

## Decision guide

- **Default LAN segment (/24-ish):** `nmap -sn` (or arp-scan via
  `host-discovery`) → `nmap -sS -p-` on live hosts → phase 3 on open ports.
- **/16 or larger, or full-port across many hosts:** `masscan` or `naabu`
  fast sweep → `nmap -sV -sC` only on hits (two-pass rule).
- **External domain scope:** `dns-recon` first to build the host list, then
  `naabu`/`nmap` on the resolved addresses.
- **Local segment, stealth-of-ICMP irrelevant:** `arp-scan` beats everything
  for completeness (via `host-discovery`).
- **Have any credential at any point:** re-run `netexec` across the whole
  inventory immediately — recon is iterative, not linear.
- **UDP:** always sweep at least 53, 69, 111, 123, 161, 500, 1900 — SNMP and
  IKE are the most under-enumerated high-value services on internal nets.

## Worked walk-through — 192.0.2.0/24 + example.com

```sh
# Phase 1 — discovery (skills: host-discovery, nmap, dns-recon)
fping -a -q -g 192.0.2.0/24 > live-hosts.txt            # host-discovery
nmap -sn -PE -PS22,80,443,445 -PA80 -PU53 192.0.2.0/24 \
     -oA disc && grep 'Status: Up' disc.gnmap | awk '{print $2}' >> live-hosts.txt
# external leg: dns-recon skill on example.com -> subdomains + IPs
sort -u live-hosts.txt -o live-hosts.txt

# Phase 2 — ports (skills: masscan, nmap)
masscan -iL live-hosts.txt -p1-65535,U:53,U:161,U:500 --rate 20000 -oJ masscan.json
# collapse masscan hits into per-host port lists, then deep scan:
nmap -sS -sU -iL live-hosts.txt -p T:22,53,80,135,139,389,443,445,1433,2049,3389,5985,U:53,161,500 \
     -sV -O -sC -oA nmap-deep                            # Phase 3 folded in

# Phase 4 — enumerate by service (route per the table)
#  192.0.2.10  445/tcp open  microsoft-ds   -> load smb-enum, then netexec
#  192.0.2.10  389/tcp open  ldap (AD DC)   -> load ldap-ad-enum, dns-recon (SRV)
#  192.0.2.20  161/udp open  snmp           -> load snmp-enum
#  192.0.2.30  2049/tcp open nfs            -> load nfs-enum
#  192.0.2.1   500/udp open  isakmp         -> load ike-scan

# Phase 5 — normalize & hand off
python3 scripts/normalize_inventory.py nmap-deep.xml masscan.json -o inventory.json
python3 scripts/inventory_to_workunits.py inventory.json -o work-units.json
cat work-units.json   # -> [{"id":"wu-001-smb-192-0-2-10","title":"Enumerate SMB on 192.0.2.10",...}]
```

End state: `inventory.json` (single source of truth for the engagement) and
`work-units.json` (fan-out array for rupu / dispatch). See
`references/rupu.md` for the ingestion patterns and `references/flow.md`
for the full methodology.
