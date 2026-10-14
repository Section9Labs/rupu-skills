---
name: host-discovery
description: Layer-2/3 live-host discovery — turn a scope of CIDRs into a deduplicated live-host list before port scanning, using fping, arp-scan, netdiscover, nmap -sn, zmap and nbtscan, then merge all sources into one alive.txt and emit port-scan work units.
license: Proprietary
compatibility: Linux with fping, arp-scan, netdiscover, nmap, zmap, nbtscan installed; root/CAP_NET_RAW for raw-socket tools
metadata:
  author: Section9Labs
  phase: discovery
---

# Host Discovery

Goal: convert the scope (one or more CIDRs / ranges / host files) into a single
deduplicated `alive.txt` of responsive hosts BEFORE any port scanning. Port
scanning dead space wastes hours; discovery first makes every later phase
cheaper and more accurate.

## Pick the tool by position

| Where you sit relative to the target | First choice | Why |
|---|---|---|
| Same L2 segment (LAN, VPN bridged, dropped box) | `arp-scan` (then `nmap -sn`, which also ARPs locally) | ARP cannot be firewalled on-segment: any IP-speaking host MUST answer ARP. Near-100% reliable. |
| Local segment, must stay quiet | `netdiscover -p` | Purely passive — reads ARP traffic, sends nothing. |
| Remote routed networks, up to a few /16s | `fping` or `nmap -sn` | Fast parallel ICMP; nmap adds TCP/UDP probe combos when ICMP is filtered. |
| Very large / internet-scale ranges | `zmap` (or masscan-as-discovery) | Stateless single-probe sweep at line rate; discovery via one well-chosen port. |
| ICMP filtered, Windows-heavy estate | `nbtscan` (udp/137) + `nmap -sn` TCP probes | NetBIOS answers even where ping is dropped, and returns hostnames. |

Always run MORE THAN ONE method and merge: ICMP-only hosts, ARP-only hosts and
single-open-port hosts are different populations. The union is the truth.

## fping — fast ICMP sweep

```bash
# Sweep a CIDR, print only alive hosts, silence per-host errors
fping -a -g 203.0.113.0/24 2>/dev/null | tee fping.txt

# Explicit start-end range
fping -a -g 198.51.100.1 198.51.100.254 2>/dev/null

# From a file of targets (one IP/host per line)
fping -a -f targets.txt 2>/dev/null

# Tuning: 2 retries, 10ms between packets, 500ms per-target timeout, quiet
fping -a -q -r 2 -i 10 -t 500 -g 192.0.2.0/24 2>/dev/null
```

Flags that matter:
- `-a` — show alive hosts only (default prints alive AND unreachable).
- `-g` — generate targets from a CIDR or `start end` range.
- `-f <file>` — read targets from a file.
- `-r N` — retries per host (default 3; lower for speed on big ranges).
- `-i ms` — interval between packets to successive targets (controls sweep rate).
- `-t ms` — initial per-target timeout.
- `-q` — quiet: no per-probe results, just the summary / alive list.

Output is one bare IP (or hostname) per line — trivially greppable. Unreachable
noise goes to stderr, hence `2>/dev/null`.

## arp-scan — authoritative on the local L2

ARP replies come from the NIC itself, below any host firewall. On the local
segment arp-scan is the ground truth.

```bash
# Scan the interface's own subnet
sudo arp-scan --localnet | tee arpscan.txt

# Explicit interface + CIDR (needed with multiple NICs / VLAN subinterfaces)
sudo arp-scan -I eth0 192.0.2.0/24

# Flaky/wifi segment: more retries, longer per-host timeout (ms)
sudo arp-scan -I eth0 --retry=3 --timeout=500 192.0.2.0/24
```

Output lines: `IP<TAB>MAC<TAB>vendor`, e.g.

```
192.0.2.10   00:50:56:ab:12:34   VMware, Inc.
192.0.2.21   b8:27:eb:11:22:33   Raspberry Pi Foundation
```

Read the vendor column — it is free intelligence: VMware/QEMU = virtualization
hosts, Cisco/Juniper = network gear, Raspberry Pi/Espressif = IoT, printer
vendors = printers. Note duplicate MACs (NAT, HA pairs) and `(DUP: n)` markers.

## netdiscover — passive and active ARP

```bash
# Passive: listen only, zero packets sent. Leave running while you work.
sudo netdiscover -p -i eth0

# Active ARP sweep of a range, parsable output, no header screen
sudo netdiscover -i eth0 -r 192.0.2.0/24 -P -N | tee netdiscover.txt
```

`-p` passive mode finds hosts arp-scan misses (hosts that talk but drop
directed probes) and reveals adjacent subnets from gratuitous ARPs and traffic
you weren't told about. `-P` prints results in a line-per-host parsable format
and exits when the sweep finishes; `-N` suppresses the header.

## nmap -sn — portable discovery

One-liner (locally this ARPs; remotely it sends the ICMP echo + ICMP
timestamp + TCP SYN/443 + TCP ACK/80 combo — see the `nmap` skill for custom
probe combos like `-PS22,80,443 -PA80 -PU53 -PE -PP` when ICMP is filtered):

```bash
sudo nmap -sn 203.0.113.0/24 -oG - | awk '/Up$/{print $2}' | tee nmap_alive.txt
```

Also keep the grepable file for the merge script: `-oG nmap_disc.gnmap`.

## zmap — internet-scale single-port discovery

zmap is stateless: one probe per host, replies matched by cookie, so it sweeps
a /8 in minutes. Discovery model = "a host with tcp/443 open is alive".

```bash
# TCP SYN discovery on 443 across a big range, 10k pps
sudo zmap -p 443 203.0.113.0/24 --rate=10000 -o alive_443.txt

# Bandwidth cap instead of pps (K/M/G suffixes)
sudo zmap -p 80 198.51.100.0/24 --bandwidth=10M -o alive_80.txt

# ICMP echo probe module instead of TCP SYN (no -p needed)
sudo zmap --probe-module=icmp_echoscan 203.0.113.0/24 -o alive_icmp.txt

# Exclusions and interface/gateway pinning
sudo zmap -p 443 203.0.113.0/24 -b blocklist.txt -i eth0 -o alive.txt
```

Key options: `-p <port>` target port; `--probe-module=tcp_synscan|icmp_echoscan|udp`;
`--rate` pps / `--bandwidth` bps (pick one); `-b <file>` blocklist of CIDRs to
skip; `-o <file>` output (default: one responsive IP per line); `-i` send
interface; `-G` gateway MAC. Run several passes on different ports (443, 80,
22, 3389) and union the results — single-port discovery undercounts by design.

## nbtscan — NetBIOS sweep when ICMP is filtered

Windows hosts answer NetBIOS name queries on udp/137 even when ping is dropped
by policy, and they tell you their name, domain/workgroup and logged user.

```bash
nbtscan -r 192.0.2.0/24 | tee nbtscan.txt
# Script-friendly, separator-delimited:
nbtscan -s : 192.0.2.0/24
```

Output: `IP  NetBIOS-name  server  user  MAC`. Equivalent nmap fallback:
`sudo nmap -sn -PU137 192.0.2.0/24` or `nmap -sU -p137 --script nbstat <cidr>`.

## Workflow: scope → alive.txt

```bash
mkdir -p disc && cd disc

# 1. If on-segment: ARP first (authoritative), plus passive listener
sudo arp-scan --localnet > arpscan.txt
sudo netdiscover -i eth0 -r 192.0.2.0/24 -P -N > netdiscover.txt

# 2. Remote CIDRs: ICMP sweep + nmap probe-combo in parallel
fping -a -q -g 203.0.113.0/24 2>/dev/null > fping.txt &
sudo nmap -sn 203.0.113.0/24 -oG nmap_disc.gnmap >/dev/null &
wait

# 3. ICMP-filtered coverage: NetBIOS + single-port zmap
nbtscan -r 203.0.113.0/24 > nbtscan.txt
sudo zmap -p 443 203.0.113.0/24 --rate=5000 -o zmap_443.txt

# 4. Merge every source, dedupe, emit work units for the port-scan phase
python3 scripts/merge_alive.py disc/*.txt disc/*.gnmap \
    -o alive.txt --units units.json
wc -l alive.txt
```

`merge_alive.py` auto-detects each format (fping bare IPs, arp-scan tab rows,
netdiscover rows, nmap grepable `Host: x (…) Status: Up`, zmap bare IPs,
nbtscan rows), extracts IPs, sorts numerically, dedupes into `alive.txt`, and
writes `units.json` — a clean JSON array (first byte `[`) of
`{id,title,targets,hints}` "port-scan <host>" work units carrying per-host
hints (seen-via sources, MAC vendor, NetBIOS name).

## Reading the merged result

- Hosts seen ONLY by arp-scan/netdiscover: host-firewalled — scan them with
  `-Pn` later, they will drop pings during port scans too.
- Hosts seen ONLY by zmap/nbtscan: ICMP-filtered network path — same `-Pn`
  treatment, and the responding port is your first open-port data point.
- Vendor/NetBIOS hints prioritize: domain controllers, hypervisors and network
  gear first.

## Handoff

`alive.txt` is the target list for the port-scan phase (`nmap`/`masscan`
skills, typically `nmap -Pn -iL alive.txt …`). `units.json` is
rupu-ingestible: feed it to a `for_each:` loop or a lead's `dispatch`, mark
each live host as a coverage asset, and report notable discovery findings.
See `references/rupu.md`.
