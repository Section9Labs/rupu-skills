---
name: nmap
description: Full-capability Nmap methodology for authorized network assessments — host discovery, TCP/UDP port scanning, service/version and OS detection, NSE scripting, timing and firewall evasion, structured XML output, and parsing results into rupu-ingestible work units that feed the recon flow and per-service enumeration sub-skills.
license: Apache-2.0
compatibility: Linux/macOS with nmap >= 7.80; root/CAP_NET_RAW for raw-socket scans; Python 3.8+ for scripts
metadata:
  author: Section9Labs
  tool: nmap
  stage: recon,enumeration
---

# Nmap — Network Scanning Methodology

Nmap is the central scanner of the recon flow. Everything downstream (SMB, LDAP,
SNMP, NFS, DNS, IKE enumeration) is driven by what Nmap finds. The discipline:
scan progressively (cheap → expensive), **always write `-oA`**, and end every
phase by parsing XML into structured work units for dispatch.

Flag catalogs live in `references/scan-types.md` (scan types, timing, evasion)
and `references/nse.md` (NSE engine and per-service script lists). Read them
when you need the full option surface; this file is the methodology.

## 0. Ground rules

- Run as root (`sudo nmap ...`) whenever possible: enables `-sS`, `-sU`, `-O`,
  ARP discovery, and raw-packet evasion. Unprivileged nmap silently falls back
  to `-sT` connect scans and loses capability.
- Every scan gets `-oA <dir>/<phase>` — produces `.nmap` (human), `.gnmap`
  (greppable), `.xml` (machine). The XML is what `scripts/parse_nmap_xml.py`
  consumes. Never run a scan you can't re-parse later.
- Add `--reason` to see *why* nmap decided a port state (syn-ack, reset,
  no-response, port-unreach). Add `-v` for live progress; press Enter during a
  run for an ETA; `-d` when debugging weird results.
- Interrupted big scan? Resume with `nmap --resume <base>.gnmap` (works for
  `-oG`/`-oA` output, same options are replayed).

## 1. Host discovery (`-sn`)

Goal: build the live-host list before spending time on ports.

**Local L2 (same subnet):** nmap automatically uses ARP — fast and
unblockable on the segment:

```
sudo nmap -sn 192.0.2.0/24 -oA scans/discovery
```

**Remote / routed targets:** ICMP echo is routinely filtered. Stack probe
types so one of them gets through — ICMP echo (`-PE`), ICMP timestamp (`-PP`),
TCP SYN to common ports (`-PS`), TCP ACK (`-PA`, slips past stateless filters
that only block SYN), UDP (`-PU`):

```
sudo nmap -sn -PE -PP -PS21,22,25,80,443,445,3389,8080 -PA80,443 -PU53,161 \
  198.51.100.0/24 -oA scans/discovery-remote
```

**When discovery lies:** hardened hosts drop everything. If you have reason to
believe a host exists (DNS record, prior intel), skip discovery with `-Pn` —
nmap treats it as up and port-scans anyway. Use `-Pn` per-host, not blindly on
whole ranges (it forces a full scan of every dead address).

**DNS control:** `-n` disables reverse DNS (faster, quieter — default choice
for internal sweeps); `-R` forces resolution of every address (useful when
hostnames carry intel, e.g. AD environments). `--dns-servers 192.0.2.53` to
pin a resolver.

**Reading output:** `Host is up (0.0012s latency)` + the discovery reason with
`--reason` (`arp-response`, `echo-reply`, `syn-ack`). Extract live hosts:

```
grep "Up" scans/discovery.gnmap | awk '{print $2}' > scans/live.txt
```

Feed that list to later phases with `-iL scans/live.txt`. Exclude known
infrastructure with `--exclude 192.0.2.1,192.0.2.254` or `--excludefile`.

## 2. TCP port scanning

Pick the scan type for the situation (full matrix in
`references/scan-types.md`):

- **`-sS` SYN scan** — the default workhorse with root. Half-open, fast,
  rarely logged by the application. Use it unless you can't.
- **`-sT` connect scan** — unprivileged fallback, and the **only** type that
  works through `proxychains`/SOCKS pivots (full TCP connect, no raw sockets).
  Through proxychains also set `-Pn -n` (no raw pings, no DNS leaks):
  `proxychains nmap -sT -Pn -n -p 445,3389 192.0.2.10`.
- **`-sA` ACK scan** — maps firewall rules, not open ports. `unfiltered` =
  packet reached the host (stateless filter), `filtered` = a stateful firewall
  ate it. Run it when `-sS` shows everything filtered and you need to know
  what kind of filter you face.
- **`-sF`/`-sX`/`-sN`** (FIN/Xmas/Null) — exploit RFC793: closed ports RST,
  open ports stay silent. Slip past some non-stateful filters and old IDS.
  Unreliable against Windows (RSTs everything → all ports look closed).

**Port selection**, progressive:

- Default: top 1000 TCP ports. `-F` = top 100 (fast triage).
- `--top-ports 2000` to widen, `-p 22,80,443,445` for specifics,
- `-p-` (= `-p1-65535`) full range — **always do a full-range pass** on
  interesting hosts; high-value services hide on odd ports.
- `-p U:161,T:1-65535` mixes protocols in one invocation.
- `--open` to only report open ports (cleaner output on noisy networks).

```
# fast triage of all live hosts
sudo nmap -sS -F -n --open -T4 -iL scans/live.txt -oA scans/tcp-fast
# full 65535-port sweep on the shortlist
sudo nmap -sS -p- -n --min-rate 1000 --max-retries 2 -T4 192.0.2.10 -oA scans/tcp-full
```

## 3. UDP scanning (`-sU`)

UDP is where SNMP, DNS, NTP, IKE, TFTP, NetBIOS and IPMI live — skipping it
loses findings. It is slow because open ports usually don't answer (state
`open|filtered`) and closed ports answer with ICMP port-unreachable, which
Linux rate-limits to ~1/sec. Manage it:

1. **Scope to the high-value ports** instead of the top 1000. Canonical list:

   `53,67,68,69,111,123,137,138,161,162,500,514,520,623,1434,1900,4500,5353`

2. **Combine with `-sV`**: version probes send protocol-correct payloads, so
   genuinely open ports answer and `open|filtered` resolves to `open`.
3. **Cap retries**: `--max-retries 1` or `2`; UDP retransmits are what makes
   full sweeps take hours.

```
sudo nmap -sU -sV --version-intensity 0 \
  -p 53,67,68,69,111,123,137,138,161,162,500,514,520,623,1434,1900,4500,5353 \
  --max-retries 1 -n 192.0.2.10 -oA scans/udp
```

Run `-sU` and a TCP type together (`-sSU`) when you want one combined XML.
A truly thorough UDP pass on one critical host: `-sU --top-ports 100 -sV`.

## 4. Timing & performance

- `-T4` on LAN, `-T3` (default) across WAN/VPN. `-T2` when IDS evasion
  matters more than time; `-T0`/`-T1` only for single-port paranoid probes;
  `-T5` only on fast local lab networks (sacrifices accuracy).
- `--min-rate 1000` floors the packet rate — the single biggest speedup for
  `-p-` sweeps. `--max-rate 50` caps it when you must stay slow.
- `--max-retries 2` (default can be 10 on bad links), `--host-timeout 30m` so
  one black-holing host doesn't stall the group, `--min-hostgroup 64` to scan
  more hosts in parallel on big ranges.

Details and the full knob list: `references/scan-types.md`.

## 5. Service/version detection (`-sV`)

```
sudo nmap -sS -sV -p 22,80,443,445,3389 192.0.2.10 -oA scans/versions
```

- `--version-intensity 0..9` (default 7). `--version-light` (=2) for speed,
  `--version-all` (=9) when a port stays `unknown` or for odd ports found in
  the full sweep.
- Read the columns: SERVICE (protocol guess), then VERSION =
  `product version extrainfo`, e.g.
  `ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)` — the
  extrainfo often leaks OS/distro. These feed CVE lookup and `searchsploit`.
- **`tcpwrapped`** = the TCP handshake completed but the service closed the
  connection before any banner — an ACL/wrapper that doesn't like your source
  IP, or a proxy. It is *not* an identified service; retry from another source
  address, through the pivot, or with targeted NSE.

## 6. OS detection (`-O`)

```
sudo nmap -O --osscan-guess -sS -p- 192.0.2.10 -oA scans/os
```

- Needs at least one open and one closed TCP port for a reliable fingerprint;
  `--osscan-limit` skips hosts that don't qualify (saves time on sweeps).
- `--osscan-guess` prints near-matches with accuracy percentages
  (`Aggressive OS guesses: Linux 5.4 (96%)`).
- Cheap cross-checks: TTL in ping/`--reason` output (~64 = Linux/Unix,
  ~128 = Windows, ~255 = network gear/Solaris) and the open-port profile
  (445+135+3389 → Windows; 22+111 → Unix).
- `-A` = `-O -sV -sC --traceroute` in one flag — fine for a single deep pass,
  too heavy for sweeps.

## 7. NSE — the scripting engine

- `-sC` runs the `default` script set; pair it with `-sV` on every deep pass.
- `--script=<expr>` takes names, globs, categories, and boolean expressions:
  `--script "smb-enum-*"`, `--script "default or safe"`,
  `--script "vuln and not dos"`, `--script "(discovery or vuln) and not intrusive"`.
- Categories: `default, safe, discovery, vuln, auth, brute, intrusive, exploit,
  dos, malware, external, fuzzer, version`.
- `--script-args` passes parameters:
  `--script smb-brute --script-args userdb=users.txt,passdb=pass.txt`.
- After adding/editing scripts: `sudo nmap --script-updatedb`. Find scripts:
  `ls /usr/share/nmap/scripts | grep smb`; read usage with
  `nmap --script-help smb-enum-shares`.

High-value targeted sets per service (full list + invocations in
`references/nse.md`):

| Port(s) | Scripts |
|---|---|
| 445/139 | `smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode,smb2-security-mode,smb-vuln-*` |
| 389/636/3268 | `ldap-rootdse,ldap-search` |
| 80/443/8080 | `http-title,http-headers,http-enum,http-methods,http-robots.txt,http-vuln-*` |
| 161/udp | `snmp-info,snmp-interfaces,snmp-processes,snmp-netstat,snmp-brute` |
| 2049/111 | `nfs-ls,nfs-showmount,nfs-statfs,rpcinfo` |
| 1433 | `ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password` |
| 3389 | `rdp-enum-encryption,rdp-ntlm-info` |
| 443/any TLS | `ssl-cert,ssl-enum-ciphers,ssl-heartbleed` |
| 53 | `dns-recon via dns-nsid,dns-zone-transfer,dns-srv-enum` |

Vuln sweep on a confirmed service: `--script vuln -sV -p <port>` — expect
noise and some intrusive probes; that's the point of the category.

## 8. Firewall/IDS evasion

Full treatment in `references/scan-types.md`. The toolkit:
`-f` / `--mtu 16` (fragment probes past dumb inspectors), `-D
RND:5` or `-D 192.0.2.7,ME,192.0.2.9` (decoy source addresses to drown your
real IP in logs), `-S <addr> -e <iface>` (full source spoof — blind unless you
can sniff the return path), `-g 53` / `--source-port 53` (source-port trust
holes in old ACLs; combine with `-sU -g 53` for DNS-shaped probes),
`--data-length 25` (pad probes away from signature sizes), `--spoof-mac 0` /
`--spoof-mac Cisco` (L2 identity on the local segment), `--badsum` (only IDS
middleboxes answer bad-checksum packets — detect them), `--scan-delay 1s` +
`-T1` (defeat threshold-based detection), `--ttl`, `--ip-options`. Also
consider `-sF/-sX/-sN` (section 2) as evasion scan types.

## 9. Chained example: 192.0.2.0/24 → 192.0.2.10

```bash
mkdir -p scans
# 1. discover
sudo nmap -sn -PE -PP -PS22,80,443,445 -PA80,443 -PU53,161 192.0.2.0/24 -oA scans/01-discovery
grep "Up" scans/01-discovery.gnmap | awk '{print $2}' > scans/live.txt

# 2. fast TCP triage of all live hosts
sudo nmap -sS -F -n --open -T4 --reason -iL scans/live.txt -oA scans/02-tcp-fast

# 3. full TCP range on the interesting host
sudo nmap -sS -p- -n -T4 --min-rate 1000 --max-retries 2 --reason \
  192.0.2.10 -oA scans/03-tcp-full

# 4. high-value UDP
sudo nmap -sU -sV --version-intensity 0 --max-retries 1 -n \
  -p 53,67,68,69,111,123,137,138,161,162,500,514,520,623,1434,1900,4500,5353 \
  192.0.2.10 -oA scans/04-udp

# 5. deep pass on every open TCP port found in step 3
PORTS=$(grep -oP '\d+/open' scans/03-tcp-full.gnmap | cut -d/ -f1 | sort -nu | paste -sd,)
sudo nmap -sS -sV -sC -O --osscan-guess -p "$PORTS" --reason \
  192.0.2.10 -oA scans/05-deep

# 6. targeted NSE per discovered service (example: SMB + LDAP + TLS seen)
sudo nmap -sS -sV -p 445 --script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode,smb-vuln-*" \
  192.0.2.10 -oA scans/06-nse-smb
sudo nmap -sS -sV -p 389,636 --script "ldap-rootdse,ldap-search" \
  192.0.2.10 -oA scans/06-nse-ldap
sudo nmap -sS -sV -p 443 --script "ssl-cert,ssl-enum-ciphers,ssl-heartbleed" \
  192.0.2.10 -oA scans/06-nse-tls
```

## 10. Parse → hand off (rupu-ingestible)

End every phase by consolidating XML and emitting work units:

```bash
python3 scripts/parse_nmap_xml.py scans/*.xml -o inventory.json
python3 scripts/nmap_to_workunits.py inventory.json -o workunits.json
```

- `inventory.json` — merged host→ports/services/OS/script-output inventory.
- `workunits.json` — a JSON **array** (first byte `[`) of
  `{id,title,targets,hints}` per-service enumeration tasks; each hint names the
  sub-skill to load (445→`smb-enum`, 389→`ldap-ad-enum`, 161→`snmp-enum`,
  2049→`nfs-enum`, 53→`dns-recon`, 500→`ike-scan`).

Feed `workunits.json` to a rupu workflow `for_each:` or a lead's `dispatch`,
mark every scanned host/port as a coverage asset, and report verified issues —
see `references/rupu.md`, which imports the shared reporting-pack skills
`work-units`, `coverage-assets`, and `finding-report`.
