# Nmap scan types, timing, and evasion — full flag reference

Companion to `SKILL.md`. Every flag with when-to-use guidance.

## Host discovery

| Flag | What it does | When |
|---|---|---|
| `-sn` | Discovery only, no port scan (old `-sP`) | Build the live-host list first |
| `-PE` | ICMP echo request | Default remote probe; often filtered |
| `-PP` | ICMP timestamp request | Gets through filters that only block echo |
| `-PM` | ICMP netmask request | Rarely answered, cheap to add |
| `-PS<ports>` | TCP SYN ping (`-PS22,80,443,445,3389`) | Best remote discovery; a SYN-ACK or RST both prove the host is up |
| `-PA<ports>` | TCP ACK ping | Beats stateless filters that only block SYN; useless vs stateful FW |
| `-PU<ports>` | UDP ping (`-PU53,161,500`) | Hosts whose TCP is fully filtered; ICMP port-unreach proves life |
| `-PY<ports>` | SCTP INIT ping | Telco / SIGTRAN environments |
| `-PR` | ARP ping | Automatic on local Ethernet; cannot be filtered on-segment |
| `-PO<protos>` | IP protocol ping (`-PO1,6,17`) | Last resort |
| `-Pn` | Skip discovery, assume up | Known hosts that drop all probes; forces full scans of dead IPs if abused on ranges |
| `-n` / `-R` | Never / always reverse-resolve DNS | `-n` default for speed+stealth; `-R` when PTR names carry intel |
| `--dns-servers x,y` | Pin resolvers | Use the target's internal DNS during internal work |
| `--traceroute` | Path mapping during scan | Network topology mapping |
| `-iL file` / `--exclude` / `--excludefile` | Input list / exclusions | Driving scans from discovery output |

Discovery best practice (remote):
`-sn -PE -PP -PS21,22,25,80,113,443,445,3389,8080 -PA80,443 -PU53,161`.

## TCP scan types

| Flag | Mechanism | Open looks like | When |
|---|---|---|---|
| `-sS` | SYN half-open (raw) | SYN-ACK → RST sent by nmap | Default with root. Fast, no full connection, less app-level logging |
| `-sT` | OS connect() | Full handshake | No root; **required through proxychains/SOCKS pivots** (pair with `-Pn -n`); logged by applications |
| `-sA` | ACK only | n/a — reports `filtered`/`unfiltered` only | Firewall rule mapping: `unfiltered` = stateless filter passes it; all-`filtered` = stateful FW |
| `-sW` | Window scan (ACK variant) | RST window size differs | Rare systems where `-sA` + window analysis distinguishes open/closed |
| `-sF` | FIN only | Silence (closed → RST) | Evade non-stateful filters / old IDS |
| `-sN` | No flags (Null) | Silence | Same; most minimal signature |
| `-sX` | FIN+PSH+URG (Xmas) | Silence | Same; most distinctive signature |
| `-sM` | FIN/ACK (Maimon) | Silence on some BSD | Niche BSD stacks |
| `--scanflags <flags>` | Custom flag combos (`--scanflags SYNFIN`) | Depends | Hand-crafted filter probing |
| `-sI <zombie:port>` | Idle scan via IPID side channel | Inferred from zombie IPID delta | Ultimate source concealment; needs an idle host with incremental IPID (find with `--script ipidseq`) |
| `-sY` / `-sZ` | SCTP INIT / COOKIE-ECHO | INIT-ACK | SCTP services (telecom) |
| `-sO` | IP protocol scan | Protocol response | Which L4 protocols a host speaks (GRE, ESP, etc.) |

FIN/Xmas/Null caveats: Windows, Cisco, and many printers RST everything →
every port reports `closed`. Interpret `open|filtered` results against an
`-sS` baseline.

Port states to read: `open`, `closed` (reachable, nothing listening — still
proves no filter), `filtered` (probe dropped), `unfiltered` (ACK scan:
reachable, openness unknown), `open|filtered` (UDP/FIN-family silence),
`closed|filtered` (idle scan only). `--reason` prints the trigger packet.

## Port selection

| Flag | Meaning |
|---|---|
| (none) | Top 1000 per protocol |
| `-F` | Top 100 |
| `--top-ports N` | Top N by frequency database |
| `-p 22,80,443` / `-p 1-1024` | Explicit |
| `-p-` | 1–65535 |
| `-p U:53,161,T:21-25,80` | Per-protocol mix |
| `-p http*` | By service name glob |
| `--exclude-ports 9100` | Skip (e.g. printers that spew paper) |
| `--open` | Report only open(/open|filtered) ports |
| `-r` | Sequential port order instead of random (debugging) |
| `--port-ratio 0.001` | Ports above a frequency ratio |

## UDP (`-sU`)

- Closed → ICMP type 3 code 3; Linux rate-limits these to ~1/s → a 1000-port
  UDP scan of one Linux host takes ~17 min minimum. Hence: scope the ports.
- Canonical high-value list:
  `53,67,68,69,111,123,137,138,161,162,500,514,520,623,1434,1900,4500,5353`
  (DNS, DHCP, TFTP, rpcbind, NTP, NetBIOS, SNMP+trap, IKE, syslog, RIP, IPMI,
  MS-SQL browser, SSDP, NAT-T, mDNS).
- `-sV` sends protocol payloads so open services actually answer —
  `open|filtered` resolves to `open`. Use `--version-intensity 0` to send only
  the most likely probe per port (fast).
- `--max-retries 1`, `--host-timeout 15m` keep sweeps bounded.
- `--defeat-icmp-ratelimit` trades accuracy (non-responding → `closed|filtered`)
  for speed on rate-limiting hosts.
- Combine protocols in one run: `-sSU -p U:161,500,T:1-65535`.

## Timing templates and knobs

| Template | Profile | Use |
|---|---|---|
| `-T0` paranoid | 5 min between probes, serial | Single-port probes under heavy IDS watch |
| `-T1` sneaky | 15 s between probes | Slow IDS-evasion scans |
| `-T2` polite | ~0.4 s delay | Fragile targets (ICS, old gear), low noise |
| `-T3` normal | Default, parallel | WAN / VPN default |
| `-T4` aggressive | Low timeouts, maxed parallelism | LAN / modern networks — default working choice |
| `-T5` insane | 250 ms RTT cap, 2 retries | Fast lab LANs only; drops results on real networks |

Fine controls (override the template):

| Flag | Effect |
|---|---|
| `--min-rate N` / `--max-rate N` | Floor/cap packets per second. `--min-rate 1000` is the standard `-p-` accelerator; `--max-rate 10` for stealth |
| `--max-retries N` | Retransmission cap; `2` for fast sweeps, `0` for one-shot blast (lossy) |
| `--host-timeout 30m` | Abandon a host that stalls (black holes, tarpits) |
| `--min-hostgroup / --max-hostgroup N` | Hosts scanned in parallel; `--min-hostgroup 64` for big ranges |
| `--min-parallelism / --max-parallelism N` | Probe concurrency per group |
| `--initial-rtt-timeout / --min-rtt-timeout / --max-rtt-timeout` | RTT model; `--max-rtt-timeout 200ms` on known-fast LANs |
| `--scan-delay 1s` / `--max-scan-delay` | Fixed inter-probe gap; defeats threshold IDS and rate-limit back-off |

## Version & OS detection

| Flag | Effect |
|---|---|
| `-sV` | Service/version probes |
| `--version-intensity 0–9` | Probe depth (default 7) |
| `--version-light` / `--version-all` | = intensity 2 / 9 |
| `--version-trace` | Debug probe exchange |
| `-O` | TCP/IP stack fingerprinting (needs 1 open + 1 closed port) |
| `--osscan-guess` / `--fuzzy` | Print near-matches with % accuracy |
| `--osscan-limit` | Only fingerprint hosts meeting the open+closed requirement |
| `--max-os-tries N` | Retries before giving up (default 5; set 1 on sweeps) |
| `-A` | `-O -sV -sC --traceroute` combined |

TTL heuristic from any response (`--reason`, ping): ~64 → Linux/Unix/macOS,
~128 → Windows, ~255 → Cisco/Solaris/network gear. Subtract observed hops.
`tcpwrapped` in `-sV` output = handshake accepted then dropped — ACL/wrapper,
not an identified service.

## Firewall / IDS evasion — full treatment

| Flag | Mechanism | Use |
|---|---|---|
| `-f` / `-ff` | Fragment IP payload into 8- / 16-byte fragments | Split TCP headers across packets so pattern-matching filters/IDS that don't reassemble miss the probe. Some stacks/filters drop fragments entirely — test first |
| `--mtu N` | Custom fragment size (multiple of 8), e.g. `--mtu 16` | Finer control than `-f`; evade reassembly thresholds |
| `-D d1,d2,ME,d3` | Decoy scan — probes also sent from spoofed decoy IPs | Your real address hides among decoys in target logs. `RND:10` for random decoys; place `ME` late in the list (position 6+) so some IDS report only the first few. Decoys must be *up* or SYN-flood protections may trip |
| `-S <addr>` | Spoof source IP entirely (needs `-e <iface>` and usually `-Pn -n`) | Blind unless you sit on the return path (shared segment, sniffing `--spoof-mac` setups) or you're abusing address-based trust. Also for framing tests of IDS attribution |
| `-e <iface>` | Force interface | Required with `-S`; multi-homed boxes |
| `-g N` / `--source-port N` | Fixed source port, e.g. `-g 53`, `-g 88`, `-g 20` | Classic misconfig: ACLs allowing "DNS replies" (udp/53), Kerberos, or FTP-data by source port. `nmap -sS -g 53 ...` / `-sU -g 53`. Doesn't work with `-sT` version/OS probes that need the OS stack |
| `--data-length N` | Append N random payload bytes | Default nmap TCP probes are empty — a signature in itself. `--data-length 25` breaks size-based detection |
| `--data <hex>` / `--data-string <s>` | Specific payload | Protocol-shaped probes |
| `--spoof-mac 0 / <prefix> / <vendor>` | Random / vendor-prefixed / named-vendor MAC (`--spoof-mac Cisco`, `--spoof-mac Apple`) | L2 identity on local segment: NAC that trusts vendor OUIs, blending into the environment |
| `--badsum` | Send bogus TCP/UDP checksums | Real stacks silently drop these; **any response = an IDS/IPS middlebox** answering without checksum validation. Pure detection trick |
| `--ttl N` | Set IP TTL | Make packets expire before a monitoring sensor but after the target, or mimic another OS's TTL |
| `--ip-options "L 192.0.2.1"` | Loose/strict source routing, record route | Mostly dropped by modern routers; occasionally bypasses path-based filtering |
| `--scan-delay`, `-T0/-T1`, `--max-rate` | Slow everything down | Defeat threshold/correlation-based IDS; the only reliable evasion against good sensors |
| `-sI zombie:port` | Idle scan (see TCP table) | Zero packets from your real IP reach the target |
| `--proxies socks4://198.51.100.5:1080` | Chain through proxies (connect-based ops only) | Source obfuscation for `-sT`-style traffic; still experimental — prefer external `proxychains` |

Layering example — fragmented, decoyed, DNS-source-port, padded, slow:

```
sudo nmap -sS -p 80,443,445 -f --mtu 16 -D RND:9,ME -g 53 --data-length 31 \
  --scan-delay 400ms -T2 -n -Pn --reason 203.0.113.15 -oA scans/evasion-pass
```

## Output & control

| Flag | Effect |
|---|---|
| `-oA <base>` | All three formats (`.nmap`, `.gnmap`, `.xml`) — **always use** |
| `-oX <file>` | XML only — the machine-readable format `parse_nmap_xml.py` consumes |
| `-oN` / `-oG` | Normal / greppable only |
| `--append-output` | Append instead of clobber |
| `--reason` | Why each port/host got its state |
| `-v` / `-vv` / `-d` / `-dd` | Verbosity / debug; Enter key during run = ETA |
| `--stats-every 30s` | Periodic progress lines |
| `--resume <base>.gnmap` | Resume an interrupted `-oN`/`-oG` scan with original options |
| `--packet-trace` | Dump every packet sent/received (debugging filters) |
| `--iflist` | Show interfaces/routes nmap will use |
| `-6` | IPv6 scanning (most scan types supported) |
| `-iR N` | N random internet targets |

Quick gnmap extraction one-liners:

```
grep "Up" base.gnmap | awk '{print $2}'                      # live hosts
grep -oP '\d+/open/tcp//[^/]*' base.gnmap                     # open tcp ports+svc
grep -oP '\d+/open' base.gnmap | cut -d/ -f1 | sort -nu | paste -sd,  # port list for -p
```
