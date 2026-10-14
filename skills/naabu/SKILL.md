---
name: naabu
description: Fast SYN/CONNECT port discovery with ProjectDiscovery's naabu — pipeline-friendly sweeps over hosts/lists with rate and concurrency control, CDN awareness, built-in service detection and an -nmap-cli handoff that runs nmap on every found port; emit -json for scripted ingestion into the nmap skill's deep pass.
license: Proprietary
compatibility: linux/macos (go install or pdtm; SYN mode needs root/CAP_NET_RAW, else falls back to CONNECT)
metadata:
  author: Section9Labs
  pipeline-stage: recon-sweep
  feeds: nmap
---

# naabu — pipeline-native port discovery

naabu is ProjectDiscovery's port scanner: fast SYN/CONNECT discovery built to
sit in a Unix pipeline (`subfinder | naabu | httpx`) and to hand results to
nmap. naabu **actively probes** targets — despite living next to passive PD
tools, there is no passive mode; every result is a packet you sent. Use it
when targets arrive as hostnames/streams from recon, when you want CDN
awareness, or when you want the built-in nmap handoff.

## 1. Input

```
naabu -host 192.0.2.10                        # single target
naabu -host 192.0.2.10,example.com            # comma list; hostnames resolve
naabu -host 203.0.113.0/24                    # CIDR
naabu -list hosts.txt                         # file: IPs/CIDRs/hostnames per line
subfinder -d example.com -silent | naabu -silent   # stdin from a pipeline
```

Hostname resolution: by default naabu scans ONE resolved IP per hostname. Add
`-scan-all-ips` (`-sa`) to scan **every** A/AAAA record — essential for
round-robin DNS and multi-homed hosts. `-ip-version 4,6` controls families.

## 2. Ports

```
-p 80,443,8000-8090        # explicit ports/ranges (-p U:53 for UDP with CONNECT-style probes)
-p -                       # ALL 65535 ports
-top-ports 100             # 100 | 1000 | full presets of most-common ports
(no flag)                  # default: top 100
-ep 22                     # -exclude-ports: carve ports out
-port-threshold 1000       # skip hosts that show >N open ports (WAF/firewall
                           # that SYN-ACKs everything — a tarpit filter)
```

`-port-threshold` (`-pts`) is the sanity valve for full-range sweeps: a host
"open" on thousands of ports is a middlebox answering for everything; drop it
rather than poison the inventory and the nmap queue.

## 3. Scan type, rate, concurrency

```
-s s             # -scan-type SYN  (default when root; raw sockets, fast, half-open)
-s c             # -scan-type CONNECT (full TCP handshake; works unprivileged)
-rate 3000       # packets per second (default 1000) — the main throttle
-c 50            # -c: general worker/goroutine concurrency (default 25)
-retries 3       # probe retries (default 3)
-timeout 1000    # ms per probe
-warm-up-time 2  # seconds between scan phases
```

- SYN mode needs root or CAP_NET_RAW; without it naabu silently uses CONNECT.
  Verify with `-v` — the banner states the scan type. `sudo naabu -s s` for
  real SYN sweeps.
- `-rate` is the throughput control. 1000 default is conservative; 3000–10000
  is routine on decent uplinks; raise `-c` alongside for many hosts.
- `-Pn` / host discovery: naabu does a ping/ARP discovery phase on CIDRs; use
  `-sn` for discovery-only, `-Pn` to skip discovery and probe everything.

## 4. CDN awareness

```
-exclude-cdn     # -ec: for CDN/WAF IPs, only scan 80,443 (don't waste 65k probes on Cloudflare)
-display-cdn     # -cdn: annotate output with the CDN name detected
```

On external perimeters, run with both: you keep the web ports on CDN fronts
(real origin ports live elsewhere) and the annotation tells you which "hosts"
are actually Cloudflare/Akamai/Fastly edges, so you don't report CDN
infrastructure as client exposure.

## 5. Service detection and the nmap handoff

```
-sV              # built-in service detection on found ports
-sV-fast         # lighter/faster probe set
```

For the real deep pass, naabu can invoke nmap itself on everything it found —
one nmap process fed all `ip:port` hits. **`-nmap` is deprecated; use
`-nmap-cli` with the full command string** (load the `nmap` skill to choose
flags):

```
naabu -list hosts.txt -top-ports 1000 -rate 3000 \
  -nmap-cli 'nmap -sV -sC -Pn -oA scans/naabu_deep'
```

naabu appends the discovered targets/ports to that command line when the scan
finishes. For per-host control, finer flags, or rupu fan-out, skip `-nmap-cli`
and drive nmap yourself from JSON output (§7).

## 6. Output

```
-o naabu.txt     # write results to file (host:port lines)
-j / -json       # JSONL: one object per open port
-silent          # results only on stdout — the pipeline mode
-v / -debug      # chatty diagnostics
-stats           # periodic progress line (big sweeps)
```

JSONL record (one per line; `port` is an integer in current releases):

```json
{"host":"example.com","ip":"192.0.2.10","port":443,"protocol":"tcp","timestamp":"2024-06-01T12:00:00Z"}
```

Plain `-silent` output is `host:port` per line — directly chainable:
`naabu -list hosts.txt -silent | httpx -silent`.

## 7. Scripted handoff (JSON → parser → nmap skill)

```
naabu -list hosts.txt -p - -rate 5000 -s s -scan-all-ips \
  -exclude-cdn -display-cdn -json -o naabu.jsonl -silent

python3 scripts/parse_naabu.py naabu.jsonl \
  --inventory inventory.json --targets targets.tsv --units work_units.json

while IFS=$'\t' read -r ip ports; do
  nmap -sS -sV -sC -Pn -p"$ports" -oA "scans/deep_${ip}" "$ip"
done < targets.tsv
```

- `inventory.json` — merged host/port inventory, entries `source:"naabu"`
  (hostname preserved alongside the IP when naabu reports both).
- `targets.tsv` — `ip<TAB>comma-ports` per host.
- `work_units.json` — rupu fan-out array (see `references/rupu.md`).

## 8. Config and maintenance

- `-config /path/naabu.yaml` — flags-as-YAML; default lives at
  `$HOME/.config/naabu/config.yaml`. Pin engagement defaults (rate, retries,
  exclude-cdn) there.
- `-update` self-updates the binary; `-duc` disables the update check noise.
- `-proxy 127.0.0.1:1080` — SOCKS5 for CONNECT scans through a pivot
  (SYN mode cannot proxy; use `-s c`).
- `-interface eth0`, `-source-ip` — pin the egress path on multi-homed boxes.

## 9. Pitfalls checklist

- Not root → you got CONNECT, not SYN. Check the banner; `sudo` for `-s s`.
- Hostname sweeps missing hosts → forgot `-scan-all-ips`.
- A host with 10k "open" ports → middlebox; re-run with `-port-threshold`.
- naabu actively probes; there is no passive mode — every port in the output
  was touched from your egress IP.
- Default is top-100 ports only — say `-p -` or `-top-ports 1000` when you
  mean a real sweep.
- `-nmap` deprecated → `-nmap-cli 'nmap ...'`.

Depth: `references/rupu.md` (reporting-pack integration).
