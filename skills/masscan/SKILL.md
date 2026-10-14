---
name: masscan
description: Internet-scale asynchronous TCP SYN port scanning with masscan — rate-driven sweeps of huge ranges, banner grabbing with its userland TCP/IP stack, sharded/resumable scans, and parsing -oL/-oJ output into an ip→ports map handed to the nmap skill for deep service detection.
license: Apache-2.0
compatibility: linux (root or CAP_NET_RAW required for raw-packet TX/RX)
metadata:
  author: Section9Labs
  pipeline-stage: recon-sweep
  feeds: nmap
---

# masscan — fast-and-wide sweep at line rate

masscan is an asynchronous SYN scanner: it transmits SYNs as fast as you tell it
to and collects SYN-ACKs independently, with its **own userland TCP/IP stack**.
It is the right tool when the target set is large (a /16, a corporate supernet,
"all of the client's public ranges") and you want every open port fast, then
hand only the hits to nmap for deep service detection. It is NOT a service
scanner — pair it with the `nmap` skill for the deep pass.

## 1. Core syntax

```
masscan <ranges> -p<ports> --rate <pps>
```

- `<ranges>`: IPs, CIDRs, dash ranges, comma-separated:
  `192.0.2.0/24 198.51.100.10-198.51.100.50 203.0.113.7`
- `-iL targets.txt` — read ranges from a file (one per line, `#` comments ok).
- `--excludefile never.txt` — ranges to carve out; exclusions win over includes.

### Ports

```
-p80,443,8080-8090        # specific TCP ports/ranges
-p1-65535                 # full TCP sweep
-p0-65535                 # include port 0
-pU:53,161,500            # UDP ports (U: prefix); mixable: -p80,443,U:161
--top-ports 100           # nmap-style most-common TCP ports
```

### Rate — the ONLY throttle that matters

masscan has no timing templates. `--rate` (packets/second) is the real control:

```
masscan 192.0.2.0/24 -p1-65535 --rate 10000
```

- Default is a glacial 100 pps — always set `--rate` explicitly.
- 1,000–10,000 pps: safe on any VPS/office uplink, negligible loss.
- 100,000 pps: needs a decent NIC and upstream; watch for drops.
- 1,000,000+ pps: dedicated hardware; ~1.5M pps is the practical limit of a
  stock Linux stack. 10M pps needs PF_RING ZC and an Intel 10GbE NIC.
- Rate × time math: a /16 (65,536 hosts) × 65,535 ports ≈ 4.3B probes;
  at 100k pps that's ~12 hours. Budget before you launch.
- Loss at high rate shows up as *missing* ports, not errors. Use `--retries 2`
  (re-sends SYNs on a timer) and/or re-run the diff at a lower rate.

### Timing / completeness

```
--wait 15        # seconds to linger for late SYN-ACKs after TX ends (default 10; --wait forever to stay open)
--retries 2      # resend probes; cheap insurance against loss at high rates
```

## 2. Banners and the userland stack

`--banners` makes masscan complete the handshake and grab service banners
(HTTP, FTP, SSH, TLS cert fields, etc.). Because masscan runs **its own TCP/IP
stack**, the kernel also sees the inbound SYN-ACK on a connection it never
opened and replies with a RST — killing the session before the banner arrives.
You must keep the kernel out of the conversation, one of two ways:

**A. Reserved source port + firewall the kernel off it (same IP):**

```
iptables -A INPUT -p tcp --dport 61000 -j DROP
masscan 192.0.2.0/24 -p80,443 --banners --source-port 61000 --rate 20000
```

Pick a `--source-port` outside the kernel's ephemeral range
(`sysctl net.ipv4.ip_local_port_range`) so nothing else collides.

**B. Spare IP the kernel doesn't own (cleanest):**

```
masscan 192.0.2.0/24 -p80 --banners --rate 20000 \
  -e eth0 --source-ip 198.51.100.99 --router-mac 66:55:44:33:22:11
```

With `--source-ip` set to an unused address on the local subnet, masscan must
answer ARP itself — give it `-e <iface>` and, since the kernel won't route for
it, `--router-mac` (the gateway's MAC, from `ip neigh` / `arp -an`). `-e` and
`--router-mac`/`--router-ip` are also how you pin masscan to a specific
interface on multi-homed scan boxes even without banners.

Other stack-related knobs: `--source-ip` ranges and `--source-port` ranges
spread traffic (`--source-ip 198.51.100.96-198.51.100.99`); `--ttl`,
`--adapter-vlan` exist for odd networks.

## 3. Config files, sharding, resume

- `-c scan.conf` loads a config; `--echo` dumps the current command line as a
  config file — the standard way to templatize a job:

  ```
  masscan 192.0.2.0/24 -p1-65535 --rate 50000 -oL out.lst --echo > job.conf
  masscan -c job.conf
  ```

- **Shard** a huge job across scan boxes — each node gets an interleaved slice
  of the randomized target space:

  ```
  # node 1 of 3:
  masscan -c job.conf --shard 1/3
  # node 2: --shard 2/3   node 3: --shard 3/3
  ```

- **Pause/resume**: Ctrl-C (or SIGINT) makes masscan wait `--wait` seconds for
  stragglers and write `paused.conf` with full progress state. Resume with:

  ```
  masscan --resume paused.conf
  ```

## 4. Output formats

Always write output to disk; stdout `-oL -` style interactive mode is only for
quick looks.

| Flag | Format | Use |
|---|---|---|
| `-oL out.lst` | list, one line per hit | **feeds the parser** — grep/awk friendly |
| `-oJ out.json` | JSON | machine ingestion (parser also accepts it) |
| `-oX out.xml` | XML (nmap-ish) | importers expecting XML |
| `-oG out.gnmap` | grepable (nmap -oG style) | legacy pipelines |
| `-oB out.bin` | compact binary | huge scans; re-render with `masscan --readscan out.bin -oL out.lst` |

Reading the list format — fields are `state proto port ip timestamp`:

```
#masscan
open tcp 443 192.0.2.10 1718000000
open tcp 22 192.0.2.10 1718000003
banner tcp 443 192.0.2.10 1718000004 ssl Subject:CN=example.com
# end
```

`banner` lines (only with `--banners`) append `service banner-text`. Quick
manual triage: `awk '/^open/{print $4":"$3}' out.lst | sort -V`.

## 5. Standard sweep recipes

```
# Full-port TCP sweep of client ranges, resumable, list output:
masscan -iL ranges.txt -p1-65535 --rate 50000 --retries 2 \
  --excludefile exclusions.txt -oL sweep.lst -oB sweep.bin

# Top-ports fast look with banners (iptables rule in place first):
iptables -A INPUT -p tcp --dport 61000 -j DROP
masscan 203.0.113.0/24 --top-ports 1000 --banners --source-port 61000 \
  --rate 20000 -oL quick.lst

# UDP essentials alongside TCP:
masscan 192.0.2.0/24 -p22,80,443,U:53,U:123,U:161,U:500 --rate 10000 -oL mix.lst
```

## 6. Handoff to the nmap deep pass

masscan tells you *open*; nmap tells you *what*. Convert hits into an
`ip -> ports` map and run nmap **only** on those ip:port pairs:

```
python3 scripts/parse_masscan.py sweep.lst \
  --inventory inventory.json --targets targets.tsv --units work_units.json
```

- `inventory.json` — merged host/port inventory, each entry `source:"masscan"`.
- `targets.tsv` — `ip<TAB>comma-ports`, one host per line (TCP;
  `targets-udp.tsv` is written too if UDP hits exist).
- `work_units.json` — rupu fan-out units (see `references/rupu.md`).

Then load the **`nmap` skill** and run the deep pass per host:

```
while IFS=$'\t' read -r ip ports; do
  nmap -sS -sV -sC -Pn -p"$ports" -oA "scans/deep_${ip}" "$ip"
done < targets.tsv
```

For UDP hits: `nmap -sU -sV -p<udports> <ip>` from `targets-udp.tsv`.

## 7. Pitfalls checklist

- Needs root/CAP_NET_RAW. Run from a box whose uplink can take the rate.
- Forgot `--rate` → 100 pps default → scan "hangs" forever.
- Banners empty/RST-killed → you skipped the iptables rule / `--source-ip`.
- Missing ports at high rate → packet loss: add `--retries`, lower `--rate`,
  raise `--wait`.
- masscan randomizes target order itself — don't pre-shuffle, and don't split
  ranges by hand when `--shard` exists.
- Statefulness: results stream to the output file as they arrive; a killed scan
  still leaves usable partial output plus `paused.conf`.

Depth: `references/rupu.md` (reporting-pack integration).
