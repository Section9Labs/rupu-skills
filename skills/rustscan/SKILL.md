---
name: rustscan
description: Very fast port discovery with RustScan — all 65k TCP ports in seconds via tuned batch sizes and ulimits, then pipe open ports straight into Nmap with the `--` passthrough; use -g greppable output for scripted pipelines and hand results to the nmap skill for the deep pass.
license: Proprietary
compatibility: linux/macos (binary, docker, or cargo install rustscan)
metadata:
  author: Section9Labs
  pipeline-stage: recon-sweep
  feeds: nmap
---

# rustscan — fast sweep that pipes straight into nmap

RustScan's whole design is the recon handoff: it finds open ports extremely
fast (full 65,535-port TCP connect scan in seconds on a tuned box), then
**execs nmap itself** against only the open ports. Use it for single hosts and
small-to-medium target sets where you want discovery + deep scan in one
command; use masscan when the target space is internet-scale.

## 1. Targets

```
rustscan -a 192.0.2.10                        # one host
rustscan -a 192.0.2.10,198.51.100.20          # comma-separated
rustscan -a 192.0.2.0/24                      # CIDR
rustscan -a example.com                       # hostname (resolved)
rustscan -a hosts.txt                         # file of addresses, one per line
rustscan --addresses 203.0.113.0/28           # long form of -a
```

`-a`/`--addresses` accepts a mix: IPs, CIDRs, hostnames, or a path to a file
containing any of those.

## 2. Ports

```
(no flag)                      # default: ALL ports, 1-65535
-r 1-65535                     # --range: explicit port range (same as the default)
-r 1-1024                      # just privileged ports
-p 22,80,443,8080              # --ports: specific ports only
--top                          # scan the top ~1000 most common ports instead of all
--scan-order serial            # ports in order (default)
--scan-order random            # shuffle port order
```

`-r`/`--range` takes `start-end`; `-p`/`--ports` takes a comma list. They are
mutually exclusive. Default with neither is the full 1–65535 sweep.

## 3. Speed knobs and the ulimit pitfall

RustScan opens one socket per in-flight probe. Its speed therefore collides
with the shell's **open file descriptor limit** (`ulimit -n`, often 1024).
Symptoms of hitting it: wildly inaccurate results, "too many open files"
errors, or silently missed ports.

```
-b 4500          # --batch-size: sockets in flight per sweep (default 4500)
-u 8000          # --ulimit: ask the OS to raise the fd limit to 8000 for this run
-t 1500          # --timeout: ms before a probe is declared dead (default 1500)
--tries 2        # probe each port N times (default 1) — accuracy vs speed
```

Rules of thumb:

- Keep `-b` comfortably **below** `ulimit -n` (RustScan auto-lowers it if it
  can't, with an accuracy warning). `ulimit -n` then `-b $((limit - 250))`.
- Easiest fix: `-u 8000` (or `ulimit -n 8000` in the shell / docker
  `--ulimit nofile=8000:8000`) and keep the default `-b 4500` or raise it.
- Slow/lossy links or fragile embedded targets: `-b 500 -t 3000 --tries 2`.
- LAN speed-run: `-u 16000 -b 10000 -t 800`.

## 4. Output modes

```
-g               # --greppable: ONLY `ip -> [ports]` lines, no banner art — for scripts
-q / --no-nmap   # quiet: skip the nmap passthrough entirely, just report open ports
--accessible     # screen-reader-friendly plain output, also easier to log-parse
```

Greppable output, the format the parser consumes:

```
192.0.2.10 -> [22,80,443]
198.51.100.20 -> [3389]
```

Normal (non-`-g`) runs also print `Open 192.0.2.10:22` lines as ports are
found; the parser accepts those too.

## 5. The nmap passthrough — the built-in deep pass

Everything after `--` is handed to nmap verbatim, with RustScan substituting
the discovered open ports (`-p<found>`) and target. **This passthrough IS the
nmap deep pass** — load the `nmap` skill to pick the right flags, then:

```
# Full-port discovery, then default scripts + versions, all output formats:
rustscan -a 192.0.2.10 -u 8000 -- -sC -sV -Pn -oA scans/rs_192.0.2.10

# Aggressive deep pass on a subnet's open ports:
rustscan -a 203.0.113.0/28 -b 2000 -- -A -Pn -oA scans/rs_dmz

# Specific ports only, vuln scripts:
rustscan -a 198.51.100.20 -p 80,443,8443 -- -sV --script vuln -oN scans/web_vuln.txt
```

Notes:
- With no `--`, RustScan runs nmap with defaults (`-vvv -p <found> <ip>`).
  Always supply your own `--` arguments on real jobs so you control `-oA`
  output paths and script selection.
- RustScan invokes the `nmap` on PATH; nmap flags needing root (`-sS`, `-O`)
  need RustScan run as root too, or stick to `-sT -sV -sC`.
- Scripted alternative: run with `-g` (no nmap), parse, and drive nmap
  yourself — see §7.

## 6. Config file

`~/.rustscan.toml` sets persistent defaults so engagement tuning survives:

```toml
addresses = ["192.0.2.0/24"]
range = { start = 1, end = 65535 }
batch_size = 4500
timeout = 1500
tries = 1
ulimit = 8000
greppable = false
scan_order = "serial"
command = ["-sC", "-sV", "-Pn"]   # default nmap passthrough args
```

CLI flags override the file. RustScan also supports scripting engines
(`scripts = "none" | "default" | "custom"` and `~/.rustscan_scripts.toml`) for
running custom scripts instead of nmap — on this fleet keep `default` (nmap)
or `none` with `-g` for the scripted pipeline.

## 7. Scripted handoff (greppable → parser → nmap skill)

```
rustscan -a 192.0.2.0/24 -u 8000 -g > rs.gnmap

python3 scripts/parse_rustscan.py rs.gnmap \
  --inventory inventory.json --targets targets.tsv --units work_units.json

# nmap skill deep pass per host:
while IFS=$'\t' read -r ip ports; do
  nmap -sS -sV -sC -Pn -p"$ports" -oA "scans/deep_${ip}" "$ip"
done < targets.tsv
```

- `inventory.json` — merged host/port inventory, entries `source:"rustscan"`.
- `targets.tsv` — `ip<TAB>comma-ports` per host.
- `work_units.json` — rupu fan-out array (see `references/rupu.md`).

## 8. Pitfalls checklist

- Inaccurate / flapping results → batch size vs ulimit: add `-u 8000`, lower
  `-b`, add `--tries 2`.
- Hostname targets scan one resolved IP; for multi-A-record names resolve
  yourself and feed the IPs.
- RustScan is TCP connect-based discovery: it completes handshakes, so it is
  louder per-port than masscan/naabu SYN scans — fine for speed, remember the
  footprint.
- `-g` suppresses the nmap passthrough implicitly; `-q/--no-nmap` does so for
  normal output. Don't expect `-oA` files from a `-g` run.
- Docker runs: `docker run --ulimit nofile=8000:8000 -it rustscan/rustscan -a 192.0.2.10`.

Depth: `references/rupu.md` (reporting-pack integration).
