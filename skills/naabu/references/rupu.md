# rupu integration — naabu results into the reporting pack

naabu output feeds two consumers: the **nmap deep pass** (built in via
`-nmap-cli`, or scripted from `-json` output) and a **rupu `for_each:`
fan-out**. Do not re-invent reporting plumbing — import the shared
reporting-pack skills **by name**:

- `work-units` — defines the work-unit schema and how rupu consumes it
- `coverage-assets` — `assets.mark` conventions for coverage tracking
- `finding-report` — `findings.report` conventions for verified issues

## 1. Work units for `for_each:` fan-out

`parse_naabu.py --units work_units.json` emits a **clean JSON ARRAY** — first
byte of the file is `[` — of deep-scan work units, one per live host:

```json
[
  {
    "id": "deep-scan-203.0.113.7",
    "title": "deep-scan 203.0.113.7:22,443,8443",
    "targets": ["203.0.113.7"],
    "hints": [
      "ports discovered by naabu: 22,443,8443",
      "nmap -sS -sV -sC -Pn -p22,443,8443 -oA scans/deep_203.0.113.7 203.0.113.7",
      "load the nmap skill for flag selection and output parsing"
    ]
  }
]
```

Point a rupu `for_each:` at the array; each unit is one deep-scan task whose
worker loads the `nmap` skill and runs/parses the hinted scan. Keep the array
clean: a single JSON array, nothing before the `[`, no JSONL wrapper, no logs.

Choosing the flow:
- **One-shot**: `-nmap-cli 'nmap -sV -sC -Pn -oA scans/naabu_deep'` is the
  built-in handoff — naabu runs one nmap over all hits. Good for small sets;
  no fan-out needed, parse the resulting `-oA` per the `nmap` skill.
- **Fleet / parallel**: emit `-json`, parse to `work_units.json`, fan out with
  rupu so each host's deep scan is independent and retryable. For per-port
  units, generate them from `targets.tsv` in a few lines (split the comma
  list, one unit per `ip:port`).

## 2. Coverage via `assets.mark`

After the parser runs, walk `inventory.json` and mark coverage per the
`coverage-assets` skill: one asset per host/IP, one per open socket
(`203.0.113.7:443/tcp`), tagged `source: naabu` plus the port spec scanned
(`-p -`, `-top-ports 1000`, ...) and scan type (SYN/CONNECT). naabu's
hostname→IP records are valuable coverage data — mark the hostname asset
linked to its resolved IP(s) (the parser preserves `hostnames` per IP), and
mark CDN-flagged hosts as CDN edges so coverage reports don't count Cloudflare
as client attack surface.

## 3. Findings via `findings.report`

Discovery is a lead; report via the `finding-report` skill once verified:
- nmap deep-pass results (version-identified vulnerable services, `--script
  vuln` hits, default creds) — attach nmap evidence, cite the naabu record as
  the discovery trail.
- naabu `-sV` service detections that already prove exposure (management
  planes, databases, RDP/SMB/IPMI reachable from the engagement vantage
  point) may be reported directly with the JSONL record as evidence.
- An origin IP found behind a CDN (host resolves to CDN per `-display-cdn`,
  but a sibling non-CDN IP serves the same app) is itself a reportable
  origin-exposure finding.

## 4. End-to-end order

1. `naabu -list hosts.txt -p - -s s -rate 5000 -scan-all-ips -exclude-cdn -json -o naabu.jsonl`
2. `python3 scripts/parse_naabu.py naabu.jsonl --units work_units.json`
3. `assets.mark` hosts/hostnames/sockets/CDN edges (coverage-assets skill)
4. rupu `for_each:` over `work_units.json` → nmap skill deep pass per unit
   (or inline `-nmap-cli` for small sets)
5. `findings.report` verified issues (finding-report skill)

— vulture
