# rupu integration — rustscan results into the reporting pack

RustScan output feeds two consumers: the **nmap deep pass** (built in via the
`--` passthrough, or scripted from `-g` output) and a **rupu `for_each:`
fan-out**. Do not re-invent reporting plumbing — import the shared
reporting-pack skills **by name**:

- `work-units` — defines the work-unit schema and how rupu consumes it
- `coverage-assets` — `assets.mark` conventions for coverage tracking
- `finding-report` — `findings.report` conventions for verified issues

## 1. Work units for `for_each:` fan-out

`parse_rustscan.py --units work_units.json` emits a **clean JSON ARRAY** —
first byte of the file is `[` — of deep-scan work units, one per live host:

```json
[
  {
    "id": "deep-scan-198.51.100.20",
    "title": "deep-scan 198.51.100.20:3389",
    "targets": ["198.51.100.20"],
    "hints": [
      "ports discovered by rustscan: 3389",
      "nmap -sS -sV -sC -Pn -p3389 -oA scans/deep_198.51.100.20 198.51.100.20",
      "load the nmap skill for flag selection and output parsing"
    ]
  }
]
```

Point a rupu `for_each:` at the array; each unit is one deep-scan task whose
worker loads the `nmap` skill and runs/parses the hinted scan. Keep the array
clean: a single JSON array, nothing before the `[`, no JSONL, no log noise.

Choosing the flow:
- **Interactive / small target set**: let RustScan's `--` passthrough do the
  deep pass inline (`rustscan -a 192.0.2.10 -- -sC -sV -oA scans/rs`); then
  parse the nmap `-oA` output per the `nmap` skill and skip the fan-out.
- **Fleet / parallel**: run `rustscan -g` for discovery only, parse to
  `work_units.json`, fan out with rupu so each host's deep scan is its own
  unit. Need per-port units instead? Generate them from `targets.tsv` in a few
  lines (split the comma list, one unit per `ip:port`).

## 2. Coverage via `assets.mark`

After the parser runs, walk `inventory.json` and mark coverage per the
`coverage-assets` skill: one asset per host (`198.51.100.20`), one per open
socket (`198.51.100.20:3389/tcp`), tagged `source: rustscan` plus the port
range scanned (`1-65535` by default) and the batch/ulimit tuning used. Also
mark hosts scanned with **zero** open ports — "swept clean" is coverage, and
RustScan's full-65k default makes that a strong statement.

## 3. Findings via `findings.report`

Discovery alone is a lead, not a finding. Report via the `finding-report`
skill once the nmap deep pass (passthrough or fan-out) verifies something:
exposed admin/management services (3389, 5900, 445, 623), version-identified
vulnerable services from `-sV`/`--script vuln`, default-credential services,
etc. Attach the nmap evidence and cite the rustscan hit as the discovery
trail. Exception: a service whose mere exposure is the issue (e.g. a database
port open to the engagement vantage point) may be reported straight from
`inventory.json` with the greppable line as evidence.

## 4. End-to-end order

1. `rustscan -a <targets> -u 8000 -g > rs.gnmap` (discovery)
2. `python3 scripts/parse_rustscan.py rs.gnmap --units work_units.json`
3. `assets.mark` hosts/sockets/sweep extent (coverage-assets skill)
4. rupu `for_each:` over `work_units.json` → nmap skill deep pass per unit
   (or inline `rustscan ... -- <nmap flags>` for small sets)
5. `findings.report` verified issues (finding-report skill)

— vulture
