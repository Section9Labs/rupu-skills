# rupu integration — masscan sweep results into the reporting pack

The masscan skill's parser output is designed to feed two consumers at once:
the **nmap deep pass** and a **rupu `for_each:` fan-out**. Do not re-invent
reporting plumbing — import the shared reporting-pack skills **by name**:

- `work-units` — defines the work-unit schema and how rupu consumes it
- `coverage-assets` — `assets.mark` conventions for coverage tracking
- `finding-report` — `findings.report` conventions for verified issues

## 1. Work units for `for_each:` fan-out

`parse_masscan.py --units work_units.json` emits a **clean JSON ARRAY** —
first byte of the file is `[` — of deep-scan work units, one per live host:

```json
[
  {
    "id": "deep-scan-192.0.2.10",
    "title": "deep-scan 192.0.2.10:22,80,443",
    "targets": ["192.0.2.10"],
    "hints": [
      "ports discovered by masscan: 22,80,443",
      "nmap -sS -sV -sC -Pn -p22,80,443 -oA scans/deep_192.0.2.10 192.0.2.10",
      "load the nmap skill for flag selection and output parsing"
    ]
  }
]
```

Point a rupu `for_each:` at that array; each unit becomes one deep-scan task.
Each worker should load the `nmap` skill, run the hinted command (adjusting
flags per the nmap skill's methodology — e.g. add `--script vuln`, `-sU` for
UDP rows), and parse the results. Keep the array *clean*: no log lines, no
trailing commentary, no JSONL — a single JSON array, nothing before the `[`.

If you need units the parser doesn't make (e.g. one unit per ip:port instead of
per host), generate them in a few lines from `targets.tsv`:

```python
import json
units = []
for line in open("targets.tsv"):
    ip, ports = line.strip().split("\t")
    for p in ports.split(","):
        units.append({"id": f"deep-scan-{ip}-{p}",
                      "title": f"deep-scan {ip}:{p}",
                      "targets": [f"{ip}:{p}"],
                      "hints": [f"nmap -sS -sV -sC -Pn -p{p} {ip}"]})
print(json.dumps(units, indent=2))
```

## 2. Coverage via `assets.mark`

Every host/port masscan confirms open is a coverage asset. After the parser
runs, walk `inventory.json` and mark each discovery per the `coverage-assets`
skill, e.g. one asset per host (`192.0.2.10`) and one per open socket
(`192.0.2.10:443/tcp`), tagged with `source: masscan` and the sweep's rate and
port range so coverage reports show what was actually swept. Mark the swept
*ranges* too (e.g. `192.0.2.0/24 ports 1-65535`) so "scanned, nothing open" is
distinguishable from "never scanned".

## 3. Findings via `findings.report`

masscan itself rarely produces a *finding* — it produces leads. Two exceptions
worth reporting directly from sweep data, per the `finding-report` skill:

- `--banners` output that already proves an issue (e.g. an FTP banner
  advertising anonymous login, a TLS cert for the wrong domain, an exposed
  management service like 23/tcp telnet or 5900/tcp VNC on an internet range).
- Exposure-class findings: databases/RDP/SMB/IPMI open to the sweep's vantage
  point (ports 3306, 1433, 3389, 445, 623 in `inventory.json`).

Everything else: wait for the nmap deep pass to verify the service, then report
through `finding-report` with the nmap evidence attached and the masscan hit as
the discovery trail.

## 4. End-to-end order

1. `masscan ... -oL sweep.lst` (sweep)
2. `python3 scripts/parse_masscan.py sweep.lst --units work_units.json`
3. `assets.mark` the hosts/sockets/ranges (coverage-assets skill)
4. rupu `for_each:` over `work_units.json` → nmap skill deep pass per unit
5. `findings.report` verified issues (finding-report skill)

— vulture
