# Handing Nmap results to rupu

The nmap skill ends every scanning phase by producing machine-readable
artifacts; this file explains how those artifacts flow into the rupu
orchestration and reporting layer.

**Import the shared reporting-pack skills by name — do not re-implement
them:**

- `work-units` — the work-unit schema and dispatch conventions.
- `coverage-assets` — recording what was examined via `assets.mark`.
- `finding-report` — reporting verified issues via `findings.report`.

Load those skills for schema detail; below is only the nmap-specific glue.

## 1. Produce the artifacts

```bash
python3 scripts/parse_nmap_xml.py scans/*.xml -o inventory.json
python3 scripts/nmap_to_workunits.py inventory.json -o workunits.json
```

- `inventory.json` — object keyed by host address:
  `{address, hostnames[], status, os{name,accuracy}, ports[{port,proto,state,
  service,product,version,extrainfo,scripts{id:output},source:"nmap"}]}`.
  Merges all XML files given; later scans refine earlier ones.
- `workunits.json` — a **JSON array whose first byte is `[`**, each element
  `{id, title, targets, hints}`. This is deliberately the exact shape rupu
  `for_each:` consumes.

## 2. Fan out the work units

In a rupu workflow, read the array and iterate:

```yaml
steps:
  - id: scan-parse
    run: |
      python3 skills/nmap/scripts/parse_nmap_xml.py scans/*.xml -o inventory.json
      python3 skills/nmap/scripts/nmap_to_workunits.py inventory.json -o workunits.json
  - id: enumerate
    for_each:
      items_from: { read_file: workunits.json }
      as: unit
    do:
      - dispatch: { unit: "{{unit}}" }
```

Or, as a lead agent, `read_file` on `workunits.json` and `dispatch` each
element to a worker. Every unit's `hints` names the sub-skill the worker should
load first:

| Service hint | Sub-skill |
|---|---|
| 445/tcp smb | `smb-enum` |
| 389,636,3268/tcp ldap | `ldap-ad-enum` |
| 161/udp snmp | `snmp-enum` |
| 2049/tcp,111/tcp nfs/rpc | `nfs-enum` |
| 53/tcp+udp dns | `dns-recon` |
| 500,4500/udp ike | `ike-scan` |

Units for services without a dedicated sub-skill carry generic hints
(service/product/version strings) so the worker can pick its own tooling.

## 3. Record coverage

Every host and every open port nmap touched is a coverage asset, whether or
not it produced a finding. After parsing, mark them (see `coverage-assets` for
the full schema):

```
assets.mark host:192.0.2.10 status=scanned source=nmap
assets.mark service:192.0.2.10:445/tcp status=enumeration-dispatched source=nmap \
  note="microsoft-ds; Windows Server 2019; smb2 signing disabled"
```

A simple loop over `inventory.json` emits one `assets.mark` per host plus one
per open/open|filtered port. Marking closed-but-scanned hosts too is what makes
coverage auditable — "we scanned the /24, 14 hosts up, 240 dead" must be
reconstructable from assets alone.

## 4. Report findings

Nmap output itself regularly contains verified issues — report them
immediately via `findings.report` (schema in `finding-report`), do not wait
for the sub-skill pass. Typical nmap-native findings:

- NSE `vuln` scripts printing `State: VULNERABLE` (e.g. `smb-vuln-ms17-010`)
  — include the CVE IDs and the full script output as evidence.
- `smb2-security-mode: Message signing enabled but not required` → SMB relay.
- `dns-zone-transfer` success → full AXFR dump as evidence.
- `ftp-anon: Anonymous FTP login allowed`, `ms-sql-empty-password`,
  `ipmi-cipher-zero`, open `redis-info`/`mongodb-databases`.
- `ssl-enum-ciphers` grades below A / SSLv2-v3 / weak DH.
- Dangerously exposed management planes (telnet, 623/udp IPMI, 1434 browser).

Evidence = the relevant `<script>` output or the `.nmap` excerpt plus the
exact command line (reproduce-ability). Attach the host/port asset IDs so the
finding links back to coverage.

## 5. Loop

Sub-skill workers (smb-enum, ldap-ad-enum, ...) will surface new leads — new
hostnames, trust relationships, additional subnets. Feed any new address space
back to the nmap skill's phase 1 (discovery) and regenerate work units. The
recon flow is a cycle, and `inventory.json` merging (`parse_nmap_xml.py`
accepts multiple XMLs across runs) keeps one consolidated picture.
