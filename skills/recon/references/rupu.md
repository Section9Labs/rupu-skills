# rupu wiring for the recon pack

How phase 5's artifacts (`inventory.json`, `work-units.json`) feed rupu:
fan-out of enumeration jobs, coverage assets, and findings.

**Import, don't re-invent:** the schemas and conventions below belong to the
shared reporting-pack skills. Load them by name for the authoritative detail:

- **`work-units`** — the work-unit splitter contract (what a unit is, id/title/
  targets/hints semantics, sizing guidance).
- **`coverage-assets`** — the asset model used with `assets.mark`.
- **`finding-report`** — the finding writeup structure used with
  `findings.report`.

This document only shows how *this domain's* output plugs into them.

## 1. The work-units array contract

`scripts/inventory_to_workunits.py` writes a **bare JSON array** — the first
byte of the file is `[` — so rupu's `for_each:` can JSON-parse the result of
`read_file` directly. Shape:

```json
[
  {
    "id": "wu-001-smb-192-0-2-10",
    "title": "Enumerate SMB on 192.0.2.10",
    "targets": ["192.0.2.10"],
    "hints": "Load the `smb-enum` skill. Ports open: 139/tcp, 445/tcp. Service: microsoft-ds (Windows Server 2019). Null session, shares, RID cycling, signing check; then feed creds to netexec."
  },
  {
    "id": "wu-002-ldap-192-0-2-10",
    "title": "Enumerate LDAP/AD on 192.0.2.10",
    "targets": ["192.0.2.10"],
    "hints": "Load the `ldap-ad-enum` skill. Ports open: 389/tcp, 3268/tcp. Likely domain controller — pull rootDSE, users, SPNs, delegation."
  },
  {
    "id": "wu-009-netexec-sweep",
    "title": "netexec multi-protocol sweep (9 hosts)",
    "targets": ["192.0.2.10", "192.0.2.20", "192.0.2.30"],
    "hints": "Load the `netexec` skill. Protocols present: smb, ldap, winrm, mssql, ssh. Run uncredentialed triage now; re-run with every credential obtained."
  }
]
```

One unit per enumerable (service-family, host) pair, plus the aggregate
netexec unit. `hints` always names the sub-skill to load so the receiving
agent needs no routing logic of its own.

## 2. Fan-out pattern A — workflow `for_each:`

A rupu workflow step reads the file and iterates:

```yaml
steps:
  - id: recon-handoff
    tool: read_file
    args:
      path: artifacts/work-units.json

  - id: enumerate
    for_each: "{{ steps.recon-handoff.output | json }}"
    as: unit
    prompt: |
      Work unit {{ unit.id }}: {{ unit.title }}
      Targets: {{ unit.targets | join(", ") }}
      {{ unit.hints }}
      Execute the enumeration, mark every asset you touch with assets.mark,
      report verified issues with findings.report, and write raw output to
      artifacts/{{ unit.id }}/.
```

Because the file is a bare array, `read_file` + JSON-parse yields the iterable
directly — no unwrapping key, no preamble stripping. Keep it that way:
anything before the `[` (log lines, comments, a BOM from a careless editor)
breaks the `for_each:` parse.

## 3. Fan-out pattern B — lead-agent `dispatch`

A lead agent holding `work-units.json` fans out one subagent per unit:

```
units = json.parse(read_file("artifacts/work-units.json"))
for unit in units:
    dispatch(
        task=f"{unit.title}. Targets: {', '.join(unit.targets)}. {unit.hints}",
        context_files=["artifacts/inventory.json"],
        deliverable=f"artifacts/{unit.id}/report.md"
    )
```

Dispatch tips for this domain:

- Pass `inventory.json` as context so the subagent sees product/version
  strings and sibling services without re-scanning.
- Dispatch protocol-family units in parallel freely; serialize only units
  that share lockout-sensitive state (password spraying — the `netexec`
  skill covers the windows).
- The aggregate netexec unit should run **after** at least one credential
  exists or **first** in uncredentialed-triage mode; a lead agent can
  dispatch it twice at those two moments.

## 4. Coverage assets — `assets.mark`

Every discovered host and service becomes a coverage asset so the engagement
ledger shows what was found, what was enumerated, and what is still pending.
Model per the **`coverage-assets`** skill; typical calls from this domain:

```
assets.mark(kind="host", id="192.0.2.10",
            attrs={"os": "Windows Server 2019", "hostnames": "dc01.example.com",
                   "source": "recon/nmap"},
            status="discovered")

assets.mark(kind="service", id="192.0.2.10:445/tcp",
            attrs={"service": "microsoft-ds", "product": "Windows Server 2019",
                   "source": "recon/nmap"},
            status="discovered")

# after the smb-enum work unit completes:
assets.mark(kind="service", id="192.0.2.10:445/tcp", status="enumerated")
```

Conventions:

- Host asset id = IP address. Service asset id = `ip:port/proto`.
- Mark `discovered` from phase 5 (a loop over `inventory.json` does it in a
  few lines), and let each enumeration subagent flip its targets to
  `enumerated` on completion. That diff *is* the coverage report — OSSTMM's
  "tested vs untested" ledger for free.
- New assets found during phase-4 enumeration (new subnets from SNMP route
  tables, new DCs from DNS SRV) get marked immediately and fed back into
  phase 1/2.

## 5. Findings — `findings.report`

Recon routinely produces reportable findings before any exploitation begins.
Write them with `findings.report` using the structure from the
**`finding-report`** skill. Issues this pack commonly verifies:

| Observation | Typical severity |
|---|---|
| SMB signing not required on hosts (relay precondition) | high |
| SMB null session / guest access to shares | high |
| Anonymous LDAP bind yields directory data | medium–high |
| DNS zone transfer (AXFR) permitted | medium |
| SNMP default communities (`public`/`private`), RW community | high (critical if RW) |
| NFS export mountable by any host / no_root_squash | high |
| IKE aggressive mode + PSK hash captured | high |
| Credentials/secrets recovered from shares, SNMP, NFS loot | critical |

Example:

```
findings.report(
    title="SMB signing not required on 4 hosts in 192.0.2.0/24",
    severity="high",
    assets=["192.0.2.10:445/tcp", "192.0.2.11:445/tcp",
            "192.0.2.12:445/tcp", "192.0.2.15:445/tcp"],
    evidence="nxc smb 192.0.2.0/24 output: 'signing:False' — see artifacts/wu-009-netexec-sweep/nxc-smb.txt",
    description="SMB message signing is not enforced, enabling NTLM relay to these hosts.",
    recommendation="Require SMB signing via GPO on all domain members."
)
```

Report findings as they are verified during phase 4 — do not batch them to
the end; downstream exploitation agents key off the findings stream.

## 6. End-to-end sequence

```
inventory.json ──┬─> assets.mark (hosts + services, status=discovered)
                 └─> inventory_to_workunits.py ─> work-units.json
work-units.json ──> for_each: / dispatch  ─> one enum agent per unit
each enum agent ──> runs its sub-skill, assets.mark(status=enumerated),
                    findings.report(verified issues),
                    writes artifacts/<unit-id>/
new discoveries ──> back into phase 1/2, inventory regenerated, loop
```
