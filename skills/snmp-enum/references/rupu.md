# rupu Handoff — snmp-enum

This skill ends by producing `snmp_out/work_units.json` (clean JSON array of
`{id,title,targets,hints}`) plus `snmp_out/snmp_enum.json` and `snmp_out/subnets.txt`.
Use the shared reporting-pack skills by name — `work-units`, `coverage-assets`,
`finding-report` — exactly as they define; nothing here replaces them.

## 1. Feed work units

Via `for_each` in a rupu plan — read the array and iterate:

```yaml
- step: snmp-followup
  for_each: ${read_file("snmp_out/work_units.json")}
  as: unit
  do:
    - run: "Execute work unit ${unit.id}: ${unit.title} against ${unit.targets} — hints: ${unit.hints}"
```

Or from a lead agent, dispatch each element:

```
units = json.load(open("snmp_out/work_units.json"))
for u in units: dispatch(unit=u)
```

Unit kinds this skill emits:
- `snmp-fullwalk-<host>-<community>` — hosts with a valid community not yet fully walked
- `snmp-write-test-<host>` — candidate write communities to probe with snmpset
- `snmp-cisco-confexfil-<host>` — confirmed rw community on a Cisco sysDescr
- `snmp-v3-userenum-<host>` — v3-only agents
- `host-discovery-<subnet>` — subnets from ipAddrTable/ipRouteTable (also in `subnets.txt`)
- `cred-followup-<host>` — secrets spotted in hrSWRunParameters

## 2. Coverage assets

Mark everything touched so other flows don't redo it:

```
assets.mark type=service   value=192.0.2.10:161/udp        state=enumerated source=snmp-enum
assets.mark type=credential value="192.0.2.10 community=public v2c (ro)" source=snmp-enum
assets.mark type=credential value="192.0.2.10 community=private v2c (rw)" source=snmp-enum
assets.mark type=subnet    value=198.51.100.0/24           state=pending-discovery source=snmp-enum
assets.mark type=identity  value="192.0.2.10 windows-user:backupadm" source=snmp-enum
```

Mark hosts that answered onesixtyone but failed walks as `state=needs-retry`.

## 3. Findings

Report via `findings.report`; include the exact command and raw evidence lines.

| Condition | Suggested severity | Evidence to attach |
|---|---|---|
| Default/guessable read community (public etc.) | medium | onesixtyone hit line + sysDescr |
| Guessable **write** community | high | snmpset sysContact probe transcript (set + restore) |
| Cleartext creds in hrSWRunParameters | high | the matching OID line(s) |
| Windows user list exposed (1.3.6.1.4.1.77.1.2.25) | medium | user OID lines |
| Routing/ARP exposure revealing internal topology | low–medium | route table excerpt + subnets.txt |
| SNMPv3 noAuthNoPriv walk permitted | high | snmpwalk transcript |
| Cisco config exfiltrated via ccCopy | critical | copyState=3 snmpget + config filename/hashes |
| net-snmp nsExtend command execution | critical | snmpset + triggered output |

Example:

```
findings.report \
  title="Guessable SNMP write community 'private' on 192.0.2.10" \
  severity=high \
  asset=192.0.2.10:161/udp \
  evidence=@snmp_out/write_probe_192.0.2.10.txt \
  description="snmpset of sysContact succeeded with community 'private' (v2c); value restored. Enables config exfil/upload (CISCO-CONFIG-COPY) or nsExtend RCE." \
  tags=snmp,default-credentials,write-access
```
