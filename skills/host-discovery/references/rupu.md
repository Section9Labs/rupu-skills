# rupu handoff — host-discovery

Import the shared reporting-pack skills by name — `work-units`,
`coverage-assets`, `finding-report` — and follow their schemas. Do not
re-invent the formats here.

## Work units → for_each / dispatch

`scripts/merge_alive.py --units units.json` writes a clean JSON array (first
byte `[`) of work units:

```json
[
  {
    "id": "portscan-203-0-113-10",
    "title": "port-scan 203.0.113.10",
    "targets": ["203.0.113.10"],
    "hints": "seen via: arp-scan, fping; mac=00:50:56:ab:12:34 vendor=VMware, Inc."
  }
]
```

Consume it either way:

- **for_each:** a rupu plan step `read_file`s `units.json` and iterates the
  array, running the port-scan task per unit with `targets` and `hints`
  interpolated.
- **dispatch:** a lead agent reads the array and `dispatch`es each unit to a
  worker, using `id` for dedup and `title` as the task line.

Hosts seen only via ARP/zmap/NetBIOS carry that in `hints` — downstream
scanners should use `-Pn` for those.

## Coverage assets

Mark every live host via `assets.mark` (per the `coverage-assets` skill) so
coverage is tracked even if the port scan is deferred:

- asset = the IP (e.g. `203.0.113.10`), kind `host`
- attach metadata from discovery: MAC + vendor (arp-scan), NetBIOS
  name/domain/user (nbtscan), discovery sources, responding zmap port.

Also mark the swept CIDRs themselves (kind `network`) so dead space is
provably covered, not just skipped.

## Findings

Discovery alone rarely yields a reportable vulnerability, but when it does,
file it via `findings.report` (per the `finding-report` skill), e.g.:

- hosts live outside the documented scope ranges (rogue/forgotten assets)
- duplicate MACs / ARP anomalies indicating spoofing or misconfigured HA
- NetBIOS exposing logged-in usernames across the segment (information
  disclosure feeding later credential attacks)

Attach the raw tool output lines as evidence and reference the asset marked
above.
