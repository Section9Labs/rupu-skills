# rupu Integration — dns-recon

This skill's handoff is rupu-ingestible. It builds on the shared reporting-pack
skills — **import them by name, do not re-implement their formats**:

- `work-units` — schema and conventions for `{id,title,targets,hints}` arrays
- `coverage-assets` — `assets.mark` for recording what was enumerated/covered
- `finding-report` — `findings.report` for verified issues with evidence

## Work units → fan-out

`scripts/parse_dns.py` emits `out/work-units.json`: a clean JSON **array**
(first byte `[`) of port-scan work units grouped by /24 netblock, conforming to
the `work-units` skill:

```json
[
  {
    "id": "port-scan-203-0-113-0-24",
    "title": "port-scan 203.0.113.0/24 (4 hosts)",
    "targets": ["203.0.113.10", "203.0.113.11", "203.0.113.37", "203.0.113.80"],
    "hints": ["www.example.com -> 203.0.113.10", "vpn.example.com -> 203.0.113.11"]
  }
]
```

Drive it from a rupu plan with `for_each:` over `read_file`:

```yaml
- step: port-scan-fanout
  for_each: read_file("out/work-units.json")
  do:
    skill: naabu            # or nmap for direct deep enum
    targets: "{{ item.targets }}"
    context: "{{ item.title }} — {{ item.hints }}"
```

Or let a lead agent `dispatch` each element of the array to worker agents, one
unit per worker. Each unit is self-contained: `targets` is what to scan,
`hints` carries hostname→IP pairs for SNI/vhost-aware follow-up.

## Coverage assets

Record everything enumerated via `assets.mark` (see `coverage-assets` for exact
call shape) so the fleet knows what dns-recon already covered:

- every discovered subdomain → asset type `hostname`, state `discovered`;
  validated ones additionally `resolved` with their IPs as attributes
- every live IP in `scan-targets.txt` → asset type `ip`, state `pending-portscan`
- every /24 group and ASN-derived CIDR → asset type `netblock` with the
  host count and ASN as attributes
- new root domains found via `amass intel` / PTR / reverse-whois → asset type
  `domain`, state `discovered` (queue a fresh dns-recon pass against them)

## Findings

Report **verified** issues through `findings.report` (schema in
`finding-report`), with raw tool output as evidence:

| finding | evidence to attach |
|---|---|
| Zone transfer allowed (AXFR) | full `dig axfr example.com @ns2.example.com` dump, per-NS results |
| Subdomain takeover candidate | `dig` output showing dangling CNAME + provider error response |
| Wildcard misconfiguration | random-label `dig` answers, where the wildcard points |
| Info disclosure via DNS | TXT/SPF internal ranges, PTR internal names, `version.bind` reply |

Severity guidance: AXFR externally is typically medium; a *confirmed* takeover
(you can claim the resource) is high; wildcard/info-disclosure usually low to
medium depending on what leaks.

## Order of operations

1. Run the pipeline (SKILL.md stages 1–4).
2. `python3 scripts/parse_dns.py --out-dir out <files…>` — ends with the
   rupu-ingestible array at `out/work-units.json` and a one-line summary on
   stderr; stdout mirrors the JSON array for direct piping.
3. `assets.mark` the hostnames/IPs/netblocks (coverage-assets).
4. `findings.report` any verified DNS issues (finding-report).
5. Feed `out/work-units.json` to the `recon` flow's `for_each:`/`dispatch`
   targeting the `naabu`/`nmap` skills (work-units).
