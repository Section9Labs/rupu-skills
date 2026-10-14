# rupu handoff — ike-scan

Import the shared reporting-pack skills by name — `work-units`,
`coverage-assets`, `finding-report` — and follow their schemas. Do not
re-invent the formats here.

## Work units → for_each / dispatch

`scripts/parse_ike.py --units units.json` writes a clean JSON array (first
byte `[`) of follow-up units, e.g.:

```json
[
  {
    "id": "ike-psk-crack-203-0-113-50",
    "title": "crack captured PSK for 203.0.113.50",
    "targets": ["203.0.113.50"],
    "hints": "psk-crack -d rockyou.txt psk-203.0.113.50.txt; hash auto MD5/SHA1; hashcat 5300/5400 for GPU"
  },
  {
    "id": "ike-aggressive-203-0-113-60",
    "title": "test aggressive mode on 203.0.113.60",
    "targets": ["203.0.113.60"],
    "hints": "main-mode handshake returned; try ike-scan -A --id=<group> -P; group-ID candidates: vpn, company name"
  }
]
```

Consume it either way:

- **for_each:** a rupu plan step `read_file`s `units.json` and iterates,
  running one task per unit with `targets`/`hints` interpolated.
- **dispatch:** a lead reads the array and `dispatch`es units to workers;
  `id` is the dedup key, `title` the task line.

## Coverage assets

Mark every responding IKE endpoint via `assets.mark` (per `coverage-assets`):

- asset = `udp://<ip>:500` (and `udp://<ip>:4500` when NAT-T answers),
  kind `service`
- metadata: IKE version(s), mode(s) answered, accepted transform(s), vendor
  guess (VID/backoff), whether a PSK hash was captured.

Mark probed-but-silent hosts too (status: no IKE) so VPN coverage of the
scope is complete.

## Findings

File via `findings.report` (per `finding-report`), with raw ike-scan /
psk-crack output as evidence:

- **Aggressive mode with PSK enabled** — PSK hash obtainable
  unauthenticated (the `-P` capture file is the evidence). High severity
  even before cracking.
- **Cracked PSK** — include the psk-crack `key "..." matches` line and the
  group ID; critical, since it yields VPN access or XAUTH MitM.
- **Weak transforms accepted** — DES (enc=1), MD5 (hash=1), DH group 1/2;
  medium, evidence = the accepted `--trans` combos.
- **Fingerprint-derived version issues** — VID/backoff identifies an
  EOL/vulnerable implementation; link the guess output and CVE candidates.

Reference the marked asset in each finding so coverage and findings stay
joined.
