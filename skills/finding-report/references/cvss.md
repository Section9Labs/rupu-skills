# CVSS v3.1 — deriving the base vector honestly

Source of truth: the FIRST CVSS v3.1 Specification Document
(https://www.first.org/cvss/v3.1/specification-document). `rating.cvss_v3` in
the rupu finding schema expects a **v3.1** base score/vector. CVSS v4.0 exists
as the successor (new metrics, no Scope); do not use v4.0 vectors in
`cvss_v3` — compute v3.1.

Score the **vulnerability as exploited in the reasonable worst case**, assuming
the attacker has already located it and prepared. Score the vulnerable
component as deployed on the engagement, not a hypothetical hardened config.

The base vector string:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Metrics must appear with the `CVSS:3.1/` prefix; order above is canonical.
Compute with `python3 scripts/cvss31.py '<vector>'` — never arithmetic by hand,
never a remembered score from a "similar" CVE.

## The eight base metrics

### AV — Attack Vector (where must the attacker be?)

| Value | Choose when | Weight |
|-------|-------------|--------|
| `N` Network | Exploitable from across the network at layer 3, "remotely exploitable" — one or more network hops, typically the internet. A listener on 203.0.113.20:443 reachable from anywhere → N. | 0.85 |
| `A` Adjacent | Bound to the same shared physical/logical network: same L2 segment, same Wi-Fi, same VPN, ARP/DHCP attacks, Bluetooth. | 0.62 |
| `L` Local | Attacker needs local access — a shell, an account, SSH — or relies on user interaction to run something locally (malicious document). Not network-stack reachable. | 0.55 |
| `P` Physical | Attacker must physically touch the device (evil-maid, cold boot, USB port). | 0.20 |

Decision: ask "what is the *most remote* position from which this works?" and
pick that. An SSRF reachable over the internet is `N` even though it targets
internal hosts (the internal reach shows up in Scope, not AV).

### AC — Attack Complexity (conditions beyond the attacker's control)

| Value | Choose when | Weight |
|-------|-------------|--------|
| `L` Low | No special conditions. The attack is repeatable at will against any vulnerable target: send the request, win. | 0.77 |
| `H` High | Success depends on conditions the attacker cannot control and must win: a race condition, winning a MitM position first, a non-default configuration, environment-specific knowledge (secret addresses, per-target values) that must be gathered. | 0.44 |

NOT complexity: required skill, number of steps, needing to write an exploit,
needing credentials (that's PR), needing a victim click (that's UI).

### PR — Privileges Required (on the vulnerable component, pre-attack)

| Value | Choose when | Weight (S:U / S:C) |
|-------|-------------|---------------------|
| `N` None | Anonymous/unauthenticated access suffices. Self-registration that anyone can complete still generally rates `N` unless the engagement treats accounts as controlled. | 0.85 / 0.85 |
| `L` Low | Basic authenticated user (any low-priv account, any tenant). | 0.62 / 0.68 |
| `H` High | Administrative or otherwise significant control over the component is needed first. | 0.27 / 0.50 |

Note the weight rises for `L`/`H` when Scope is Changed — breaking out from a
privileged position is worth more.

### UI — User Interaction

| Value | Choose when | Weight |
|-------|-------------|--------|
| `N` None | Attacker alone completes the exploit. | 0.85 |
| `R` Required | A human other than the attacker must act: click a link, open a file, visit a page, approve a prompt. Reflected XSS and CSRF are `UI:R`. Stored XSS is usually `UI:R` too — the victim must view the page. | 0.62 |

### S — Scope (does impact cross a security authority?)

| Value | Choose when |
|-------|-------------|
| `U` Unchanged | Impact is confined to resources governed by the same security authority as the vulnerable component. SQLi reading the app's own database → `U` (the DB serves that app under the same authority). |
| `C` Changed | The exploit crosses into resources governed by a *different* authority: VM/container escape to host, XSS (vulnerable component = web server, impacted component = victim's browser), SSRF pivoting to internal services, sandbox escape, a shared DB serving other applications. |

Scope is the most mis-scored metric. Test: name the vulnerable component and
the impacted component. Same authority governs both → `U`. When `C`, score
C/I/A against the *more severely* impacted component.

### C / I / A — Confidentiality, Integrity, Availability impact

Each independently, on the impacted component:

| Value | Confidentiality | Integrity | Availability | Weight |
|-------|-----------------|-----------|--------------|--------|
| `H` | Total loss, or serious direct impact: all data readable, or the disclosed data is itself critical (admin password, private key, full PII table). | Attacker can modify any data, or modify critical data (price records, auth config, code). | Component fully down or repeatedly deniable at attacker's will. | 0.56 |
| `L` | Some restricted data disclosed; attacker doesn't control what, or impact is limited. | Some modification possible but constrained or without serious consequence. | Reduced performance, intermittent interruption. | 0.22 |
| `N` | No loss on that axis. | | | 0.00 |

SQLi that dumps every table: C:H. Can also `UPDATE`/`DROP`: I:H, and A:H if
tables can be destroyed. Blind boolean exfiltration of one limited field: C:L.
Information disclosure of a stack trace: C:L. Full account takeover of the
application: C:H/I:H (and usually A:H if the attacker can lock the account or
destroy data).

## The formula (what the script implements)

```
ISS            = 1 − (1−C)·(1−I)·(1−A)
Impact (S:U)   = 6.42 · ISS
Impact (S:C)   = 7.52 · (ISS − 0.029) − 3.25 · (ISS − 0.02)^15
Exploitability = 8.22 · AV · AC · PR · UI

Impact ≤ 0     → BaseScore = 0
S:U            → BaseScore = Roundup(min(Impact + Exploitability, 10))
S:C            → BaseScore = Roundup(min(1.08 · (Impact + Exploitability), 10))
```

`Roundup` is the spec's integer-safe round-up to one decimal (Appendix A):
multiply by 100000, round to int; if divisible by 10000 divide back, else floor
to the next 0.1 above. This is why 7.0000001-style float drift never changes a
score — use the script.

Scope-change interaction: `S:C` both re-curves the impact subscore (the 7.52…
polynomial, which compresses high ISS values but lifts mid ones) and applies
the final ×1.08 — plus the higher PR weights. So the same C/I/A profile scores
higher with `S:C`, but never above 10.0.

## Qualitative severity bands (spec §5)

| Band | Score |
|------|-------|
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

Map the band to `rating.risk_rating`/`risk_factor` as the starting point
(Critical→Critical, High→High, …), then adjust with documented reasoning if the
deployment context truly changes risk — and note that CVSS has no "Critical"
qualitative impact distinct from High; the schema's `rating.impact` scale
(Low/Medium/High/Critical) is the engagement's business-impact judgment, not a
CVSS output.

## Common mis-scorings

- **Scope inflation**: SQLi against the app's own DB is `S:U`, not `S:C`. The
  database authorizes the app to read it; no authority is crossed. `S:C` needs
  a second security authority (browser, hypervisor host, internal network,
  other tenants' apps).
- **Scope deflation on XSS/SSRF**: XSS is `S:C` (impact lands in victims'
  browsers); SSRF that reaches internal-only services is `S:C`.
- **PR vs UI confusion**: PR = privileges the *attacker* holds on the
  vulnerable component before attacking. UI = action by *someone else*. CSRF
  is `PR:N / UI:R` (attacker needs no account; victim must click). An attack
  requiring a stolen session is not `PR:N` — if any authenticated session
  works, it is `PR:L`.
- **AV:L for "needs credentials"**: credentials affect PR, not AV. A login-
  protected internet endpoint is `AV:N / PR:L`.
- **AV:A for "internal network only"**: a service on an internal routed network
  is still `AV:N` if exploitable across layer 3; `A` is for same-segment/link-
  layer attacks only.
- **AC:H for "hard to find" or "needs skill"**: discovery difficulty and
  exploit-engineering effort are explicitly excluded. AC:H is for conditions
  outside attacker control (races, MitM prerequisite, non-default config).
- **Chained scoring**: score the vulnerability in front of you, not the whole
  kill chain. "SQLi → cracked hash → admin" is SQLi's own C/I/A; the pivot
  belongs in the `impact` narrative (and possibly a separate finding with a
  `prerequisite` cross-reference).
- **Averaging C/I/A against partial reach**: if the attacker reads *all* data
  of the component, C:H — even if "only" the one database.
- **Guessing**: no evidence to pick a metric → gather evidence or, if severity
  truly cannot be assessed, set `rating.cvss_v3` to `Unknown`. Never a round
  number from memory.

## Classification companions

- **CWE** (https://cwe.mitre.org): pick the most specific weakness matching the
  *root cause* — CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (OS command injection),
  CWE-306 (missing authn), CWE-862/863 (missing/incorrect authz), CWE-287
  (improper authn), CWE-502 (deserialization), CWE-22 (path traversal),
  CWE-918 (SSRF), CWE-787 (OOB write), CWE-416 (UAF). Goes in `cwe[]`.
- **OWASP**: Top 10 2021 (`A01:2021`–`A10:2021`), API Security Top 10 2023
  (`API1:2023`–`API10:2023`), and WSTG test ids (e.g. `WSTG-INPV-05`) — in
  `references` and as `classifications` entries (`{"system":"OWASP","id":"A03:2021"}`).
- **CVE** (https://www.cve.org): only when the target demonstrably runs the
  vulnerable component/version; cite the evidence (banner, package version).
  Goes in `classifications` as `{"system":"CVE","id":"CVE-YYYY-NNNN"}`.
- **ATT&CK** (https://attack.mitre.org): technique ids for redteam-profile
  findings, e.g. `{"system":"ATT&CK","id":"T1190"}`.
