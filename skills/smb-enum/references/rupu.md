# rupu Integration — smb-enum

How this skill's outputs feed the orchestration layer. The reporting formats come
from the shared pack — import these skills **by name** and follow them, do not
re-invent their schemas:

- **`work-units`** — the work-unit array contract (`[{id,title,targets,hints}]`).
- **`coverage-assets`** — `assets.mark` for everything enumerated.
- **`finding-report`** — `findings.report` for verified issues.

## 1. Work units → `for_each:` / `dispatch`

`scripts/parse_smb.py` writes `work_units.json`: a clean JSON **array**, no
wrapper object, each element `{id, title, targets, hints}` per the `work-units`
skill. Feed it to a rupu flow:

```yaml
- id: smb-followup
  for_each:
    items_from:
      read_file: smb_192.0.2.10/work_units.json
    as: wu
  steps:
    - run: <skill selected by wu.hints.skill> with targets {{ wu.targets }}
```

Or let a lead agent fan it out with `dispatch`, one unit per worker. Typical units
emitted:

| id prefix | title | hints |
|---|---|---|
| `share-walk-` | Walk readable share X | `{skill: "smb-enum", share, access}` |
| `spray-` | Password spray harvested users | `{skill: "netexec", userfile: "users.txt", lockout_threshold, lockout_window}` |
| `relay-` | NTLM relay unsigned hosts | `{targets_file: "relay-targets.txt"}` |
| `ms17-010-` | Verify EternalBlue on SMBv1 host | `{skill: "nmap", script: "smb-vuln-ms17-010"}` |
| `ldap-pivot-` | Enumerate the discovered DC | `{skill: "ldap-ad-enum", domain}` |

## 2. Coverage assets → `assets.mark`

Mark everything you touched/learned, per the `coverage-assets` skill:

- host asset per SMB endpoint (`192.0.2.10:445`) with attrs: os, signing, smbv1, dialects.
- domain asset when `inventory.json.domain` is set (e.g. `EXAMPLE` / example.com),
  with the DC host linked.
- share asset per entry in `shares[]` with its access level.
- account asset per harvested username (uncredentialed state until a spray hits).

This is what lets later flows skip re-enumeration and lets the lead see coverage.

## 3. Findings → `findings.report`

Report **verified** conditions only, with the raw evidence line from the tool output:

| Condition | Evidence to attach |
|---|---|
| Null session yields data | enum4linux-ng/rpcclient output showing users/shares/policy over `-u '' -p ''` |
| Guest access to shares | smbmap line with `READ`+ as guest |
| SMB signing not required | `smb_signing_required: false` / nmap `smb2-security-mode` line |
| SMBv1 enabled | `smb1_supported: true` / `smb-protocols` NT LM 0.12 |
| MS17-010 vulnerable | nmap `smb-vuln-ms17-010` VULNERABLE block |
| Writable share (esp. SYSVOL/NETLOGON/wwwroot) | smbmap `READ, WRITE` line |
| Credentials found in share files | file path + redacted excerpt |
| Admin exec achieved (`smbmap -x`) | command output proving execution |

Severity guidance: ms17-010 / writable SYSVOL / admin exec → critical;
signing off on many hosts, null session with user dump → high; SMBv1 alone,
guest share read → medium (raise if contents are sensitive).

— vulture (silver-pinnacle)
