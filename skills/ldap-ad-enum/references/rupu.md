# rupu Integration — ldap-ad-enum

How this skill's outputs feed the orchestration layer. Import the shared pack
skills **by name** and follow their schemas — do not re-invent them:

- **`work-units`** — the work-unit array contract (`[{id,title,targets,hints}]`).
- **`coverage-assets`** — `assets.mark` for enumerated objects.
- **`finding-report`** — `findings.report` for verified issues.

## 1. Work units → `for_each:` / `dispatch`

`scripts/parse_ldap.py` writes `work_units.json`: a clean JSON **array** of
`{id, title, targets, hints}` elements. Feed into a rupu flow:

```yaml
- id: ldap-followup
  for_each:
    items_from:
      read_file: ldap_example.com/work_units.json
    as: wu
  steps:
    - run: <skill from wu.hints.skill> against {{ wu.targets }}
```

Or hand the array to a lead's `dispatch` for parallel fan-out. Typical units:

| id prefix | title | hints |
|---|---|---|
| `kerberoast-` | Roast SPN accounts | `{skill: "netexec", mode: "--kerberoasting", targets_file: "spn-targets.txt"}` |
| `asrep-` | AS-REP roast preauth-less accounts | `{skill: "netexec", mode: "--asreproast"}` |
| `spray-` | Spray harvested users | `{skill: "netexec", userfile: "users.txt", note: "pull pass-pol from smb-enum first"}` |
| `deleg-` | Abuse delegation on host/account X | `{type: "unconstrained|constrained|rbcd", principal}` |
| `cred-desc-` | Verify credential found in description | `{skill: "netexec", account, candidate_password}` |
| `trust-pivot-` | Enumerate trusted domain | `{skill: "ldap-ad-enum", domain, direction}` |
| `bloodhound-` | Collect + ingest BloodHound CE data | `{collector: "bloodhound-ce-python", methods: "All"}` |
| `laps-` / `gmsa-` | Dump readable LAPS/gMSA secrets | `{skill: "netexec", module: "laps|gmsa"}` |

## 2. Coverage assets → `assets.mark`

Per the `coverage-assets` skill, mark:

- the DC host (`192.0.2.10:389/636/3268`) with attrs: FQDN, naming contexts,
  anonymous-bind state.
- a domain asset per naming context / trustedDomain (`example.com`, trust partners).
- an account asset per user in `inventory.json.users` (flag kerberoastable/asrep/
  adminCount in attrs); computer assets per entry in `computers`.
- group assets for privileged groups with member counts.

This dedupes later enumeration and gives the lead a coverage picture of the forest.

## 3. Findings → `findings.report`

Report **verified** conditions with raw evidence (the LDIF entry or tool line):

| Condition | Evidence |
|---|---|
| Anonymous LDAP bind returns objects | the unauthenticated ldapsearch output with entries |
| Password/credential in `description` | the LDIF `description:` line (redact in title, full in evidence) |
| Kerberoastable SPN account (esp. privileged/adminCount=1) | sAMAccountName + servicePrincipalName LDIF; escalate to confirmed-cracked finding once hashcat lands |
| AS-REP roastable account | UAC filter match LDIF; escalate on crack |
| Unconstrained delegation on non-DC | computer entry + UAC bit |
| Constrained delegation / RBCD | msDS-AllowedToDelegateTo / msDS-AllowedToActOnBehalfOfOtherIdentity values |
| LAPS password readable by low-priv | ms-Mcs-AdmPwd value returned (redact) |
| gMSA password readable | msDS-ManagedPassword blob returned |
| PASSWD_NOTREQD accounts | UAC filter match |
| Reversible encryption enabled | UAC 0x80 match |

Severity guidance: readable LAPS/gMSA, cracked kerberoast of privileged account,
cred-in-description that validates → critical/high; anonymous bind with full user
dump, unconstrained delegation on non-DC → high; AS-REP/kerberoastable existing
(uncracked), PASSWD_NOTREQD → medium pending exploitation result.

— vulture (silver-pinnacle)
