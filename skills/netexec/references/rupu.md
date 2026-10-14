# rupu ingestion contract for the netexec skill

This skill ends every parse/handoff step with rupu-ingestible output. The
machinery for work units, coverage assets, and findings is shared across the
fleet — **import the reporting-pack skills by name and use their contracts
verbatim. Do not re-invent schemas:**

- **`work-units`** — the follow-up queue contract
- **`coverage-assets`** — `assets.mark` coverage recording
- **`finding-report`** — `findings.report` verified-issue recording

## 1. Work units (stdout of parse_nxc.py)

`python3 scripts/parse_nxc.py <logs...> -o out/` prints a clean JSON **array**
(first byte `[`) of work units:

```json
[
  {
    "id": "spray-users-example-com",
    "title": "Password spray 42 discovered users against DC",
    "targets": ["192.0.2.5"],
    "hints": [
      "users file: out/users.txt",
      "pass-pol: lockout threshold 5, window 30m -> max 3 attempts/account/window",
      "nxc smb 192.0.2.5 -u out/users.txt -p '<candidate>' -d example.com --continue-on-success --log spray.log"
    ]
  }
]
```

Feed it per the `work-units` skill:

- **for_each**: a rupu step `read_file`s the array (write it to a file:
  `python3 scripts/parse_nxc.py logs/*.log -o out/ > out/work_units.json`) and
  fans out one task per element; `targets` and `hints` become the task context.
- **dispatch**: a lead agent passes individual units to workers via its
  `dispatch` primitive, using `id` for dedupe/tracking.

Unit `id`s are deterministic (stable across re-parses of the same facts) so
re-runs don't duplicate queue entries.

## 2. Coverage assets (`assets.mark` — see `coverage-assets`)

Mark everything nxc touched so the recon flow knows what is covered:

- every fingerprinted host → asset kind `host`, properties: netbios name,
  domain, OS/build, smb signing, smbv1 (from `nxc_parsed.json .hosts`)
- every readable/writable share → asset kind `share`
  (`//192.0.2.17/DATA`, props: perms, remark)
- every validated account → asset kind `credential`
  (`example.com\jdoe`, props: protocol(s), pwned hosts) — mark the account as
  covered, store the secret only in the credential store the platform provides

`nxc_parsed.json` keys `hosts`, `shares`, `creds`, `users` map 1:1 onto these.

## 3. Findings (`findings.report` — see `finding-report`)

Report **verified** conditions only — nxc output is the evidence; attach the
matching log lines:

| condition | evidence line shape | typical severity |
|---|---|---|
| SMB null session with data | `[+] example.com\:` + `--users/--shares` output | medium/high |
| Guest access to shares | `[+] example.com\guest:` + share READ | medium |
| SMB signing not required | `(signing:False)` fingerprint line | medium (relay enabler) |
| Valid sprayed credential | `[+] example.com\jdoe:Autumn2024!` | high |
| Admin exec / lateral | `(Pwn3d!)` | high/critical |
| Local-admin password reuse | same `--local-auth` cred Pwn3d on N hosts | high |
| SAM/LSA secrets dumped | `--sam`/`--lsa` hash lines | critical |
| NTDS dump (domain compromise) | `--ntds` output on DC | critical |
| Kerberoastable SPN accounts | `--kerberoasting` hash export | medium/high |
| AS-REP roastable accounts | `--asreproast` hash export | medium/high |
| Module-verified vuln (zerologon, ms17-010, printnightmare, ...) | module `VULNERABLE` line | critical |

One finding per condition per affected set (group identical signing-disabled
hosts into one finding with all targets listed), per the `finding-report`
schema.

## 4. End-of-step ritual

Every nxc batch ends the same way:

```
nxc ... --log step.log
python3 scripts/parse_nxc.py step.log -o out/ > out/work_units.json
# then: assets.mark from out/nxc_parsed.json, findings.report for the table above,
# and hand out/work_units.json to for_each / dispatch.
```
