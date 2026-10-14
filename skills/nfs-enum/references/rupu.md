# rupu Handoff — nfs-enum

This skill ends by producing `nfs_out/work_units.json` (clean JSON array of
`{id,title,targets,hints}`) and `nfs_out/nfs_enum.json`. Use the shared reporting-pack
skills by name — `work-units`, `coverage-assets`, `finding-report` — exactly as they
define; nothing here replaces them.

## 1. Feed work units

Via `for_each` in a rupu plan:

```yaml
- step: nfs-followup
  for_each: ${read_file("nfs_out/work_units.json")}
  as: unit
  do:
    - run: "Execute work unit ${unit.id}: ${unit.title} against ${unit.targets} — hints: ${unit.hints}"
```

Or from a lead agent:

```
units = json.load(open("nfs_out/work_units.json"))
for u in units: dispatch(unit=u)
```

Unit kinds this skill emits:
- `nfs-mount-loot-<host>-<pathslug>` — mountable export → mount, sweep for keys/configs/backups
- `nfs-norootsquash-exploit-<host>-<pathslug>` — rw + no_root_squash confirmed/suspected →
  SUID drop / authorized_keys write (SKILL.md §4C)
- `nfs-uid-impersonate-<host>-<pathslug>` — restricted owner uids seen → useradd/setuid reads
- `nfs-v4-pseudo-root-<host>` — v4-only server, mount `:/` and browse
- `host-discovery-<client>` — clients seen in `showmount -a` → new targets

## 2. Coverage assets

```
assets.mark type=service value=192.0.2.20:111/tcp  state=enumerated source=nfs-enum
assets.mark type=service value=192.0.2.20:2049/tcp state=enumerated source=nfs-enum
assets.mark type=export  value="192.0.2.20:/srv/backups acl=* rw" state=mounted source=nfs-enum
assets.mark type=export  value="192.0.2.20:/home acl=192.0.2.0/24" state=pending-mount source=nfs-enum
assets.mark type=host    value=198.51.100.7 state=new source=nfs-enum   # from showmount -a
```

Mark exports whose ACL excludes your position as `state=blocked-acl` with the ACL recorded,
so a pivoted re-run from inside the ACL picks them up.

## 3. Findings

Report via `findings.report` with raw command output as evidence.

| Condition | Suggested severity | Evidence |
|---|---|---|
| World-mountable export (`*`/everyone) | medium (high if sensitive content) | showmount -e line + mount + listing |
| Sensitive data in export (keys, shadow, backups, PII) | high | file paths + sanitized excerpts |
| rw export writable by spoofed uid (authorized_keys drop possible) | high | write test transcript |
| **rw + no_root_squash** | critical | root-owned file created from client (`touch`+`ls -ln`), or §4C SUID proof |
| `insecure` export (unprivileged spoofing) | high | libnfs access transcript with uid=0 |
| `showmount -a` client disclosure | low | showmount -a output |
| NFS without Kerberos (sec=sys) carrying sensitive data | medium | negotiated sec from nfsstat/mount |

Example:

```
findings.report \
  title="NFS export /srv/backups on 192.0.2.20 is world-mountable rw with no_root_squash" \
  severity=critical \
  asset=192.0.2.20:2049/tcp \
  evidence=@nfs_out/proof_192.0.2.20_srv_backups.txt \
  description="showmount -e lists /srv/backups *. Mounted vers=3; uid-0 write honored: created root-owned 4755 binary from the client (proof attached). Direct path to root on the server and full read of all stored backups." \
  tags=nfs,no_root_squash,world-mountable
```
