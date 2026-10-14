# NFS Export Options & ACL Reference

## Where options live

`showmount -e` shows only `path` + client ACL. The option list lives server-side in
`/etc/exports` (or `exportfs -v` output). Get it by: mounting and reading `/etc/exports` if
`/etc` or `/` is exported; looting it from a backup export; or inferring by behavior
(write test, uid-0 write test).

Format: `/path client1(opt,opt) client2(opt)` — note `client (rw)` with a space exports to
`client` with defaults AND to *everyone* rw (classic typo misconfig).

## Client ACL forms (showmount column 2)

| ACL | Meaning | Attack read |
|---|---|---|
| `*` / `(everyone)` | any source IP | mount from anywhere → world-mountable finding |
| `192.0.2.0/24` | subnet | mountable if you sit in / can pivot into it |
| `203.0.113.0/255.255.255.0` | netmask form | same |
| `host.example.com`, `*.example.net` | DNS names | reverse-DNS of YOUR ip is checked — control PTR or source from a matching host |
| netgroup `@trusted` | NIS netgroup | enumerate NIS (also on rpcbind) to see members |

## Options table

| Option | Default? | Meaning | Attack impact |
|---|---|---|---|
| `ro` / `rw` | ro | read-only / read-write | rw required for drop attacks; ro still leaks data |
| `root_squash` | yes | client uid 0 → anonuid (nobody) | blocks uid-0 writes; bypass by impersonating non-root owner uids |
| `no_root_squash` | — | client uid 0 honored | **critical**: write root-owned/SUID files, read any file (SKILL.md §4C) |
| `all_squash` | — | ALL uids → anon | kills uid-spoof reads; only anon-readable/writable data reachable |
| `no_all_squash` | yes | uids passed through | enables uid impersonation (§4A/B) |
| `anonuid=N`,`anongid=N` | 65534 | squash target | if set to a real user (e.g. 0!), squash itself becomes the privilege |
| `secure` | yes | require client src port <1024 | spoofing needs local root on the client |
| `insecure` | — | any src port | **unprivileged** uid spoofing via libnfs/nfsshell userspace clients |
| `sec=sys` | yes | client-asserted AUTH_SYS uid/gid | the whole uid-trust model — spoofable |
| `sec=krb5` / `krb5i` / `krb5p` | — | Kerberos auth (+integrity/+privacy) | uid spoofing dead; attack Kerberos instead |
| `subtree_check` / `no_subtree_check` | no_subtree_check | path confinement check | with no_subtree_check + filehandle guessing, files outside the export subtree may be reachable |
| `async` | — | ack writes before disk | irrelevant to access, good for fast exfil writes |
| `nohide` / `crossmnt` | — | expose nested mounts | more filesystems reachable through one export |
| `fsid=0` | — | NFSv4 pseudo-root | mount `server:/` with vers=4 and browse everything exported under it |

## Mount-side notes

| Mount option | Why |
|---|---|
| `vers=3` / `vers=4` / `vers=4.2` | force protocol; v3 for mountd-based ACL behavior, v4 when 111 filtered |
| `nolock` | skip nlockmgr (avoids hangs, needed when statd/lockd blocked) |
| `soft,timeo=30,retrans=2` | fail instead of hanging forever |
| `port=2049,mountport=<p>` | pin ports through a firewall/SSH pivot |
| `ro` | forensic-quiet looting |
| `tcp` / `udp` | transport; some old servers are udp-only |
| `nfsvers=2` | ancient servers; also weakest filehandle generation |

## Server fingerprints

- `rpcinfo -p`: nfs 100003 (versions column = 2/3/4), mountd 100005, nlockmgr 100021,
  status 100024, rquotad 100011, ypserv 100004 (NIS — its own enumeration target).
- `nfsstat -m` (on a client you control) shows negotiated options for active mounts.
- nmap `nfs-ls` prints `access: Read Lookup Modify ...` per export — a quick rw check
  without mounting, plus uid/gid/mode of top-level entries for the uid-impersonation list.

## Userspace (no local root) clients for `insecure` exports

- libnfs utils: `nfs-ls "nfs://192.0.2.20/srv/backups?version=3&uid=0&gid=0"`,
  `nfs-cp nfs://192.0.2.20/srv/backups/shadow /tmp/shadow`
- nfsshell / NfSpy: interactive clients that let you set arbitrary uid/gid per operation —
  useful when you cannot mount (container, no CAP_SYS_ADMIN) or must iterate many uids fast.
