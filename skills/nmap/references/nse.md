# NSE — the Nmap Scripting Engine

Lua scripts (600+) shipped in `/usr/share/nmap/scripts/`, driven by the
`--script` option. NSE turns nmap from a port scanner into an enumeration and
vulnerability-probing engine. This file: engine mechanics, categories, and the
per-service targeted script lists with ready invocations.

## Engine mechanics

```
-sC                         # run the "default" category (pair with -sV)
--script <expr>             # names, globs, categories, boolean expressions
--script-args k=v,k2=v2     # script parameters
--script-args-file file     # same, from file
--script-help "<expr>"      # usage docs for matching scripts
--script-trace              # dump script-level network traffic
--script-updatedb           # rebuild script.db after adding/editing scripts
-sV                         # many scripts key off detected service, not port number — run -sV with scripts
```

Expression examples:

```
--script default,safe
--script "smb-enum-*"
--script "vuln and not dos"
--script "(discovery or vuln) and not (intrusive or brute)"
--script /opt/custom-scripts/my-check.nse
```

Finding scripts:

```
ls /usr/share/nmap/scripts | grep -i smb
grep -l "categories.*vuln" /usr/share/nmap/scripts/*.nse
nmap --script-help "smb-vuln-*"
```

Script phases: prerule (before scanning, e.g. `broadcast-*`, `dns-brute`),
host scripts (per host, e.g. `smb-os-discovery`), port scripts (per open port,
most of them), postrule (reporting). Broadcast scripts
(`broadcast-dhcp-discover`, `broadcast-netbios-master-browser`,
`broadcast-ping`) run without targets: `nmap --script broadcast -e eth0`.

## Categories

| Category | Content | Notes |
|---|---|---|
| `default` | What `-sC` runs: fast, useful, low-impact | Baseline on every deep pass |
| `safe` | Won't crash services or consume heavy resources | Broad sweep without `intrusive` |
| `discovery` | Enumeration of hosts/services/shares/users | Core of recon |
| `version` | Extend `-sV` detection | Run automatically with `-sV` |
| `auth` | Auth checks, anonymous/null access, credential use | `ftp-anon`, `smb-enum-*` with creds |
| `brute` | Credential guessing (`*-brute`) | Pair with `--script-args userdb=,passdb=`; set `unpwdb.timelimit=0` for unlimited runs |
| `vuln` | Checks for specific vulnerabilities, reports findings | Primary vuln sweep; some overlap with intrusive |
| `intrusive` | May crash/alter target or trip IDS | Expected during exploitation-adjacent work |
| `exploit` | Actively exploits (`http-shellshock`, `smb-vuln-ms17-010` check/exploit modes) | |
| `dos` | May deny service | Exclude with `and not dos` unless testing resilience |
| `malware` | Backdoor/implant detection (`ftp-vsftpd-backdoor`) | Cheap wins on compromised hosts |
| `external` | Talks to third-party services (whois, Shodan) | Leaks target info off-net — know when you use it |
| `fuzzer` | Protocol fuzzing | Lab/crash-hunting |

Useful global script-args: `--script-args http.useragent="Mozilla/5.0"`,
`--script-args smbusername=svc,smbpassword=Passw0rd!` (credentialed SMB
scripts), `--script-args vulns.showall` (vuln scripts print NOT VULNERABLE
too — proves coverage).

## Per-service targeted script lists

Run these against ports confirmed open by earlier phases. Always include
`-sV` and `-oA`.

### SMB / NetBIOS — 445, 139

```
sudo nmap -sS -sV -p 445,139 \
  --script "smb-os-discovery,smb-security-mode,smb2-security-mode,smb2-time,smb2-capabilities,smb-enum-shares,smb-enum-users,smb-enum-sessions,smb-enum-domains,smb-protocols" \
  192.0.2.10 -oA scans/nse-smb
# vuln pass (MS17-010 etc.)
sudo nmap -sS -p 445 --script "smb-vuln-*" 192.0.2.10 -oA scans/nse-smb-vuln
# credentialed
sudo nmap -p 445 --script smb-enum-shares,smb-enum-users \
  --script-args smbusername=jdoe,smbpassword='Winter2024!' 192.0.2.10 -oA scans/nse-smb-auth
```

Read: `message_signing: disabled` (smb2-security-mode) → relay candidate;
anonymous share listings; OS/domain/FQDN from smb-os-discovery. Hand off to
the `smb-enum` sub-skill.

### LDAP / Active Directory — 389, 636, 3268, 3269

```
sudo nmap -sS -sV -p 389,636,3268 --script "ldap-rootdse,ldap-search" \
  192.0.2.10 -oA scans/nse-ldap
# authenticated search
sudo nmap -p 389 --script ldap-search \
  --script-args 'ldap.username="cn=jdoe,cn=users,dc=example,dc=com",ldap.password=Winter2024!,ldap.qfilter=users' \
  192.0.2.10 -oA scans/nse-ldap-auth
```

Read rootdse: `defaultNamingContext`, `dnsHostName`, domain functional level,
supported SASL mechs. Also grab `krb5-enum-users` on 88:
`--script krb5-enum-users --script-args krb5-enum-users.realm=EXAMPLE.COM,userdb=users.txt`.
Hand off to `ldap-ad-enum`.

### HTTP(S) — 80, 443, 8080, 8443, any `-sV` http

```
sudo nmap -sS -sV -p 80,443,8080,8443 \
  --script "http-title,http-headers,http-server-header,http-methods,http-robots.txt,http-enum,http-cookie-flags,http-auth,http-git" \
  192.0.2.10 -oA scans/nse-http
# vuln pass
sudo nmap -sS -sV -p 80,443 --script "http-vuln-*,http-shellshock,http-sql-injection" \
  192.0.2.10 -oA scans/nse-http-vuln
```

`http-enum` is a mini directory brute (nikto-style fingerprints); `http-methods`
with `--script-args http-methods.test-all` flags PUT/DELETE/TRACE; `http-git`
finds exposed `.git`. Hand off to web tooling (gobuster/ffuf/nuclei).

### SNMP — 161/udp

```
sudo nmap -sU -sV -p 161 \
  --script "snmp-info,snmp-interfaces,snmp-sysdescr,snmp-processes,snmp-netstat,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users" \
  --script-args snmp.version=v2c,creds.snmp=:public 192.0.2.10 -oA scans/nse-snmp
# community brute
sudo nmap -sU -p 161 --script snmp-brute \
  --script-args snmp-brute.communitiesdb=communities.txt 192.0.2.10 -oA scans/nse-snmp-brute
```

A readable community string dumps processes, users, netstat, software — often
the best unauthenticated intel on a host. Hand off to `snmp-enum`
(snmpwalk/onesixtyone).

### NFS / RPC — 2049, 111

```
sudo nmap -sS -sV -p 111,2049 --script "rpcinfo,nfs-showmount,nfs-ls,nfs-statfs" \
  192.0.2.10 -oA scans/nse-nfs
```

`nfs-showmount` lists exports + allowed clients; `nfs-ls` lists contents and
permissions (world-readable exports → mount them). Hand off to `nfs-enum`.

### MS-SQL — 1433/tcp, 1434/udp

```
sudo nmap -sS -sU -sV -p T:1433,U:1434 \
  --script "ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password,ms-sql-config,ms-sql-dac" \
  192.0.2.10 -oA scans/nse-mssql
# brute + post-auth
sudo nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt 192.0.2.10 -oA scans/nse-mssql-brute
sudo nmap -p 1433 --script ms-sql-xp-cmdshell,ms-sql-dump-hashes \
  --script-args mssql.username=sa,mssql.password=sapass,ms-sql-xp-cmdshell.cmd="whoami" \
  192.0.2.10 -oA scans/nse-mssql-exec
```

1434/udp browser service reveals instance names and real TCP ports even when
1433 is firewalled. `ms-sql-ntlm-info` leaks domain/hostname pre-auth.

### RDP — 3389

```
sudo nmap -sS -sV -p 3389 --script "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020" \
  192.0.2.10 -oA scans/nse-rdp
```

`rdp-ntlm-info` leaks NetBIOS/DNS computer and domain names pre-auth;
`rdp-enum-encryption` shows NLA/CredSSP posture.

### TLS — 443 or any `-sV`-detected TLS wrapper

```
sudo nmap -sS -sV -p 443,8443,636,3389,465,993,995 \
  --script "ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,ssl-poodle,sslv2" \
  192.0.2.10 -oA scans/nse-tls
```

`ssl-cert` CN/SAN entries reveal vhosts and internal names — feed back into
DNS/web recon. `ssl-enum-ciphers` grades each suite; anything < A is report
material.

### DNS — 53

```
sudo nmap -sSU -sV -p 53 --script "dns-nsid,dns-recursion,dns-service-discovery" \
  192.0.2.53 -oA scans/nse-dns
# zone transfer + SRV enumeration against a known domain
sudo nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com \
  192.0.2.53 -oA scans/nse-dns-axfr
sudo nmap -p 53 --script dns-srv-enum --script-args dns-srv-enum.domain=example.com \
  192.0.2.53 -oA scans/nse-dns-srv
# subdomain brute (prerule, no port needed)
nmap --script dns-brute --script-args dns-brute.domain=example.com,dns-brute.threads=12 -oA scans/nse-dns-brute example.com
```

A successful AXFR is a finding by itself and a complete host list. Hand off to
`dns-recon`.

### FTP — 21

```
sudo nmap -sS -sV -p 21 --script "ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor" \
  192.0.2.10 -oA scans/nse-ftp
```

### SSH — 22

```
sudo nmap -sS -sV -p 22 --script "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" \
  --script-args ssh.user=root 192.0.2.10 -oA scans/nse-ssh
```

`ssh-auth-methods` revealing `password` → spray candidate; hostkey reuse across
hosts reveals cloned images.

### Mail — 25, 465, 587, 110, 143

```
sudo nmap -sS -sV -p 25,465,587 \
  --script "smtp-commands,smtp-open-relay,smtp-enum-users,smtp-ntlm-info" \
  --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} 192.0.2.10 -oA scans/nse-smtp
```

### IKE / VPN — 500/udp, 4500/udp

```
sudo nmap -sU -sV -p 500,4500 --script "ike-version" 192.0.2.10 -oA scans/nse-ike
```

Then hand off to the `ike-scan` sub-skill for aggressive-mode / PSK work —
NSE coverage of IKE is shallow.

### IPMI — 623/udp

```
sudo nmap -sU -sV -p 623 --script "ipmi-version,ipmi-cipher-zero" 192.0.2.10 -oA scans/nse-ipmi
```

`ipmi-cipher-zero` = auth bypass; IPMI 2.0 hash disclosure follows (metasploit
`ipmi_dumphashes`).

### MySQL / Postgres / Redis / Mongo / Elastic — 3306, 5432, 6379, 27017, 9200

```
sudo nmap -sS -sV -p 3306,5432,6379,27017,9200 \
  --script "mysql-info,mysql-empty-password,pgsql-brute,redis-info,mongodb-info,mongodb-databases,http-title" \
  192.0.2.10 -oA scans/nse-db
```

Unauthenticated `redis-info` / `mongodb-databases` / Elasticsearch `9200`
responses are frequent direct findings.

### Vuln sweep (any confirmed service)

```
sudo nmap -sS -sV -p 21,22,80,139,443,445,3389 --script "vuln and not dos" \
  --script-args vulns.showall 192.0.2.10 -oA scans/nse-vuln
```

Read `State: VULNERABLE` blocks; each includes IDs (CVE), risk, and
references — copy them verbatim into findings.

## Brute category pattern

```
sudo nmap -p <port> --script <svc>-brute \
  --script-args userdb=users.txt,passdb=passwords.txt,brute.firstonly=true,unpwdb.timelimit=0 \
  192.0.2.10 -oA scans/nse-brute-<svc>
```

Available for ssh, ftp, smb, ms-sql, mysql, pgsql, snmp, http (`http-brute`,
`http-form-brute`), rdp (`rdp-ntlm` via other tools is better), vnc, telnet,
imap/pop3/smtp, and more. For serious credential attacks hand off to
hydra/medusa/crackmapexec — NSE brute is for quick wins and default creds.

## Reading NSE output into the pipeline

Script results land in the XML as `<script id="..." output="...">` elements
under each port (and `<hostscript>` for host scripts).
`scripts/parse_nmap_xml.py` captures them into
`ports[].scripts{id: output}` in `inventory.json`, so downstream work units
and findings can quote script evidence directly.
