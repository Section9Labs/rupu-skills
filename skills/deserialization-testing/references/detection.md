# Spotting Serialized Objects — markers, seats, decode pipeline

## 1. Format markers

| Format | Raw bytes (hex) | Base64 prefix | Text form |
|---|---|---|---|
| Java serialization | `ac ed 00 05` | `rO0AB` | — |
| Java, gzip-wrapped | `1f 8b 08` | `H4sIA` | decompress → re-check for `ac ed` |
| .NET BinaryFormatter | `00 01 00 00 00 ff ff ff ff` | `AAEAAAD/////` | — |
| .NET LosFormatter / ViewState | — | `/wEP`, `/wEW`, `/wEd` | `__VIEWSTATE` field |
| .NET SoapFormatter | — | — | XML `<SOAP-ENV:` with `clr-ns` namespaces |
| PHP serialize() | — | `Tz`/`YT`/`czo` (b64 of O:/a:/s:) | `O:4:"User":2:{…}` `a:3:{…}` `s:5:"admin";` `i:42;` `b:1;` |
| Python pickle p2–p5 | `80 02` … `80 05` | `gAJ` `gAN` `gAR` `gASV` | — |
| Python pickle p0 | printable, ends `.` | `KGRw` (`(dp`) | `(dp0\nS'key'\n...` |
| Ruby Marshal 4.8 | `04 08` | `BAh` | — |
| Node node-serialize | — | — | JSON containing `"$$ND_FUNC$$"` |
| Java JSF ViewState | — | `rO0` or `H4sIA` in `javax.faces.ViewState` | — |

Encodings stack: URL-encoding over base64 over gzip over the raw stream.
Decode outermost-in: `urldecode → base64 → gunzip → magic check`, up to 3
layers. Also try **URL-safe base64** (`-`/`_`) and hex.

## 2. Where blobs live

- **Cookies**: `session`, `remember_me`, `auth`, `user`, framework defaults —
  Java `JSESSIONID` is usually a reference id (not a blob), but custom
  `*-token`/`*-data` cookies often are. Flask `session=` cookies are
  base64(json or **pickle**).zip with an HMAC suffix (`.`-separated).
- **Hidden fields**: `__VIEWSTATE` (+`__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`),
  `javax.faces.ViewState`, custom `state`/`data` fields.
- **Params/headers**: `?data=`, `?state=`, `X-Session`, `X-Api-Token`.
- **Uploads**: anything later touched by `phar://` (PHP), `ObjectInputStream`
  (Java import features), pickle model/config loads (ML apps: `.pkl`, `.pt`,
  joblib caches).
- **Queues/RPC**: JMS/ActiveMQ/RabbitMQ object messages, Java RMI (port 1099),
  JMX (1099/9010), T3 (WebLogic 7001), AMF (`application/x-amf`).
- **Error leaks**: `java.io.StreamCorruptedException`, `ClassNotFoundException`,
  `BinaryFormatter`-typed stack traces, `unserialize(): Error at offset`,
  `pickle.UnpicklingError` — each names the deserializer even without a blob.

## 3. Parse-oracle test (blind confirmation without gadgets)

1. Replay the original blob → baseline response.
2. Flip a byte mid-stream (keep magic intact) → resend.
3. 500 / deserialization exception / different error page ⇒ the server parses
   the blob. Exception text frequently names the library and version — feed
   that straight into gadget selection (`java.md` dependency map).
4. For MAC'd containers (ViewState with MAC, signed Flask/Django sessions): a
   generic "invalid signature" on ANY change means you need the key first
   (machineKey leak, `SECRET_KEY` from LFI/SSTI/config, default keys lists).

## 4. detect_serialized.py pipeline

```
python3 scripts/detect_serialized.py scan -i req1.txt -i burp-items.xml \
    --work-units deser-units.json --json
cat sitemap-urls.txt | python3 scripts/detect_serialized.py scan --work-units u.json
```

Per input file it: extracts request URL/Host context, pulls candidate tokens
(cookie values, param values, header values, standalone base64 runs), runs the
decode pipeline, classifies against the marker table, dedupes, and emits:

- stdout: human/`--json` report (`location`, `format`, `encoding chain`,
  `suggested_tool`, `first_probe`),
- `--work-units`: the rupu fan-out array (shape in `rupu.md`) — one unit per
  distinct (URL, location, format) sink.

Hand the array to the `work-units` skill; mark each discovered sink via the
`coverage-assets` skill (`web:route`, depth `crawled`).
