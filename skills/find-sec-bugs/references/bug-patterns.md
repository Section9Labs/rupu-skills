# Find Security Bugs — pattern catalog with CWE and triage notes

Pattern ids are the `type` attribute of a `BugInstance` (XML) / `ruleId`
(SARIF). Priority 1=High, 2=Medium, 3=Low confidence. Rank 1–20 (lower =
worse). Full upstream list: https://find-sec-bugs.github.io/bugs.htm

## Injection — SQL / ORM

| Pattern | Sink | CWE |
|---|---|---|
| `SQL_INJECTION_JDBC` | `Statement.execute*`, `Connection.prepareStatement(concat)` | 89 |
| `SQL_INJECTION_HIBERNATE` | `Session.createQuery/createSQLQuery` with concat (HQL injection) | 89/564 |
| `SQL_INJECTION_JPA` | `EntityManager.createQuery/createNativeQuery` | 89 |
| `SQL_INJECTION_SPRING_JDBC` | `JdbcTemplate.query/update/execute` | 89 |
| `SQL_INJECTION_JDO` | JDO `newQuery` | 89 |
| `SQL_INJECTION_TURBINE` | Turbine `BasePeer` | 89 |
| `SQL_INJECTION_VERTX` | Vert.x SQL client | 89 |
| `SQL_INJECTION_ANDROID` | Android `SQLiteDatabase.rawQuery` etc. | 89 |
| `SCALA_SQL_INJECTION_SLICK` / `_ANORM` | Slick/Anorm string interpolation | 89 |
| `SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE` (core SpotBugs) | any non-constant SQL | 89 |

Triage: find where the concatenated value enters the method. Parameterized
query / bound parameter → FP. Value from request param, header, JSON body,
or any upstream user data → confirm injectable; craft `' OR '1'='1` style
proof against the actual query shape.

Vulnerable example:
```java
String q = "SELECT * FROM users WHERE name = '" + req.getParameter("u") + "'";
stmt.executeQuery(q);   // SQL_INJECTION_JDBC, rank ~4
```

## Injection — OS command

- `COMMAND_INJECTION` (CWE-78): tainted value reaches
  `Runtime.exec`, `ProcessBuilder`, `new ProcessBuilder(List)`.
  Note: `exec(String)` tokenizes on whitespace — injection of extra args is
  possible even without a shell; `exec(new String[]{"sh","-c", tainted})` is
  full shell injection.
- `SCALA_COMMAND_INJECTION`: `scala.sys.process` sinks.

## Path traversal / file disclosure

- `PATH_TRAVERSAL_IN` (CWE-22): tainted path in `new File`,
  `Paths.get`, `FileInputStream`, `FileReader` — read primitive.
- `PATH_TRAVERSAL_OUT` (CWE-22): tainted path in `FileOutputStream`,
  `FileWriter` — write primitive (often escalates to RCE via webroot/
  classpath writes).
- `SPRING_FILE_DISCLOSURE`, `STRUTS_FILE_DISCLOSURE` (CWE-552): tainted
  view name / `ModelAndView` → arbitrary file read via view resolver.
- `FILE_UPLOAD_FILENAME` (CWE-22): trusting
  `Part.getSubmittedFileName()` / multipart filename.

Triage: check for canonicalization + prefix check (`getCanonicalPath()`
compared against base dir). A `..` filter alone is usually bypassable
(`....//`, URL-encoding handled upstream, absolute paths, NUL on old JVMs).

## LDAP / XPath / other query injection

- `LDAP_INJECTION` (CWE-90): tainted filter in `DirContext.search`.
- `XPATH_INJECTION` (CWE-643): `XPath.evaluate` / `compile` with concat.
- `SCRIPT_ENGINE_INJECTION` (CWE-94): `ScriptEngine.eval(tainted)` — direct
  code exec.
- `SPEL_INJECTION` (CWE-94): `SpelExpressionParser.parseExpression(tainted)`
  — RCE via `T(java.lang.Runtime).getRuntime().exec(...)`.
- `EL_INJECTION` (CWE-94): `ExpressionFactory.createValueExpression`.
- `OGNL_INJECTION` (CWE-94): Struts `OgnlUtil`/`OgnlContext` — Struts RCE
  class.
- `TEMPLATE_INJECTION_VELOCITY` / `_FREEMARKER` / `_PEBBLE` (CWE-1336):
  tainted template string → SSTI → usually RCE.
- `AWS_QUERY_INJECTION` (CWE-943): SimpleDB select.
- `MONGO_INJECTION` style via `SQL_INJECTION_*` variants in newer versions.

## XML — XXE and friends

| Pattern | Parser | CWE |
|---|---|---|
| `XXE_SAXPARSER` | `SAXParser.parse` | 611 |
| `XXE_XMLREADER` | `XMLReader.parse` | 611 |
| `XXE_DOCUMENT` | `DocumentBuilder.parse` | 611 |
| `XXE_XMLSTREAMREADER` | `XMLInputFactory` / StAX | 611 |
| `XXE_XSLT_TRANSFORM_FACTORY` / `XXE_DTD_TRANSFORM_FACTORY` | `TransformerFactory` | 611 |
| `XML_DECODER` | `java.beans.XMLDecoder.readObject` | 20/502 — this is RCE, not just XXE |

Safe configuration that makes these FPs:
`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
or `FEATURE_SECURE_PROCESSING` + external-entity features disabled, or
`XMLConstants.ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` set to "".
findsecbugs checks nearby `setFeature` calls but misses settings applied in
another method/factory helper — verify before filing.

## Deserialization

- `OBJECT_DESERIALIZATION` (CWE-502): `ObjectInputStream.readObject` on
  untrusted stream. Confirm the stream source (socket/HTTP/file upload) and
  check for `ObjectInputFilter` / look-ahead whitelisting. Gadget chains:
  ysoserial-class libraries on the classpath (commons-collections ≤3.2.1,
  etc.) make this directly exploitable.
- `JACKSON_UNSAFE_DESERIALIZATION` (CWE-502): `enableDefaultTyping()` /
  `@JsonTypeInfo(use=Id.CLASS)` polymorphic typing.
- `UNSAFE_XSTREAM` (CWE-502): XStream without a type whitelist.
- `SNAKE_YAML_DESERIALIZATION` (CWE-502): `new Yaml()` without
  `SafeConstructor` → `!!javax.script.ScriptEngineManager` style RCE.
- `DESERIALIZATION_GADGET` (CWE-502): class implements readObject/readResolve
  patterns usable as a gadget.
- `OBJECT_DESERIALIZATION` cousins: `KRYO`/`HESSIAN`/`CASTOR` patterns in
  recent releases.

## SSRF / redirects / request forgery

- `URLCONNECTION_SSRF_FD` (CWE-918): tainted URL into
  `URL.openConnection/openStream`, `HttpClient`. Verify scheme/host control;
  internal metadata endpoints (169.254.169.254) are the classic impact.
- `UNVALIDATED_REDIRECT` (CWE-601): `sendRedirect(tainted)`.
- `SPRING_UNVALIDATED_REDIRECT` (CWE-601): `redirect:` + tainted.
- `HTTP_PARAMETER_POLLUTION` (CWE-235), `URL_REWRITING` (CWE-598:
  `encodeURL` putting session id in URL).
- `HTTP_RESPONSE_SPLITTING` (CWE-113), `CRLF_INJECTION_LOGS` (CWE-117),
  `SMTP_HEADER_INJECTION` (CWE-93).

## XSS

- `XSS_SERVLET` (CWE-79): tainted data to `ServletResponse` writer/output.
- `XSS_JSP_PRINT` (CWE-79): `<%= tainted %>` in compiled JSP — only fires if
  you feed the **precompiled JSP classes** to SpotBugs (compile JSPs with
  jasper/`jspc` and add the output to the scan target).
- `XSS_REQUEST_WRAPPER` (CWE-79): flawed sanitizing `HttpServletRequestWrapper`.

Triage: check for output encoding (OWASP Java Encoder, `StringEscapeUtils`,
template auto-escaping). Content-Type matters: JSON endpoints with
`text/html` default are still XSS.

## Cryptography

| Pattern | Problem | CWE |
|---|---|---|
| `CIPHER_INTEGRITY` | cipher without MAC/AEAD (e.g. `AES/CBC/PKCS5Padding` alone) | 353 |
| `ECB_MODE` | `AES/ECB/...` | 327 |
| `PADDING_ORACLE` | CBC + PKCS5 where ciphertext is attacker-suppliable | 346/696 |
| `STATIC_IV` | constant/reused IV | 329 |
| `DES_USAGE` / `TDES_USAGE` | DES / 3DES | 326 |
| `RSA_NO_PADDING` | `RSA/ECB/NoPadding` | 780 |
| `RSA_KEY_SIZE` / `BLOWFISH_KEY_SIZE` | short keys | 326 |
| `WEAK_MESSAGE_DIGEST_MD5` / `WEAK_MESSAGE_DIGEST_SHA1` | MD5/SHA-1 | 327/328 |
| `HAZELCAST_SYMMETRIC_ENCRYPTION` | weak cluster crypto | 327 |
| `NULL_CIPHER` | `javax.crypto.NullCipher` | 327 |
| `UNENCRYPTED_SOCKET` / `UNENCRYPTED_SERVER_SOCKET` | plaintext sockets | 319 |
| `INSECURE_SMTP_SSL` | SMTP SSL without cert check | 297 |

Weak-hash triage: MD5/SHA-1 for passwords or signatures = real finding; for
non-security cache keys/checksums = downgrade.

## Randomness & secrets

- `PREDICTABLE_RANDOM` / `PREDICTABLE_RANDOM_SCALA` (CWE-330):
  `java.util.Random` / `Math.random` / `ThreadLocalRandom` for
  tokens/session ids/password reset codes. Verify the usage is security-
  relevant before filing.
- `HARD_CODE_PASSWORD` (CWE-259), `HARD_CODE_KEY` (CWE-321): literal
  passwords/keys passed to `KeyStore.load`, `PBEKeySpec`,
  `SecretKeySpec`, JDBC `getConnection`, LDAP env. Extract the literal and
  check whether it is live.

## Web/session hardening

- `INSECURE_COOKIE` (CWE-614): `Cookie` without `setSecure(true)`.
- `HTTPONLY_COOKIE` (CWE-1004): without `setHttpOnly(true)`.
- `COOKIE_USAGE` (CWE-315): sensitive data in cookie value.
- `TRUST_BOUNDARY_VIOLATION` (CWE-501): request data put into `HttpSession`
  without validation.
- `SERVLET_*` info patterns (`SERVLET_PARAMETER`, `SERVLET_HEADER`,
  `SERVLET_HEADER_REFERER`, `SERVLET_QUERY_STRING`, ...): taint-source
  markers, rank ~15+. Not findings themselves — use them to map input
  surface for manual review and semgrep/codeql seeding.

## TLS validation

- `WEAK_HOSTNAME_VERIFIER` (CWE-295): `HostnameVerifier` returning true.
- `WEAK_TRUST_MANAGER` (CWE-295): `X509TrustManager` with empty
  `checkServerTrusted`.
- `SSL_CONTEXT` (CWE-295): `SSLContext.getInstance("SSL")` / weak protocol.
- `DEFAULT_HTTP_CLIENT` (CWE-295): legacy `DefaultHttpClient` without TLS 1.2.
- `ANDROID_SSL_ERROR` / `ANDROID_WEB_VIEW_*`: Android WebView TLS/JS bridges.

These are near-zero-FP: an empty trust manager is a finding, full stop.

## Framework specifics

- Spring: `SPRING_CSRF_PROTECTION_DISABLED` (CWE-352),
  `SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING` (352),
  `SPRING_ENDPOINT` (info: `@RequestMapping` surface),
  `SPRING_FILE_DISCLOSURE`, `SPRING_UNVALIDATED_REDIRECT`,
  `SPEL_INJECTION`.
- Struts: `STRUTS_FORM_VALIDATION` / `STRUTS1_ENDPOINT` /
  `STRUTS2_ENDPOINT` (info), `STRUTS_FILE_DISCLOSURE`, `OGNL_INJECTION`.
- JAX-RS/JAX-WS: `JAXRS_ENDPOINT`, `JAXWS_ENDPOINT` (surface mapping).
- Tapestry/Wicket: `TAPESTRY_ENDPOINT`, `WICKET_ENDPOINT`.
- JWT: `JWT_NONE_ALGORITHM` (CWE-347) — jjwt/auth0 parsing allowing `none`.
- `PERMISSIVE_CORS` (CWE-942): `Access-Control-Allow-Origin: *` on
  credentialed endpoints.
- `LDAP_ENTRY_POISONING` (CWE-90): JNDI `SearchControls` with
  returningObjFlag=true → remote classloading RCE (log4shell-adjacent).
- `EXTERNAL_CONFIG_CONTROL` (CWE-15): tainted value into `setCatalog` etc.
- `DANGEROUS_PERMISSION_COMBINATION`, `OVERLY_PERMISSIVE_FILE_PERMISSION`
  (CWE-732).
- Android: `ANDROID_EXTERNAL_FILE_ACCESS`, `ANDROID_BROADCAST`,
  `ANDROID_WORLD_WRITABLE`, `ANDROID_GEOLOCATION`,
  `ANDROID_WEB_VIEW_JAVASCRIPT(_INTERFACE)`.

## Rank bands (triage order)

| Rank | Band | Action |
|---|---|---|
| 1–4 | Scariest | verify first; usually injection/deser/RCE class |
| 5–9 | Scary | verify |
| 10–14 | Troubling | verify when touching user input |
| 15–20 | Of concern | surface-mapping & hardening; batch-review |
