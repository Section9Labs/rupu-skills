# Java (+ Kotlin/Scala/Groovy): sources, sinks, sanitizers, ripgrep patterns

Scan globs: `-g '*.java' -g '*.kt' -g '*.scala' -g '*.groovy'` (abbreviated
`-g '*.java'` below).

## Sources

| Context | Expressions |
|---|---|
| Servlet | `request.getParameter/getParameterMap/getQueryString`, `getHeader(s)`, `getCookies`, `getInputStream/getReader`, `getRequestURI/getPathInfo`, `Part.getSubmittedFileName()` |
| Spring MVC | `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`-bound beans (every setter!), `MultipartFile.getOriginalFilename()` |
| JAX-RS | `@QueryParam`, `@PathParam`, `@HeaderParam`, `@FormParam`, entity bodies |
| Generic | `args[]` in exposed mains, JMS/Kafka message bodies, RMI args, DB reads of user data, deserialized object fields |

## Sinks by class

### SQL injection
```
rg -n 'createStatement\(' -g '*.java'
rg -n '(executeQuery|executeUpdate|execute|addBatch)\([^)]*\+' -g '*.java'
rg -n '(prepareStatement|createQuery|createNativeQuery|createSQLQuery)\([^)]*\+' -g '*.java'
rg -n '@Query\([^)]*\+|@Query\(.*\$\{' -g '*.java'
rg -n 'jdbcTemplate\.(query|queryForObject|update|execute)\([^)]*\+' -g '*.java'
```
A `PreparedStatement` built from a **concatenated** string is still SQLi —
the `?` binding is the sanitizer, not the class. JPQL/HQL concat is equally
injectable. MyBatis: `${param}` interpolates (sink), `#{param}` binds (safe).
```
rg -n '\$\{[^}]+\}' -g '*Mapper.xml' -g '*.xml'
```

### Command injection
```
rg -n 'Runtime\.getRuntime\(\)\.exec\(' -g '*.java'
rg -n 'new ProcessBuilder\(' -g '*.java'
rg -n 'Process(Builder)?[^;]*(sh|bash|cmd(\.exe)?|/c|-c)' -g '*.java'
```
`exec(String)` tokenizes on whitespace (no shell metachars) but
`exec(new String[]{"sh","-c", cmd})` and `ProcessBuilder("bash","-c", cmd)`
are full shell injection. Sanitizer: fixed argv array, user data as a single
non-shell argument.

### Code injection (EL/SpEL/OGNL/Groovy) & SSTI
```
rg -n 'ScriptEngine(Manager)?|getEngineByName' -g '*.java'
rg -n 'SpelExpressionParser|parseExpression\(' -g '*.java'
rg -n 'GroovyShell|GroovyClassLoader|Eval\.(me|x|xy)\(' -g '*.java'
rg -n 'Ognl\.|OgnlContext' -g '*.java'
rg -n 'templateEngine\.process\(|Velocity\.evaluate\(|new Template\(|createTemplate\(' -g '*.java'
```
SpEL confirm payload: `T(java.lang.Runtime).getRuntime().exec('id')`.
Thymeleaf: user data in template *names* or preprocessed `__${...}__`
expressions → SSTI; fragment selectors from request are the classic case.

### Deserialization
```
rg -n 'new ObjectInputStream\(|\.readObject\(|\.readUnshared\(' -g '*.java'
rg -n 'XMLDecoder|XStream|new Yaml\(\)|SnakeYaml' -g '*.java'
rg -n 'enableDefaultTyping\(|activateDefaultTyping\(|@JsonTypeInfo' -g '*.java'
rg -n 'InvokerTransformer|ysoserial' -g '*.java'
```
`ObjectInputStream.readObject` on attacker bytes = gadget-chain RCE
(commons-collections, etc. — check the classpath with the `sca` tooling).
Sanitizers: `ObjectInputFilter` allowlist (`serialFilter`), XStream allowlist
(`allowTypes`), SnakeYAML `new Yaml(new SafeConstructor())`, Jackson default
typing OFF or `PolymorphicTypeValidator` allowlist.

### SSRF
```
rg -n 'new URL\([^)]*\)\.open(Connection|Stream)\(' -g '*.java'
rg -n 'restTemplate\.(getForObject|getForEntity|postForObject|exchange)\(' -g '*.java'
rg -n 'HttpClient\.newHttpClient|HttpRequest\.newBuilder|new HttpGet\(|OkHttpClient' -g '*.java'
rg -n 'ImageIO\.read\(\s*new URL|new URL\([^)]*request' -g '*.java'
```
`new URL(user).openStream()` also follows `file:` and `jar:` → arbitrary read.

### Path traversal / zip-slip
```
rg -n 'new (File|FileInputStream|FileOutputStream|FileReader|FileWriter)\([^)]*\+' -g '*.java'
rg -n 'Paths\.get\([^)]*\+|Files\.(readAllBytes|newInputStream|copy|write)\(' -g '*.java'
rg -n 'new ZipInputStream\(|ZipEntry|getNextEntry\(|zipEntry\.getName\(\)' -g '*.java'
rg -n 'MultipartFile.*getOriginalFilename|transferTo\(' -g '*.java'
```
Zip-slip: `new File(destDir, entry.getName())` without a
`getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator)`
check. Same for `transferTo(new File(dir, originalFilename))`.

### XXE
```
rg -n '(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)\.newInstance\(' -g '*.java'
rg -n 'new SAXReader\(|new XmlMapper\(|Unmarshaller' -g '*.java'
rg -n 'disallow-doctype-decl|external-general-entities|XMLConstants\.FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES' -g '*.java'
```
Factory present + no hardening feature within the same class = candidate.
Required sanitizer (DocumentBuilderFactory):
`dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
(plus `setXIncludeAware(false)`, `setExpandEntityReferences(false)`).
StAX: `xif.setProperty(XMLInputFactory.SUPPORT_DTD, false)`.

### Authz / IDOR
```
rg -n '@(Get|Post|Put|Patch|Delete|Request)Mapping' -g '*.java'      # route inventory
rg -n '(findById|getById|getOne|getReferenceById)\(' -g '*.java'
rg -n '@PreAuthorize|@Secured|@RolesAllowed|hasRole|hasAuthority|SecurityContextHolder' -g '*.java'
```
For each controller method taking `@PathVariable Long id` into
`repo.findById(id)`: is there a tenant/owner predicate or `@PreAuthorize`
with an ownership SpEL? Check `WebSecurityConfig`/`SecurityFilterChain` for
`permitAll()` on sensitive paths and for method-security being enabled at all
(`@EnableMethodSecurity`) — annotations without it are inert.

### Crypto misuse
```
rg -n 'Cipher\.getInstance\(\s*"(DES|DESede|AES"|AES/ECB|RSA/ECB/NoPadding|Blowfish)' -g '*.java'
rg -n 'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"' -g '*.java'
rg -n 'new Random\(|Math\.random\(' -g '*.java'
rg -n 'new IvParameterSpec\(\s*("|new byte)|SecretKeySpec\(\s*"' -g '*.java'   # static IV/key
rg -n 'checkServerTrusted|X509TrustManager|setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER' -g '*.java'
```
`Cipher.getInstance("AES")` defaults to ECB. Tokens want `SecureRandom`;
passwords want bcrypt/argon2 (Spring `BCryptPasswordEncoder`). Trust-all
`X509TrustManager` = empty `checkServerTrusted` body.

### Secrets
```
rg -n -i '(api[_-]?key|secret|passw(or)?d|token)\s*=\s*"[A-Za-z0-9+/=_\-]{8,}"' -g '*.java' -g '*.properties' -g '*.yml' -g '*.yaml' -g '*.xml'
```
Load `gitleaks` / `trufflehog` skills for breadth.

## Common Java sanitizers

| Sanitizer | Neutralizes | Caveats |
|---|---|---|
| `PreparedStatement` with `?` binds | SQLi | only bound values, not concat parts |
| `Integer.parseInt` / `Long.valueOf` / enum `valueOf` | injections | exceptions must not fall back to raw |
| fixed argv `ProcessBuilder` | cmdi | no `sh -c`; `--` before user arg |
| `getCanonicalPath` + prefix check | traversal/zip-slip | append `File.separator` |
| `disallow-doctype-decl` feature | XXE | must be on the instance actually used |
| `ObjectInputFilter` allowlist | deser | allowlist, not blocklist |
| `ESAPI`/OWASP encoders | XSS | per-context encoder |
