---
name: find-sec-bugs
description: Run SpotBugs with the Find Security Bugs plugin to find security vulnerabilities (injection, XXE, deserialization, SSRF, XSS, weak crypto, hardcoded secrets) in compiled Java/Kotlin/Scala/Groovy bytecode; use whenever a JVM project can be built to .class/.jar/.war and you need fast, pattern-based bytecode security review before deeper dataflow analysis.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Find Security Bugs (SpotBugs + findsecbugs plugin)

Bytecode-level security scanner for the JVM. SpotBugs analyzes compiled
classes; the Find Security Bugs plugin adds ~140 security bug patterns
(injection sinks, XXE, deserialization, SSRF, crypto misuse, Spring/Struts
specifics) with taint analysis inside method bodies. It covers Java, Kotlin,
Scala, and Groovy equally because it never looks at source — only bytecode.

## 0. Prerequisite: build the project

findsecbugs analyzes **compiled bytecode**, never source. Build first and
locate the artifacts:

```bash
# Maven
mvn -DskipTests clean package          # -> target/classes/, target/*.jar|war
# Gradle
./gradlew assemble -x test             # -> build/classes/, build/libs/*.jar
# Plain javac
javac -d out/ $(find src -name '*.java')
# Kotlin / Scala / Groovy: kotlinc -d out.jar ..., sbt package, gradle build
```

Also collect the **dependency jars** — they are required as auxclasspath
(section 2):

```bash
mvn dependency:copy-dependencies -DoutputDirectory=target/deps
# Gradle: copy configurations.runtimeClasspath into build/deps (see references/build-and-run.md)
```

## 1. Install

Three equivalent routes (details in `references/build-and-run.md`):

1. **SpotBugs CLI + plugin jar** (preferred for ad-hoc review):
   - SpotBugs release zip → `spotbugs-<ver>/bin/spotbugs`
   - `findsecbugs-plugin-<ver>.jar` from Maven Central
     (`com.h3xstream.findsecbugs:findsecbugs-plugin`).
2. **Standalone wrapper**: the findsecbugs release zip ships `findsecbugs.sh`
   / `findsecbugs.bat`, a SpotBugs launcher with the plugin preloaded. Same
   flags as `spotbugs`.
3. **Build integration**: `spotbugs-maven-plugin` or the Gradle
   `com.github.spotbugs` plugin with findsecbugs declared as a plugin
   dependency — good for CI, less flexible for triage.

## 2. Run (CLI)

Canonical invocation — max effort, report everything down to low confidence,
SARIF out:

```bash
spotbugs -textui \
  -pluginList /opt/findsecbugs/findsecbugs-plugin.jar \
  -effort:max -low \
  -auxclasspath "$(find target/deps -name '*.jar' | paste -sd:)" \
  -sourcepath src/main/java \
  -sarif -output fsb.sarif \
  target/classes
```

Also produce the native XML — it carries fields SARIF drops (rank, numeric
priority, CWE id, full class/method identity):

```bash
spotbugs -textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar \
  -effort:max -low \
  -auxclasspath "$(find target/deps -name '*.jar' | paste -sd:)" \
  -xml:withMessages -output fsb.xml target/classes
```

Human-readable variants: `-html -output fsb.html` or plain text with
`-sortByClass`. Targets can be a classes directory, one or more `.jar` /
`.war` / `.ear` files, or any mix.

**auxclasspath is critical for accuracy.** Without the application's
dependency jars SpotBugs cannot resolve supertypes and method signatures:
taint tracking through library calls breaks, detectors silently skip
classes, and you get both false negatives and `missing class` noise. Always
pass every runtime dependency jar (colon-separated, or a directory via
`-auxclasspathFromFile deps.txt`). Watch stderr for
`The following classes needed for analysis were missing:` — if security-
relevant classes (servlet API, JDBC driver, crypto provider, framework jars)
appear there, fix the auxclasspath and re-run.

Or let the helper do all of the above and emit work units in one step:

```bash
python3 scripts/run_findsecbugs.py \
  --plugin /opt/findsecbugs/findsecbugs-plugin.jar \
  --aux target/deps --source src/main/java \
  --out-dir fsb-out target/classes
# -> fsb-out/fsb.sarif, fsb-out/fsb.xml, fsb-out/workunits.json
```

## 3. Run (Maven / Gradle)

```bash
# Maven, no pom changes needed:
mvn com.github.spotbugs:spotbugs-maven-plugin:check \
  -Dspotbugs.plugins=com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0 \
  -Dspotbugs.effort=Max -Dspotbugs.threshold=Low \
  -Dspotbugs.sarifOutput=true -Dspotbugs.failOnError=false
# results: target/spotbugsXml.xml, target/spotbugsSarif.json
```

Gradle: apply `com.github.spotbugs`, add
`spotbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0'`,
set `effort = 'max'`, `reportLevel = 'low'`, enable the XML/SARIF reports,
then `./gradlew spotbugsMain`. Full recipes with `onlyAnalyze`,
include/exclude filters and multi-module handling:
`references/build-and-run.md`.

## 4. Bug-pattern catalog (what you are looking for)

Full catalog with CWE mapping and triage guidance per pattern:
`references/bug-patterns.md`. The high-signal classes:

| Class | Key pattern types | CWE |
|---|---|---|
| SQL/HQL/JPA injection | `SQL_INJECTION_JDBC`, `SQL_INJECTION_HIBERNATE`, `SQL_INJECTION_JPA`, `SQL_INJECTION_SPRING_JDBC`, `SQL_INJECTION_JDO`, `SCALA_SQL_INJECTION_SLICK` | 89 |
| Command injection | `COMMAND_INJECTION`, `SCALA_COMMAND_INJECTION` | 78 |
| Path traversal | `PATH_TRAVERSAL_IN`, `PATH_TRAVERSAL_OUT` | 22 |
| LDAP / XPath injection | `LDAP_INJECTION`, `XPATH_INJECTION` | 90 / 643 |
| XXE | `XXE_SAXPARSER`, `XXE_DOCUMENT`, `XXE_XMLSTREAMREADER`, `XXE_XMLREADER`, `XXE_XSLT_TRANSFORM_FACTORY`, `XXE_DTD_TRANSFORM_FACTORY` | 611 |
| Deserialization | `OBJECT_DESERIALIZATION`, `JACKSON_UNSAFE_DESERIALIZATION`, `DESERIALIZATION_GADGET`, `UNSAFE_XSTREAM`, `SNAKE_YAML_DESERIALIZATION` | 502 |
| SSRF | `URLCONNECTION_SSRF_FD`, `SPRING_UNVALIDATED_REDIRECT` (related: 601) | 918 |
| XSS | `XSS_SERVLET`, `XSS_JSP_PRINT`, `XSS_REQUEST_WRAPPER` | 79 |
| Crypto | `CIPHER_INTEGRITY`, `ECB_MODE`, `PADDING_ORACLE`, `STATIC_IV`, `DES_USAGE`, `TDES_USAGE`, `WEAK_MESSAGE_DIGEST_MD5/SHA1`, `RSA_NO_PADDING`, `BLOWFISH_KEY_SIZE` | 327/326/329 |
| RNG | `PREDICTABLE_RANDOM`, `PREDICTABLE_RANDOM_SCALA` | 330 |
| Secrets | `HARD_CODE_PASSWORD`, `HARD_CODE_KEY` | 259/321 |
| Trust boundary | `TRUST_BOUNDARY_VIOLATION` | 501 |
| Cookies | `INSECURE_COOKIE`, `HTTPONLY_COOKIE`, `COOKIE_USAGE` | 614/1004 |
| TLS | `WEAK_HOSTNAME_VERIFIER`, `WEAK_TRUST_MANAGER`, `SSL_CONTEXT`, `DEFAULT_HTTP_CLIENT` | 295 |
| Spring / Struts / templates | `SPEL_INJECTION`, `SPRING_CSRF_PROTECTION_DISABLED`, `SPRING_FILE_DISCLOSURE`, `STRUTS_FILE_DISCLOSURE`, `OGNL_INJECTION`, `TEMPLATE_INJECTION_*`, `EL_INJECTION`, `SCRIPT_ENGINE_INJECTION` | varies |

Also valuable: `JWT_NONE_ALGORITHM`, `URL_REWRITING`, `HTTP_RESPONSE_SPLITTING`,
`CRLF_INJECTION_LOGS`, `EXTERNAL_CONFIG_CONTROL`, `UNVALIDATED_REDIRECT`,
Android patterns (`ANDROID_*`).

**Reading a result.** Each `BugInstance` gives:
- **type** — the pattern id above; drives severity and the verification playbook.
- **priority** — detector confidence: 1=High, 2=Medium, 3=Low. Low often means
  the taint source was unresolved (frequently an auxclasspath problem, not FP).
- **rank** — 1–20 severity scale: 1–4 scariest, 5–9 scary, 10–14 troubling,
  15–20 of concern. Triage order = rank asc, then priority asc.
- **CWE** — `cweid` attribute on the XML BugInstance.
- **location** — Class + Method + `SourceLine` start (needs `-sourcepath` for
  the path to resolve to real source files; otherwise you get `sourcepath`
  relative to the package).

Verify by opening the class/method at the given line, tracing where the
tainted argument comes from (HTTP parameter? config? constant?), and
confirming the sink is reachable with attacker-controlled input.

## 5. Tuning

- **Effort**: `-effort:max` (deepest interprocedural analysis within a class,
  slowest) / default / `-effort:min`. Always `max` for security review.
- **Confidence threshold**: `-low` report everything (use this), `-medium`
  default, `-high` only high-confidence. For security triage run `-low` and
  sort by rank — missing a priority-3 `COMMAND_INJECTION` is worse than
  reading a few FPs.
- **Filter files**: `-include security-only.xml` to restrict to the SECURITY
  category, `-exclude suppress.xml` to drop known-FP classes/patterns.
  Example include filter:

```xml
<FindBugsFilter>
  <Match><Bug category="SECURITY"/></Match>
</FindBugsFilter>
```

  Match on `<Bug pattern="..."/>`, `<Class name="~regex"/>`, `<Method>`,
  `<Rank value="14"/>` (rank <= 14) etc. More in
  `references/build-and-run.md`.
- `-onlyAnalyze com.example.app.*` to focus on first-party packages;
  `-maxRank 14` to cut noise; `-nested:true` to descend into jars inside
  wars/ears (on by default).
- Memory: `spotbugs -textui -maxHeap 4096 ...` or `SPOTBUGS_OPTS=-Xmx4g`.

## 6. Normalize, split, report (rupu handoff)

1. Convert results to work units:

```bash
python3 scripts/fsb_to_workunits.py fsb.sarif fsb.xml -o workunits.json \
  --min-rank 20 --repo-root .
```

   `workunits.json` is a clean top-level JSON array of
   `{id, title, targets:["path:line"], hints:{pattern, rank, priority, cwe, severity, message}}`
   — directly consumable by a rupu workflow `for_each:` or a lead agent
   `dispatch` fan-out. XML and SARIF entries for the same bug are
   deduplicated; XML enriches SARIF with rank/priority/CWE.
2. Mark coverage with `assets.mark`: the repository, every scanned
   module/jar, and the dependency jars that fed the auxclasspath. Concrete
   calls in `references/rupu.md`.
3. Load the `work-units` skill to split the normalized findings into
   per-agent work units (do not re-invent the splitter).
4. Verify each unit against source, then load the `finding-report` skill and
   file every verified issue via `findings.report` (do not re-invent the
   report format).
5. Route `fsb.sarif` to the `sarif-triage` skill for cross-tool merge and
   dedup with other scanners' SARIF.

## 7. Limits → next tools

findsecbugs taint analysis is mostly intra-procedural per class: it misses
taint flows across many methods/classes, through DI/framework indirection,
and anything decided at runtime. It also can't see annotations-driven routing
semantics. When a pattern class matters but findsecbugs is quiet or
low-confidence:

- Run the **`semgrep`** skill with the Java packs (`p/java`, `p/owasp-top-ten`,
  framework rules) for source-level, pattern+taint coverage including code
  that doesn't compile.
- Build a **`codeql`** Java database for real interprocedural dataflow —
  CodeQL must trace the build: `codeql database create db --language=java
  --command='mvn -DskipTests clean package'` — then run the
  `java-security-extended` suite and merge its SARIF in `sarif-triage`.
