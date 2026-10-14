# Build & run recipes — SpotBugs + findsecbugs

## Installing

```bash
# SpotBugs CLI
curl -sSL -o spotbugs.tgz https://github.com/spotbugs/spotbugs/releases/download/4.8.6/spotbugs-4.8.6.tgz
tar xzf spotbugs.tgz -C /opt && ln -s /opt/spotbugs-4.8.6/bin/spotbugs /usr/local/bin/spotbugs

# findsecbugs plugin jar (Maven Central)
curl -sSL -o /opt/findsecbugs-plugin.jar \
  https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.13.0/findsecbugs-plugin-1.13.0.jar

# OR the standalone CLI zip (ships findsecbugs.sh with the plugin preloaded)
curl -sSL -o fsb-cli.zip \
  https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.13.0/findsecbugs-cli-1.13.0.zip
unzip fsb-cli.zip -d /opt/findsecbugs-cli && chmod +x /opt/findsecbugs-cli/findsecbugs.sh
```

`findsecbugs.sh` accepts the same arguments as `spotbugs -textui` (it is a
wrapper that sets `-pluginList` for you).

## CLI flag reference

```
spotbugs -textui [options] <classes-dir | jar | war | ear> ...
  -pluginList <jar[:jar...]>     load findsecbugs (and other) plugins
  -effort:min|default|max        analysis depth; use max
  -low | -medium | -high         min confidence to report; use -low
  -maxRank <1..20>               drop results ranked worse than N
  -sarif [-output f.sarif]       SARIF 2.1.0 output
  -xml:withMessages [-output f]  native XML with human messages (keep this!)
  -html [-output f.html]         HTML report (also -html:fancy-hist.xsl)
  -sortByClass                   text output grouped by class
  -auxclasspath <cp>             dependency jars/dirs (colon-separated)
  -auxclasspathFromInput         read auxclasspath entries from stdin
  -auxclasspathFromFile <file>   one entry per line
  -sourcepath <dirs>             map bytecode lines back to source paths
  -onlyAnalyze com.example.*     restrict analysis (trailing .* = package,
                                 .- = recursive subpackages)
  -include <filter.xml>          only report matching bugs
  -exclude <filter.xml>          suppress matching bugs
  -nested:true|false             analyze jars nested in wars/ears (default true)
  -maxHeap <MB>                  JVM heap for the analysis
  -quiet / -progress             stderr verbosity
```

Exit code: SpotBugs sets bit flags (1 = errors during analysis, 2 = classes
missing, 4 = bugs found) unless `-exitcode` behavior disabled — treat nonzero
as "check stderr", not failure.

### Scanning a war

```bash
spotbugs -textui -pluginList /opt/findsecbugs-plugin.jar \
  -effort:max -low -nested:true \
  -auxclasspath "$(find ~/.m2/repository -name 'servlet-api*.jar' | head -1)" \
  -sarif -output fsb.sarif target/example-app.war
```

`WEB-INF/classes` and `WEB-INF/lib/*.jar` inside the war are analyzed; still
add provided-scope jars (servlet-api, etc.) to the auxclasspath.

### JSPs

`XSS_JSP_PRINT` and other JSP patterns need **precompiled JSP classes**:

```bash
# Tomcat jasper precompile, then scan the output
$CATALINA_HOME/bin/jasper.sh ... # or org.apache.jasper.JspC via ant/maven
spotbugs ... -effort:max -low out/jsp-classes
```

## auxclasspath construction

```bash
# Maven: copy runtime deps, build classpath string
mvn -q dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=target/deps
AUX=$(find target/deps -name '*.jar' | paste -sd:)

# Or get the resolved classpath directly:
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt
AUX=$(cat cp.txt)

# Gradle: add a task
cat >> build.gradle <<'EOF'
task copyDeps(type: Copy) {
  from configurations.runtimeClasspath
  into "$buildDir/deps"
}
EOF
./gradlew copyDeps
AUX=$(find build/deps -name '*.jar' | paste -sd:)
```

### auxclasspath pitfalls

- **Missing jars = silent false negatives.** Taint transfer functions and
  type hierarchy resolution need every runtime dependency. Watch stderr for
  `The following classes needed for analysis were missing:` — if any
  framework/driver class is listed, fix and re-run.
- Don't put the **target classes themselves** on the auxclasspath — they must
  be analysis targets, not aux. Overlap causes classes to be skipped.
- Multi-module builds: analyze each module's classes with an auxclasspath of
  all sibling module jars + third-party deps, or merge everything into one
  run (`spotbugs ... module-a/target/classes module-b/target/classes`).
- Mismatched JDK: analyze with a SpotBugs running on a JDK >= the bytecode
  version (`Unsupported class file major version` otherwise).
- Kotlin/Scala: add `kotlin-stdlib` / `scala-library` jars to auxclasspath;
  expect some noise from compiler-generated synthetics (suppress with an
  exclude filter on `~.*\$\$inlined.*` style class regexes).

## Maven

One-shot, no pom edit:

```bash
mvn com.github.spotbugs:spotbugs-maven-plugin:4.8.6.4:check \
  -Dspotbugs.plugins=com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0 \
  -Dspotbugs.effort=Max -Dspotbugs.threshold=Low \
  -Dspotbugs.sarifOutput=true -Dspotbugs.xmlOutput=true \
  -Dspotbugs.failOnError=false -Dspotbugs.includeFilterFile=security-only.xml
# outputs per module: target/spotbugsXml.xml, target/spotbugsSarif.json
```

Permanent pom config:

```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <version>4.8.6.4</version>
  <configuration>
    <effort>Max</effort>
    <threshold>Low</threshold>
    <sarifOutput>true</sarifOutput>
    <includeFilterFile>security-only.xml</includeFilterFile>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
        <version>1.13.0</version>
      </plugin>
    </plugins>
  </configuration>
</plugin>
```

`mvn spotbugs:spotbugs` writes reports without failing the build;
`mvn spotbugs:check` fails on findings; `mvn spotbugs:gui` opens the triage
GUI on the XML.

## Gradle

```groovy
plugins { id 'com.github.spotbugs' version '6.0.19' }

dependencies {
  spotbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0'
}

spotbugs {
  effort = com.github.spotbugs.snom.Effort.MAX
  reportLevel = com.github.spotbugs.snom.Confidence.LOW
  includeFilter = file('security-only.xml')
}

tasks.withType(com.github.spotbugs.snom.SpotBugsTask) {
  reports {
    xml.required = true
    sarif.required = true
    html.required = true
  }
}
```

Run `./gradlew spotbugsMain` → `build/reports/spotbugs/main.{xml,sarif,html}`.
Kotlin projects: same plugin, it scans the Kotlin-compiled classes
automatically.

## Filter files

Include only security bugs:

```xml
<FindBugsFilter>
  <Match><Bug category="SECURITY"/></Match>
</FindBugsFilter>
```

Suppress known FPs (exclude filter):

```xml
<FindBugsFilter>
  <!-- generated code -->
  <Match><Class name="~com\.example\.generated\..*"/></Match>
  <!-- a specific pattern in a specific method -->
  <Match>
    <Class name="com.example.app.LegacyCrypto"/>
    <Method name="hashForCacheKey"/>
    <Bug pattern="WEAK_MESSAGE_DIGEST_MD5"/>
  </Match>
  <!-- everything ranked worse than 14 -->
  <Match><Rank value="15"/></Match>
</FindBugsFilter>
```

Matchers compose with implicit AND inside a `<Match>`; multiple `<Match>`
elements are OR. Available: `Bug` (pattern/code/category), `Class`, `Method`,
`Field`, `Local`, `Package`, `Priority`, `Confidence`, `Rank`, `Source`,
`Not`, `And`, `Or`. `~` prefix makes a value a Java regex.

In-source suppression:
`@edu.umd.cs.findbugs.annotations.SuppressFBWarnings("PATH_TRAVERSAL_IN")`
(needs `com.github.spotbugs:spotbugs-annotations` on the compile classpath) —
grep for existing `SuppressFBWarnings` in the repo: previously suppressed
security patterns are worth a manual look.

## Performance

- `-effort:max -low` on a large monolith can take 10–30+ min and several GB
  heap: `-maxHeap 8192` or `SPOTBUGS_OPTS=-Xmx8g`.
- Scope with `-onlyAnalyze 'com.example.-'` (recursive) to skip vendored
  packages; dependencies still belong on the auxclasspath.
- Multi-module: run per module in parallel, merge the SARIF/XML afterwards
  (the parser script accepts multiple input files).
