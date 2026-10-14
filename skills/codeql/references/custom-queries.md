# Custom CodeQL queries — qlpack, TaintTracking, quick-eval

Write custom queries when the standard suites don't model the app's sources
(custom RPC/message bus deserializers) or sinks (in-house SQL/exec wrappers),
or when you want to answer a one-off reachability question across the DB.

## 1. Create a query pack

```bash
codeql pack init myorg/audit-queries --dir=audit-queries
```

Generated `audit-queries/qlpack.yml` — edit to add the language library dep:

```yaml
name: myorg/audit-queries
version: 0.0.1
library: false
dependencies:
  codeql/python-all: "*"      # or codeql/java-all, codeql/javascript-all, ...
```

```bash
cd audit-queries
codeql pack install           # resolves deps into the package cache, writes codeql-pack.lock.yml
```

## 2. Minimal taint-tracking query (`@kind path-problem` → SARIF code flows)

`audit-queries/CustomSqlSink.ql` — Python example: taint from any remote
input to the first argument of an in-house wrapper `dbutil.raw_query(...)`:

```ql
/**
 * @name Untrusted input reaches dbutil.raw_query
 * @description Remote input flows into the in-house raw SQL wrapper.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/audit/custom-sql-sink
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs
import MyFlow::PathGraph

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource          // request params, headers, bodies...
  }

  predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("dbutil").getMember("raw_query").getACall().getArg(0)
  }

  // optional noise control:
  // predicate isBarrier(DataFlow::Node node) { ... sanitizer calls ... }
}

module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted input from $@ reaches raw_query.", source.getNode(), "remote source"
```

Anatomy, language-independent:
- **Sources**: each language lib ships `RemoteFlowSource` /
  `ThreatModelFlowSource` classes (HTTP params, env, files per threat model).
- **Sinks**: locate calls with `API::` graphs (Python/JS/Ruby) or
  `Method`/`MethodCall` classes (Java/C#) and pick the tainted argument.
- **Config**: implement `DataFlow::ConfigSig` (`isSource`, `isSink`, optional
  `isBarrier`, `isAdditionalFlowStep`), instantiate
  `TaintTracking::Global<Config>` (taint, loose) or `DataFlow::Global<Config>`
  (value-preserving, strict).
- **`@kind path-problem`** + `import MyFlow::PathGraph` + the 4-part `select`
  is what makes CodeQL emit `codeFlows` in SARIF. `@kind problem` gives a
  single location only.
- `@id`, `@security-severity`, `@tags external/cwe/cwe-NNN` feed straight into
  the SARIF rule metadata the downstream parser reads.

Java flavor of the sink predicate:

```ql
predicate isSink(DataFlow::Node sink) {
  exists(MethodCall mc |
    mc.getMethod().hasQualifiedName("com.example.db", "DbUtil", "rawQuery") and
    sink.asExpr() = mc.getArgument(0)
  )
}
```

## 3. Run it

```bash
# whole pack (compiles all .ql in it)
codeql database analyze /tmp/db-example ./audit-queries \
  --format=sarif-latest --output=custom.sarif

# single query file
codeql database analyze /tmp/db-example ./audit-queries/CustomSqlSink.ql \
  --format=sarif-latest --output=custom.sarif
```

Fast iteration without SARIF plumbing:

```bash
codeql query run --database=/tmp/db-example ./audit-queries/CustomSqlSink.ql
codeql query compile ./audit-queries/CustomSqlSink.ql    # type-check only
```

VS Code + the CodeQL extension gives quick-eval (evaluate a selected
predicate) and an AST viewer — the fastest way to find the right classes for
a sink. CLI equivalent for exploration: write small `select` queries, e.g.
`from CallNode c where ... select c` to enumerate candidate calls.

## 4. Extending the standard queries instead (data extensions)

Often you don't need a new query — just teach the *standard* SQLi/cmdi query
about your wrapper via **model packs** (YAML data extensions): declare
`sinkModel` / `sourceModel` / `summaryModel` rows for your APIs in a pack with
`extensionTargets: codeql/<lang>-all`, then pass it at analyze time with
`--model-packs myorg/my-models` (or add it to the analyzed pack's
dependencies). This keeps you on maintained query logic while covering
in-house frameworks. See the upstream "Customizing library models" docs for
the exact column formats per language.

## 5. Distribute

```bash
codeql pack create ./audit-queries         # compile + bundle
codeql pack publish ./audit-queries        # push to a GHES/ghcr registry (optional)
```

Pin custom packs in a `codescanning-config` or pass the local directory —
local dirs are fine for engagement work.
