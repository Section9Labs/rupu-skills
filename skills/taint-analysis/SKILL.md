---
name: taint-analysis
description: Manual + tool-assisted source-to-sink (taint) methodology for security code review — enumerate dangerous sinks with ripgrep sink-pattern packs, trace each sink backwards to an untrusted source, check for class-appropriate sanitizers on the path, confirm reachability, then generalize with semgrep taint-mode or CodeQL dataflow and file verified findings. Use as the core bug-finding technique on any source-code audit (SQLi, command/code injection, deserialization, SSRF, path traversal, XXE, IDOR/authz, crypto misuse, secrets).
license: MIT
metadata:
  author: Section9Labs
---

# Taint analysis: source → sink code review

This is the core "how to actually find the bug" skill. Every injection-style
vulnerability is the same shape: **untrusted data (SOURCE) flows through the
program (PROPAGATION) into a dangerous operation (SINK) without a sanitizer
adequate for that vulnerability class on that path.** Your job is to prove or
refute that flow for every candidate sink in the codebase.

## 1. The model

**SOURCES** — where attacker-controlled data enters:
- HTTP: query params, POST body, JSON body, path segments, headers
  (`Host`, `X-Forwarded-For`, `Referer`, `User-Agent`), cookies, multipart
  filenames and file contents, websocket frames.
- CLI arguments and stdin of exposed tools; environment variables set by a
  less-trusted layer (CGI, container orchestrator annotations).
- Files read from upload dirs, shared mounts, archives (zip entry names!).
- Message queues, webhooks, pub/sub payloads, gRPC/thrift request fields.
- **Second-order**: DB columns that previously stored attacker data — a read
  from `users.display_name` is a source if registration lets anyone set it.
- Deserialized objects: every field of a deserialized payload is a source,
  and the deserialization call itself may be a sink (gadget chains).

**PROPAGATION** — how taint moves: assignments and aliasing; function
arguments and return values; string concatenation, `%`/`.format()`/f-strings,
template rendering; collection stores (`dict[k] = tainted` taints lookups);
object fields; serialization round-trips. Taint survives all of these.

**SANITIZERS** — operations that neutralize taint *for one class only*:
parameterized queries (SQLi), argv-array exec without a shell (cmdi), output
encoding (XSS), canonicalize-then-prefix-check (traversal), allowlist
validation, integer casts (`int(x)` kills nearly every injection class).
Sanitizers are class-specific: HTML-encoding does **nothing** against SQLi;
`shlex.quote` does nothing against path traversal. Treat blocklists, single
pass `replace()`, and `startswith()` checks without canonicalization as
**broken** sanitizers until proven otherwise.

**SINKS** — dangerous operations: SQL execution, shell/process spawn, `eval`,
template compilation, deserializers, outbound HTTP, filesystem APIs, XML
parsers, crypto primitives, reflection. The per-language sink tables and
ripgrep patterns live in `references/sinks-*.md`.

A **finding** = source reaches sink, no adequate sanitizer on *every* path
between them, and the code is reachable by an attacker.

## 2. The workflow

### Step 1 — Enumerate sinks (sink-first is faster than source-first)

```
python3 scripts/sink_hunt.py /path/to/repo -o sink_units.json
python3 scripts/sink_hunt.py /path/to/repo --lang python --lang javascript --vuln-class sql-injection -o sqli.json
```

`sink_hunt.py` drives ripgrep with the built-in per-language sink-pattern
packs (same patterns documented in `references/sinks-*.md`) and writes a
**clean JSON array of work units** — one per (file, vuln-class) group of sink
hits — ready for rupu `for_each:` / `dispatch` fan-out. Also run the raw
one-liners from the reference files when you want to iterate on a pattern.

Mark the repo and the scanned modules as assets (`assets.mark`) so coverage
is trackable — see `references/rupu.md`.

### Step 2 — Trace each sink backwards to a source

For each work unit, open the sink with context:

```
python3 scripts/trace_context.py app/views.py:42 -n 20 --function
```

Then walk backwards:
1. What expression feeds the dangerous argument? Resolve each variable to its
   assignment inside the function.
2. If it's a parameter, find the callers: `rg -n '\bbuild_report\(' --type py`
   and repeat in each caller. Keep a written chain:
   `request.args["q"] -> q -> build_filter(q) -> sql -> cursor.execute(sql)`.
3. Stop when you hit (a) a source — candidate bug; (b) a constant/config —
   dead end, next unit; (c) a sanitizer — evaluate it (Step 3).
4. Forward-tracing is the complement: start from route handlers / request
   objects and follow the data down. Use it on small codebases or when
   auditing one endpoint; sink-first scales better.

### Step 3 — Judge the sanitizers on the path

Ask, in order:
- Is it the **right class**? (`escape()` before `os.system` = still cmdi.)
- Is it on **every path**? Check `if/else` branches, early returns, exception
  handlers, and *every* caller when the sanitizer lives in only some callers.
- Is it applied **before every use**, not just the first? (TOCTOU: validate,
  then re-read the raw value.)
- Is it **complete**? Blocklists, regex without anchors (`re.match` vs
  `fullmatch`), single-pass `replace("../","")` (bypass: `....//`),
  `startswith("/safe/")` without `realpath` — all bypassable.

### Step 4 — Confirm reachability and attacker control

- Is the route registered and exposed? Find the router/urlconf, middleware
  order, authn requirement. An authz-free admin sink is a worse bug.
- Does the value survive propagation with injection power intact? An `int()`
  cast, enum lookup, or UUID parse kills the flow; `str.strip()` does not.
- Write the concrete attack value that fires the sink
  (`q = "' OR 1=1--"`, `url = "http://169.254.169.254/latest/meta-data/"`,
  `path = "../../../../etc/passwd"`) and verify each hop would pass it
  through. If a PoC harness/test exists, run the payload.

### Step 5 — Generalize: find the siblings

Once one flow is confirmed, the same team wrote more of them. Encode the flow
as a rule and sweep the whole repo:
- Load the **`semgrep`** skill and write a `mode: taint` rule (template in
  §4 below and in `references/classes.md`).
- Load the **`codeql`** skill for cross-procedural flows semgrep misses —
  the `TaintTracking::Global` config sketch is in §4.

### Step 6 — Record

- Every confirmed source→sink path: load the **`finding-report`** skill and
  file it with `findings.report` — include the full hop chain, the attack
  value, and the fix (the correct sanitizer for the class).
- Update `assets.mark` for every file/module you cleared, even when clean.

## 3. Vulnerability-class playbook (condensed)

Full tables, more languages, and bypass notes: `references/classes.md` and
`references/sinks-<lang>.md`. Patterns below are ripgrep.

### SQL injection
- Sinks: `execute`/`query` with concatenated or formatted strings; ORM escape
  hatches: Django `.raw()`/`.extra()`, SQLAlchemy `text()`, Sequelize
  `sequelize.query`, `knex.raw`, JPA `createQuery(.. + ..)`, Rails
  `find_by_sql` / string `where`.
- Sanitizers: parameterized queries / prepared statements; allowlists for
  identifiers (table/column/ORDER BY — placeholders can't cover those).
- `rg -n '\.execute\(\s*f["\x27]|\.execute\([^,)]*(\+|%|\.format)' -g '*.py'`
- Vuln: `cur.execute(f"SELECT * FROM users WHERE name='{name}'")`
  Fix: `cur.execute("SELECT * FROM users WHERE name=%s", (name,))`

### OS command injection
- Sinks: `os.system`, `os.popen`, `subprocess.*(shell=True)`, Node
  `child_process.exec`, Java `Runtime.getRuntime().exec`, PHP
  `exec/system/shell_exec/passthru`, Ruby `system`/`%x`/backticks,
  Go `exec.Command("sh","-c",...)`.
- Sanitizers: argv-array exec with no shell; allowlist of subcommands;
  `shlex.quote` only as last resort (argument-injection still possible: `-oProxyCommand=` style flags).
- `rg -n 'os\.system\(|shell\s*=\s*True' -g '*.py'` ·
  `rg -n '\bexec(Sync)?\(' -g '*.js' -g '*.ts'`
- Vuln: `os.system("ping " + host)` → Fix: `subprocess.run(["ping","--",host])`

### Code / template injection (incl. SSTI)
- Sinks: `eval`, `exec`, `new Function()`, `vm.runInNewContext`, SpEL
  `parseExpression`, `GroovyShell`; templates compiled from user strings:
  `render_template_string`, `jinja2.Template(user)`, `ERB.new(user)`,
  `render inline:`, Twig `createTemplate`, Thymeleaf expression preprocessing.
- Sanitizers: don't compile user input — pass it as template *data*;
  sandboxed env is a mitigation, not a fix.
- `rg -n 'render_template_string\(|jinja2\.Template\(' -g '*.py'`
- Vuln: `render_template_string("Hi " + request.args["name"])`
  (payload `{{cycler.__init__.__globals__.os.popen('id').read()}}`)
  Fix: `render_template_string("Hi {{ n }}", n=request.args["name"])`

### Insecure deserialization
- Sinks: `pickle.loads`, `yaml.load` (no `SafeLoader`), `marshal`,
  `jsonpickle.decode`, Java `ObjectInputStream.readObject`, `XMLDecoder`,
  XStream, SnakeYAML `new Yaml().load`, Ruby `Marshal.load`/`YAML.load`,
  PHP `unserialize($user)`, Node `node-serialize .unserialize`, js-yaml <4 `load`.
- Sanitizers: don't deserialize untrusted bytes — use JSON + schema;
  `yaml.safe_load`; Java `ObjectInputFilter` allowlists; HMAC the blob first.
- `rg -n 'pickle\.loads?\(|yaml\.(load|unsafe_load)\(' -g '*.py'`
- Vuln: `obj = pickle.loads(request.data)` → Fix: `obj = json.loads(request.data)` + schema validation.

### SSRF
- Sinks: any HTTP client with a user-influenced URL or host: `requests.*`,
  `urllib.request.urlopen`, `httpx`, `fetch`, `axios`, `got`, Java
  `URL.openConnection` / `RestTemplate`, Go `http.Get`, PHP
  `file_get_contents($url)` / cURL, Ruby `URI.open` / `Net::HTTP`.
- Impact targets: `http://169.254.169.254/` (cloud metadata), internal
  services, `file://`, `gopher://` where the client allows schemes.
- Sanitizers: allowlist of hosts/URL prefixes **after** parsing +
  canonicalization; resolve DNS and reject private/link-local ranges;
  re-validate on redirects. Blocklisting "169.254.169.254" alone is broken
  (decimal IPs, `[::ffff:169.254.169.254]`, DNS rebinding, redirects).
- `rg -n 'requests\.(get|post|request)\(|urlopen\(' -g '*.py'`

### Path traversal / arbitrary file read-write
- Sinks: `open`, `fs.readFile/writeFile`, `send_file`, `res.sendFile`,
  `new File(base + name)`, `os.path.join(base, user)` (absolute user path
  **discards** base in Python/Node!), archive extraction (`extractall`,
  zip-slip via `ZipEntry.getName()`), `include $_GET` in PHP (→ LFI/RCE).
- Sanitizers: canonicalize (`os.path.realpath`, `filepath.Clean`,
  `getCanonicalPath`) **then** verify prefix against the base dir; or map
  user input to an ID → server-chosen filename.
- `rg -n 'os\.path\.join\([^)]*(request|params|filename)|send_file\(' -g '*.py'`
- Vuln: `open(os.path.join(BASE, request.args["f"]))` →
  Fix: `p = os.path.realpath(os.path.join(BASE, f));` reject unless `p.startswith(BASE + os.sep)`.

### XXE
- Sinks: XML parsers with DTD/external entities enabled: Java
  `DocumentBuilderFactory`/`SAXParser`/`XMLInputFactory`/`TransformerFactory`
  without `disallow-doctype-decl`; lxml `XMLParser(resolve_entities=True)` or
  old defaults; PHP `LIBXML_NOENT`; libxmljs `{noent: true}`; dom4j `SAXReader`.
- Sanitizers: `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`,
  `defusedxml`, `resolve_entities=False`, never pass `LIBXML_NOENT`.
- `rg -n 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory' -g '*.java'`

### Authz gaps: IDOR and missing access control
- Model: the "sink" is any read/update/delete keyed by a **request-supplied
  object id**; the missing "sanitizer" is an ownership/role check between
  authn and the query.
- Hunt: list every route (`rg -n '@app\.route|router\.(get|post|put|delete)|@GetMapping|@PostMapping'`),
  then every fetch-by-request-id
  (`rg -n 'objects\.get\(.*request|findById\(.*request|params\[:id\]'`),
  and diff against where the ownership filter (`owner=request.user`,
  `WHERE user_id = ?`, `@PreAuthorize`, policy middleware) appears. Every
  route in the first list missing from the second is a candidate. Check
  state-changing routes for CSRF + method confusion too.
- Vuln: `Doc.objects.get(id=request.GET["id"])` →
  Fix: `Doc.objects.get(id=request.GET["id"], owner=request.user)`.

### Crypto misuse
- Sinks/smells: `AES/ECB`, `DES`, static IV/key literals, `MD5`/`SHA1` for
  passwords (want bcrypt/scrypt/argon2), non-CSPRNG for tokens
  (`random.*`, `Math.random`, `java.util.Random`, `mt_rand`, `math/rand`),
  disabled TLS verify (`verify=False`, `rejectUnauthorized: false`,
  `InsecureSkipVerify: true`, `CURLOPT_SSL_VERIFYPEER => false`,
  trust-all `X509TrustManager`).
- `rg -n 'MODE_ECB|verify\s*=\s*False|hashlib\.(md5|sha1)' -g '*.py'`
- Taint angle: trace where the weak token/hash is *used* — a `Math.random()`
  password-reset token is critical; a `Math.random()` cache key is noise.

### Hardcoded secrets
- For breadth across history and entropy detection, route to the
  **`gitleaks`** and **`trufflehog`** skills. During manual review:
  `rg -n -i '(api[_-]?key|secret|passw(or)?d|token|private[_-]?key)\s*[:=]\s*["\x27][A-Za-z0-9+/=_\-]{8,}'`
  plus `rg -n 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY'` and provider prefixes
  (`AKIA`, `ghp_`, `xoxb-`, `sk_live_`). A found secret is also a **source**
  of further access — note what it unlocks.

## 4. Tool assist: encode the flow, sweep the repo

**semgrep taint mode** (load the `semgrep` skill for full usage). Concrete
rule confirming + sibling-hunting the Flask SQLi above:

```yaml
rules:
  - id: flask-request-to-sql-execute
    mode: taint
    languages: [python]
    severity: ERROR
    message: User input flows into SQL execute without parameterization
    pattern-sources:
      - pattern-either:
          - pattern: flask.request.args.get(...)
          - pattern: flask.request.args[...]
          - pattern: flask.request.form[...]
          - pattern: flask.request.get_json(...)
          - pattern: flask.request.headers[...]
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: uuid.UUID(...)
    pattern-sinks:
      - patterns:
          - pattern: $CUR.execute($QUERY, ...)
          - focus-metavariable: $QUERY
```

Run: `semgrep --config taint-sqli.yaml --sarif -o semgrep.sarif /path/to/repo`.

**CodeQL dataflow** (load the `codeql` skill). Sketch of a global taint
config (modern `ConfigSig` style, Python):

```ql
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

module SqliConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::MethodCallNode c |
      c.getMethodName() = "execute" and n = c.getArg(0))
  }
  predicate isBarrier(DataFlow::Node n) {
    exists(DataFlow::CallCfgNode c |
      c.getFunction().asExpr().(Name).getId() = "int" and n = c)
  }
}
module Sqli = TaintTracking::Global<SqliConfig>;
import Sqli::PathGraph
from Sqli::PathNode src, Sqli::PathNode sink
where Sqli::flowPath(src, sink)
select sink.getNode(), src, sink, "Tainted SQL from $@.", src.getNode(), "user input"
```

Use CodeQL when the flow crosses many functions/files or goes through
collections and wrappers that defeat semgrep's intra-procedural taint.

## 5. Scripts in this skill

- `scripts/sink_hunt.py ROOT [-o FILE] [--lang L ...] [--vuln-class C ...] [--list]`
  — ripgrep-backed sink enumeration; emits the clean JSON work-unit array
  `[{"id","title","targets":["path:line"],"hints":{"vuln_class","sink","language","snippet"}}]`.
  Falls back to a pure-Python scanner if `rg` is absent.
- `scripts/trace_context.py path:line [path:line ...] [-n 12] [--function]`
  — prints numbered context and the enclosing function for fast back-tracing.

## 6. Handoff (rupu)

1. `assets.mark` the repository, each scanned module/file group, and the
   dependency manifests (see `references/rupu.md` for exact calls).
2. Load the **`work-units`** skill to split/normalize `sink_units.json`
   into per-agent work units; a rupu workflow consumes the file with
   `read_file` + `for_each:` (the array is clean top-level JSON), and a lead
   agent fans out with `dispatch` — wiring YAML in `references/rupu.md`.
3. Each dispatched agent runs Steps 2–5 on its unit (trace → judge →
   confirm → generalize).
4. For every **verified** source→sink path, load the **`finding-report`**
   skill and record it with `findings.report`, including the hop chain,
   attack value, sanitizer gap, and fix.
