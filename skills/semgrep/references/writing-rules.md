# Writing Semgrep rules — full tutorial

Custom rules are where Semgrep pays off on a real engagement: model the
target's own dangerous wrappers, forbidden APIs, and trust boundaries.
Iterate interactively at https://semgrep.dev/playground or locally with
`semgrep scan -e '<pattern>' -l <lang> <path>`.

## 1. Rule file skeleton

A rule file is YAML with a top-level `rules:` list. Every rule needs:

```yaml
rules:
  - id: org-unique-kebab-case-id          # shows up in output; prefix with project
    languages: [python]                    # go, javascript, typescript, java, ruby...
    severity: ERROR                        # INFO | WARNING | ERROR
    message: >-
      One-sentence what + why + fix hint. Metavariables interpolate: found $FUNC.
    metadata:                              # free-form, but keep these keys —
      cwe: "CWE-89: SQL Injection"         #   downstream tooling reads them
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      references:
        - https://owasp.org/Top10/A03_2021-Injection/
    patterns: ...                          # or: pattern / pattern-either / mode: taint
```

Optional keys: `fix:` (autofix template, metavariables allowed),
`paths: {include: [...], exclude: [...]}` (per-rule file scoping),
`options:` (engine switches, e.g. `symbolic_propagation: true`).

## 2. Pattern language

### Metavariables and ellipsis

- `$X`, `$FUNC`, `$ARG1` — bind any single expression/identifier/statement.
  Repeating a metavariable in the SAME pattern requires equality:
  `$X == $X` matches `a == a` but not `a == b`.
- `...` — any sequence: arguments `foo(...)`, statements between two anchors,
  characters inside strings `"..."`, keyword args `foo(..., timeout=$T, ...)`.
- `<... $X ...>` — deep expression match: `$X` anywhere inside an expression,
  e.g. `pattern: cursor.execute(<... request.args ...>)`.
- Patterns are AST-based: whitespace, comments, parentheses, argument order of
  keyword args don't matter. `foo(1, 2)` matches `foo( 1 , 2 )` and `foo(1,2)`.

### Operators

```yaml
patterns:                      # AND — all clauses must hold on the same code
  - pattern: $CUR.execute($Q)
  - pattern-not: $CUR.execute("...")          # subtract literal-only queries
  - pattern-inside: |                          # must appear within this context
      def $VIEW(request, ...):
          ...
  - pattern-not-inside: |                      # ...but not inside this one
      with transaction.atomic():
          ...
  - metavariable-pattern:                      # recursively constrain a binding
      metavariable: $Q
      patterns:
        - pattern-either:
            - pattern: f"..."
            - pattern: $A + $B
            - pattern: "...".format(...)
            - pattern: "..." % ...
  - metavariable-regex:
      metavariable: $CUR
      regex: ^(cursor|cur|db)$
```

```yaml
pattern-either:                # OR
  - pattern: eval(...)
  - pattern: exec(...)
```

- `pattern-regex` / `pattern-not-regex`: raw regex over file text (multiline
  with `(?s)`); use for secrets, config files, languages Semgrep can't parse.
  Named groups become metavariables: `(?P<KEY>AKIA[0-9A-Z]{16})` → `$KEY`.
- `metavariable-comparison`: evaluate a Python-ish expression on bindings:

```yaml
- pattern: os.chmod($PATH, $MODE)
- metavariable-comparison:
    metavariable: $MODE
    comparison: $MODE >= 0o777
```

Also supports `int($X) == 0`, `str($X) == "md5"`, `$X < 2048`, `in`, `not in`,
`re.match(...)`.

### Useful idioms

```yaml
# match a call regardless of import style (python resolves aliases):
- pattern: subprocess.run(...)        # also matches `from subprocess import run; run(...)`

# typed metavariable (java/go/ts): only when $REQ is an HttpServletRequest
- pattern: ($REQ : HttpServletRequest).getParameter(...)

# anything assigned from a function whose name matches:
- pattern: $X = $F(...)
- metavariable-regex: { metavariable: $F, regex: (?i).*(unsafe|raw).* }
```

## 3. Complete search-mode examples

### Python — hardcoded Flask secret key

```yaml
rules:
  - id: flask-hardcoded-secret
    languages: [python]
    severity: ERROR
    message: Hardcoded Flask SECRET_KEY — session forgery. Load from env/secret store.
    metadata: {cwe: "CWE-798: Use of Hard-coded Credentials", owasp: "A02:2021 - Cryptographic Failures"}
    pattern-either:
      - pattern: $APP.config["SECRET_KEY"] = "..."
      - pattern: $APP.secret_key = "..."
    fix: $APP.secret_key = os.environ["SECRET_KEY"]
```

### JavaScript — DOM XSS via innerHTML

```yaml
rules:
  - id: js-innerhtml-nonliteral
    languages: [javascript, typescript]
    severity: WARNING
    message: Non-literal assigned to innerHTML — DOM XSS risk. Use textContent or sanitize.
    metadata: {cwe: "CWE-79: Cross-site Scripting", owasp: "A03:2021 - Injection"}
    patterns:
      - pattern: $EL.innerHTML = $V
      - pattern-not: $EL.innerHTML = "..."
      - pattern-not: $EL.innerHTML = `...`      # only when template has no ${}
      - metavariable-pattern:
          metavariable: $V
          patterns:
            - pattern-not: DOMPurify.sanitize(...)
```

### Go — TLS verification disabled

```yaml
rules:
  - id: go-insecure-skip-verify
    languages: [go]
    severity: ERROR
    message: TLS certificate verification disabled (InsecureSkipVerify) — MITM.
    metadata: {cwe: "CWE-295: Improper Certificate Validation", owasp: "A02:2021 - Cryptographic Failures"}
    patterns:
      - pattern: tls.Config{..., InsecureSkipVerify: true, ...}
      - pattern-not-inside: |
          func Test...(...) { ... }
```

## 4. Taint mode

`mode: taint` tracks dataflow from sources to sinks (intraprocedural by
default; assignments, concatenation, f-strings/templates, container inserts,
and sanitizer-free function returns propagate taint).

Keys:
- `pattern-sources` — list of pattern clauses that introduce taint. Each entry
  takes the same operators as search mode (`pattern`, `patterns`,
  `pattern-either`, `pattern-inside`...). Optional `label:`/`requires:` for
  multi-stage taint.
- `pattern-sinks` — where tainted data must arrive. By default any tainted
  subexpression of the sink pattern triggers; use `focus-metavariable: $CMD`
  inside a `patterns:` sink to require taint in one specific argument.
- `pattern-sanitizers` — clears taint. `by-side-effect: true` makes an
  in-place call (e.g. `validate($X)`) sanitize `$X` afterwards.
- `pattern-propagators` — teach flow through calls the engine doesn't model:

```yaml
pattern-propagators:
  - pattern: $DST.append($SRC)
    from: $SRC
    to: $DST
  - pattern: strings.Join($SRC, $SEP)
    from: $SRC
    to: $RET          # taint the return — use within an assignment context
```

Run with `--dataflow-traces` to see the full source→sink path in output.

### Python — user input to SQL string concat

```yaml
rules:
  - id: taint-flask-sqli-concat
    languages: [python]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled value flows into a dynamically-built SQL string executed
      by the DB driver — SQL injection. Use parameterized queries.
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
    pattern-sources:
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.form.get(...)
      - pattern: flask.request.values[...]
      - pattern: flask.request.get_json()
      - pattern: flask.request.cookies.get(...)
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: uuid.UUID(...)
      - patterns:
          - pattern: $CONN.escape($X)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $CUR.execute($Q, ...)
              - pattern: $CUR.executemany($Q, ...)
              - pattern: $ENGINE.execute($Q, ...)
          - focus-metavariable: $Q
```

This fires on all of:

```python
q = "SELECT * FROM users WHERE name = '" + flask.request.args.get("u") + "'"
cur.execute(q)                                            # concat via variable
cur.execute(f"DELETE FROM t WHERE id = {request.args.get('id')}")   # f-string
name = request.form.get("n"); q = "..." % name; cur.execute(q)      # % format
```

and stays silent on `cur.execute("SELECT * FROM users WHERE id = %s", (uid,))`.

### JavaScript — Express req to child_process

```yaml
rules:
  - id: taint-express-cmd-injection
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: Request data reaches child_process exec — command injection.
    metadata: {cwe: "CWE-78: OS Command Injection", owasp: "A03:2021 - Injection"}
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $REQ.query
              - pattern: $REQ.body
              - pattern: $REQ.params
              - pattern: $REQ.headers
          - pattern-inside: |
              $APP.$METHOD('...', function ($REQ, $RES) { ... })
      - pattern-inside: |
          $APP.$METHOD('...', ($REQ, $RES) => { ... })
    pattern-sanitizers:
      - pattern: parseInt(...)
      - pattern: Number(...)
    pattern-sinks:
      - pattern: child_process.exec(...)
      - pattern: child_process.execSync(...)
      - pattern: require('child_process').exec(...)
```

### Go — request parameter to exec.Command with shell

```yaml
rules:
  - id: taint-go-shell-injection
    languages: [go]
    severity: ERROR
    mode: taint
    message: HTTP input reaches a shell invocation — command injection.
    metadata: {cwe: "CWE-78: OS Command Injection"}
    pattern-sources:
      - pattern: $R.URL.Query().Get(...)
      - pattern: $R.FormValue(...)
      - pattern: $R.PostFormValue(...)
    pattern-sinks:
      - patterns:
          - pattern: exec.Command("sh", "-c", $ARG, ...)
          - focus-metavariable: $ARG
      - patterns:
          - pattern: exec.Command("bash", "-c", $ARG, ...)
          - focus-metavariable: $ARG
```

## 5. Testing rules

Place a fixture file next to the rule (same basename, target-language
extension): `rules/taint-flask-sqli-concat.yaml` + `rules/taint-flask-sqli-concat.py`.
Annotate the line BEFORE each expected match:

```python
import flask
from flask import request
cur = get_cursor()

def bad():
    # ruleid: taint-flask-sqli-concat
    cur.execute("SELECT * FROM u WHERE n='" + request.args.get("n") + "'")

def good():
    # ok: taint-flask-sqli-concat
    cur.execute("SELECT * FROM u WHERE n=%s", (request.args.get("n"),))

def todo():
    # todoruleid: taint-flask-sqli-concat   <- known miss, won't fail the test
    helper(request.args.get("n"))
```

```bash
semgrep --validate --config rules/     # schema/pattern syntax errors
semgrep --test rules/                  # asserts ruleid/ok annotations; non-zero exit on mismatch
```

Keep every custom rule under test — rules rot as the pattern engine evolves.

## 6. Rule-writing workflow on an engagement

1. Grep the repo for its own danger surface: DB access layers, exec wrappers,
   template renderers, deserializers, auth decorators.
   `grep -rn "def execute_raw\|shell=True\|dangerouslySetInnerHTML" .`
2. Write a search rule for direct misuse of each wrapper; write a taint rule
   from the app's input boundary (framework request objects, message-queue
   consumers, file parsers) to each wrapper.
3. Validate, test against hand-made fixtures, then run on the repo with
   `--dataflow-traces` and triage.
4. Tighten with `pattern-not` / sanitizers for each confirmed FP class;
   re-run until signal is high; keep the rules in `rules/` in the engagement
   workspace so re-scans are reproducible.
