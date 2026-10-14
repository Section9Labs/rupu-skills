# Pyre/Pysa — configured taint analysis for Python

When Bandit flags a sink (B602, B608, B506, ...) but you can't eyeball the
dataflow, or when you suspect flows Bandit structurally cannot see
(cross-function, cross-module, through class attributes), bring in Pysa —
the taint analysis built into Facebook's Pyre type checker. Pysa does
interprocedural source→sink tracking driven by model files you control.

## Install & init

```bash
pip install pyre-check
cd /path/to/repo
pyre init                     # writes .pyre_configuration, asks for source dirs
```

A working `.pyre_configuration` for analysis:

```json
{
  "source_directories": ["src"],
  "taint_models_path": [".pysa_models"],
  "search_path": [{"site-package": "requests"}],
  "exclude": [".*/tests/.*", ".*/\\.venv/.*"]
}
```

Pysa ships a large stub/model set for Django, Flask, requests, etc. in
`pyre_check/taint/` inside the package — add it to `taint_models_path` to
start with sane sources/sinks:

```bash
python3 -c "import pyre_check, os; print(os.path.join(os.path.dirname(pyre_check.__file__), 'taint'))"
```

Pysa leans on type info; untyped code still works (it over-approximates)
but stubs for your frameworks dramatically improve both recall and
precision.

## Taint models (.pysa files)

Models declare WHERE taint enters (sources) and WHERE it must not go
(sinks), by annotating function signatures. Put them in
`.pysa_models/*.pysa`. The taxonomy lives in `taint.config` (JSON):

```json
{
  "sources": [{ "name": "UserControlled" }],
  "sinks":   [{ "name": "RemoteCodeExecution" }, { "name": "SQL" }],
  "features": [],
  "rules": [
    {
      "name": "User input to RCE",
      "code": 5001,
      "sources": ["UserControlled"],
      "sinks": ["RemoteCodeExecution"],
      "message_format": "User-controlled data reaches code execution sink"
    },
    {
      "name": "User input to SQL",
      "code": 5002,
      "sources": ["UserControlled"],
      "sinks": ["SQL"],
      "message_format": "User-controlled data reaches SQL execution"
    }
  ]
}
```

`.pysa_models/app.pysa` — annotate real signatures from the target repo:

```python
# Sources: everything a request handler receives
def flask.request.args.get(key) -> TaintSource[UserControlled]: ...
def example_app.api.get_param(name) -> TaintSource[UserControlled]: ...

# Sinks: parameters that must stay clean
def subprocess.run(args: TaintSink[RemoteCodeExecution], *, shell): ...
def os.system(command: TaintSink[RemoteCodeExecution]): ...
def example_app.db.query(sql: TaintSink[SQL], *params): ...

# Sanitizers / passthrough control
def shlex.quote(s) -> Sanitize: ...
@Sanitize
def example_app.util.escape_sql(s): ...

# Attribute sources (e.g. a parsed-request dataclass)
example_app.http.Request.body: TaintSource[UserControlled] = ...
```

Modeling tips:
- Model the TARGET REPO's wrapper functions, not just stdlib — if the app
  has `run_cmd(cmd)` calling subprocess internally, Pysa traces through
  it automatically, but modeling it directly as a sink shortens traces
  and survives refactors.
- `TaintInTaintOut` on helpers that transform-but-preserve taint
  (`def example_app.util.normalize(s) -> TaintInTaintOut: ...`).
- Convert each Bandit lead into a sink model: B602 → the exact
  subprocess call site's enclosing function; B608 → the execute wrapper.

## Run the analysis

```bash
pyre analyze --save-results-to out/
# incremental re-run after model edits:
pyre analyze --save-results-to out/ --use-cache
```

`out/` contains `errors.json` (the issues) plus `taint-output.json`
shards (full traces). Quick read of issues:

```bash
python3 - <<'EOF'
import json
for e in json.load(open("out/errors.json")):
    print(f"[{e['code']}] {e['name']}: {e['path']}:{e['line']} — {e['description']}")
EOF
```

Each issue has: rule `code` (yours, e.g. 5001), `path:line` of the
**issue callable** (where source-flow meets sink-flow), and the
`define` (fully qualified function). The full forward/backward traces are
in the taint output; the easiest way to walk them is SAPP:

```bash
pip install fb-sapp
sapp analyze out/        # ingests taint-output.json into sapp.db
sapp server              # web UI: click through source→sink call chains
# or terminal:
sapp explore             #   issues(), issue(1), trace()
```

Reading a trace: SAPP shows the chain
`source frame → ... → issue callable → ... → sink frame`. Each hop is a
real call edge — this is your exploit path. Verify the hops in code,
then build the PoC input at the source end.

## Pysa vs Bandit vs the others

| | Bandit | Semgrep taint | Pysa | CodeQL |
|---|---|---|---|---|
| Scope | single file, AST | file / simple interproc | whole program | whole program |
| Setup | zero | low (rules) | medium (models, types) | medium (db build) |
| Strength | sink inventory | fast confirmation | deep Python taint, custom taxonomies | breadth + query library |

Workflow: Bandit inventories sinks → write .pysa sink models from the
Bandit hits + UserControlled sources from the app's entry points →
`pyre analyze` → every issue is a (near-)confirmed flow → verify the SAPP
trace → PoC → load the `finding-report` skill and file it with
`findings.report`. Convert Pysa `errors.json` into work units with the
same shape as Bandit's (`id,title,targets,hints`) if you want to fan out
trace-verification across agents — load the `work-units` skill for the
split.
