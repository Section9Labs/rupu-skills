# rupu Wiring for Brakeman Output

How to plug this skill's output into the rupu fleet: work-unit fan-out,
coverage marking, and finding reports.

## 1. Produce the work-unit array

```sh
python3 scripts/run_brakeman.py -p /src/example-app -o out/
# writes out/brakeman.json, out/brakeman.sarif, out/workunits.json
```

`out/workunits.json` is a CLEAN top-level JSON array (rupu's `for_each:`
JSON-parses any value starting with `[`):

```json
[
  {
    "id": "9f1c8e2a...",
    "title": "SQL Injection in app/controllers/users_controller.rb:42",
    "targets": ["app/controllers/users_controller.rb:42"],
    "hints": {
      "check": "SQL Injection",
      "rule": "CheckSQL",
      "confidence": "High",
      "severity": "high",
      "cwe": "CWE-89",
      "message": "Possible SQL injection",
      "code": "User.where(\"name = '#{params[:name]}'\")",
      "user_input": "params[:name]",
      "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/"
    }
  }
]
```

## 2. Workflow: read_file + for_each

```yaml
steps:
  - id: scan
    run: python3 scripts/run_brakeman.py -p /src/example-app -o out/

  - id: load-units
    tool: read_file
    args:
      path: out/workunits.json

  - id: review-each
    for_each: "{{ steps.load-units.output }}"   # parsed as JSON array
    as: unit
    prompt: |
      Load the `work-units` skill. You are reviewing Brakeman work unit
      {{ unit.id }}: {{ unit.title }}.
      Targets: {{ unit.targets }}. Hints: {{ unit.hints }}.
      Open each target file:line, trace the user-input path
      ({{ unit.hints.user_input }}) to the sink, decide exploitability, and
      build a concrete PoC input. If verified, load the `finding-report`
      skill and file it with findings.report. If false positive, record the
      reason for the brakeman.ignore note.
```

## 3. Lead-agent dispatch fan-out

```yaml
  - id: fan-out
    for_each: "{{ steps.load-units.output }}"
    as: unit
    tool: dispatch
    args:
      agent: code-reviewer
      input: |
        Verify Brakeman warning {{ unit.id }} ({{ unit.hints.check }},
        confidence {{ unit.hints.confidence }}, {{ unit.hints.cwe }})
        at {{ unit.targets }}. Code: {{ unit.hints.code }}
        Load `work-units` for the review protocol and `finding-report`
        to file verified issues.
```

Batching tip: group units by `hints.check` before dispatch so one agent takes
all SQL Injection units (shared context), another takes the XSS family, etc.

## 4. Coverage: assets.mark

Mark the repo, every scanned file, and dependency packages so coverage is
trackable:

```json
{"tool": "assets.mark", "args": {
  "asset_type": "repository",
  "identifier": "git@example.com:example/example-app.git",
  "status": "scanned",
  "evidence": "brakeman 6.x, -A -w1, out/brakeman.sarif"
}}
```

```json
{"tool": "assets.mark", "args": {
  "asset_type": "file",
  "identifier": "example-app/app/controllers/users_controller.rb",
  "status": "scanned",
  "evidence": "brakeman run 2024-01-01, 2 warnings"
}}
```

The Brakeman JSON `scan_info.number_of_templates` / controller/model counts
plus the per-warning `file` fields enumerate scanned files; mark every file
that appears in `app/`, `lib/`, and `config/` of the scan root. Mark packages
from `Gemfile.lock`:

```json
{"tool": "assets.mark", "args": {
  "asset_type": "package",
  "identifier": "rubygems:rails@6.1.4",
  "status": "scanned",
  "evidence": "Gemfile.lock; brakeman EOLRails/CVE checks applied"
}}
```

## 5. Reporting: findings.report

For each VERIFIED warning (load the `finding-report` skill for full report
structure and severity rubric):

```json
{"tool": "findings.report", "args": {
  "title": "SQL injection in UsersController#search via params[:name]",
  "severity": "high",
  "asset": "example-app:app/controllers/users_controller.rb:42",
  "cwe": "CWE-89",
  "evidence": "User.where(\"name = '#{params[:name]}'\"); PoC: GET /users/search?name=' OR '1'='1 returns all rows; brakeman fingerprint 9f1c8e2a...",
  "reproduction": "curl 'http://192.0.2.10/users/search?name=%27%20OR%20%271%27=%271'",
  "source": "brakeman"
}}
```

Keep the Brakeman fingerprint in evidence - it links the finding to the
ignore file and to future `--compare` diffs.

## 6. SARIF handoff

Route `out/brakeman.sarif` to the `sarif-triage` skill to merge/dedupe with
other SARIF producers (semgrep, CodeQL) before fan-out, when multiple
scanners ran on the same repo. `brakeman_to_workunits.py --sarif` can also
ingest the SARIF directly if JSON output is unavailable; prefer native JSON
(richer: fingerprint, user_input, render_path, code).
