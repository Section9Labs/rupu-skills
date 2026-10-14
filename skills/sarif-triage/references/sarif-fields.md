# SARIF 2.1.0 field reference — exact JSON paths

The slice of the spec `normalize_sarif.py` reads, with real-shape examples
from multiple tools. Everything else in a SARIF file is ignorable for triage.

## Top level

| Path | Meaning |
|---|---|
| `version` | `"2.1.0"` |
| `runs[]` | one per tool invocation (a file can hold several runs) |

## Run / tool / rules

| Path | Meaning |
|---|---|
| `runs[].tool.driver.name` | tool name (`"Semgrep OSS"`, `"CodeQL"`, `"gosec"`, `"Bandit"`, `"gitleaks"`) |
| `runs[].tool.driver.semanticVersion` | tool version |
| `runs[].tool.driver.rules[]` | rule catalog, indexed by `results[].ruleId` or `ruleIndex` |
| `runs[].tool.extensions[].rules[]` | rules contributed by query packs (CodeQL) — also searched |
| `rules[].id` | rule id, e.g. `python.lang.security.audit.sqli` or `py/sql-injection` |
| `rules[].shortDescription.text` | human title → `title` |
| `rules[].fullDescription.text` | long text (scanned for `CWE-\d+` as a fallback) |
| `rules[].defaultConfiguration.level` | fallback level when the result omits `level` |
| `rules[].properties.cwe` | CWE as string or list (`"CWE-89"` or `["CWE-89: ..."]`) — semgrep style |
| `rules[].properties.tags[]` | CodeQL style: `"external/cwe/cwe-089"`; also `"security"` |
| `rules[].properties["security-severity"]` | CVSS-like `"8.8"` string, 0–10 |

## Results

| Path | Meaning |
|---|---|
| `results[].ruleId` | joins to the rule catalog |
| `results[].ruleIndex` | positional fallback into `driver.rules[]` |
| `results[].level` | `error` / `warning` / `note` / `none` |
| `results[].message.text` | finding message → `message` |
| `results[].locations[0].physicalLocation.artifactLocation.uri` | file path (usually repo-relative) → `file` |
| `results[].locations[0].physicalLocation.region.startLine` | → `line` |
| `results[].locations[0].physicalLocation.region.startColumn` | → `column` |
| `results[].partialFingerprints` | stable dedup keys, e.g. `{"primaryLocationLineHash": "ab12...:1"}` → hashed into `fingerprint` |
| `results[].properties` | merged over rule properties (result wins) |
| `results[].codeFlows[].threadFlows[].locations[]` | taint path, source first, sink last |
| `...threadFlows[].locations[].location.physicalLocation` | same shape as a result location |
| `...threadFlows[].locations[].location.message.text` | per-step annotation (`"source: request.args"`) |

## Example: semgrep SARIF (abridged)

```json
{"version": "2.1.0", "runs": [{
  "tool": {"driver": {"name": "Semgrep OSS", "rules": [{
    "id": "python.django.security.injection.sql.sql-injection-db-cursor-execute",
    "shortDescription": {"text": "SQL injection via cursor.execute"},
    "defaultConfiguration": {"level": "error"},
    "properties": {
      "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
      "security-severity": "8.8",
      "tags": ["security", "OWASP-A03:2021"]}}]}},
  "results": [{
    "ruleId": "python.django.security.injection.sql.sql-injection-db-cursor-execute",
    "level": "error",
    "message": {"text": "User-controlled data flows into cursor.execute"},
    "locations": [{"physicalLocation": {
      "artifactLocation": {"uri": "app/views.py"},
      "region": {"startLine": 42, "startColumn": 5}}}],
    "partialFingerprints": {"matchBasedId/v1": "1f0c..."}}]}]}
```

Normalizes to: severity **high** (security-severity 8.8 → high, overriding
level error→high anyway), cwe `CWE-89`, fingerprint from
`partialFingerprints`.

## Example: CodeQL SARIF with a code flow (abridged)

```json
{"version": "2.1.0", "runs": [{
  "tool": {"driver": {"name": "CodeQL"},
    "extensions": [{"rules": [{
      "id": "py/sql-injection",
      "shortDescription": {"text": "SQL query built from user-controlled sources"},
      "defaultConfiguration": {"level": "error"},
      "properties": {
        "tags": ["security", "external/cwe/cwe-089"],
        "security-severity": "8.8"}}]}]},
  "results": [{
    "ruleId": "py/sql-injection", "ruleIndex": 0,
    "message": {"text": "This SQL query depends on a user-provided value."},
    "locations": [{"physicalLocation": {
      "artifactLocation": {"uri": "app/db.py"},
      "region": {"startLine": 42}}}],
    "partialFingerprints": {"primaryLocationLineHash": "6c9f1e..."},
    "codeFlows": [{"threadFlows": [{"locations": [
      {"location": {"physicalLocation": {
         "artifactLocation": {"uri": "app/views.py"},
         "region": {"startLine": 10}},
       "message": {"text": "request.args['q'] : source"}}},
      {"location": {"physicalLocation": {
         "artifactLocation": {"uri": "app/db.py"},
         "region": {"startLine": 42}},
       "message": {"text": "cursor.execute(...) : sink"}}}]}]}]}]}]}
```

Normalizes to `code_flow: ["app/views.py:10 -- request.args['q'] : source",
"app/db.py:42 -- cursor.execute(...) : sink"]` — carry this into triage: the
first step is the attacker-controlled source, the last is the sink.

## Per-tool SARIF quirks

| Tool | Quirk |
|---|---|
| semgrep | CWE + security-severity in rule `properties`; `matchBasedId/v1` partial fingerprint |
| CodeQL | rules under `tool.extensions[]` (query packs); CWE only in tags (`external/cwe/cwe-089`); results often omit `level` → use `defaultConfiguration.level`; path queries carry `codeFlows` |
| gosec | plain level mapping; native severity preserved in rule properties on some versions; `line` may be a range `"12-14"` in native JSON (handled) |
| bandit | SARIF has level only; native JSON richer (`issue_severity`, `issue_confidence`, `issue_cwe.id`) — prefer native for bandit |
| njsscan | level-based; CWE embedded in message/metadata text (regex-extracted) |
| brakeman | level-based; confidence (High/Medium/Weak) in properties on some versions |
| gitleaks | no CWE, no severity → normalized to CWE-798 / high; `partialFingerprints` present in SARIF; native JSON has `Fingerprint`, `Commit`, `Secret` |

## Native JSON shapes autodetected by normalize_sarif.py

| Format | Detection | Key fields read |
|---|---|---|
| semgrep `--json` | `results[].check_id` | `check_id`, `path`, `start.line`, `extra.severity`, `extra.metadata.cwe`, `extra.metadata["security-severity"]`, `extra.fingerprint` |
| bandit `-f json` | `results[].issue_severity` or `metrics` | `test_id`, `test_name`, `filename`, `line_number`, `issue_severity`, `issue_confidence`, `issue_cwe.id`, `issue_text` |
| gosec `-fmt json` | top-level `Issues` | `rule_id`, `details`, `file`, `line`, `severity`, `confidence`, `cwe.id` |
| gitleaks json | list with `RuleID` | `RuleID`, `Description`, `File`, `StartLine`, `Fingerprint`, `Commit` |
| trivy `-f json` | `Results` + `SchemaVersion`/`ArtifactName` | `Target`, `Vulnerabilities[]` (`VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, `CweIDs`), `Secrets[]` |
| npm audit `--json` | `auditReportVersion` | `vulnerabilities{name: {severity, range, via[].{title,cwe,source}}}` |
