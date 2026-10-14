# rupu wiring — consume sarif-triage output in the fleet

How the pipeline output plugs into rupu workflows, `dispatch` fan-out,
`assets.mark` coverage, and `findings.report`. The shared splitter and the
reporting pack are NOT re-implemented here: load the `work-units` skill to
split normalized findings into work units, and the `finding-report` skill to
file each verified issue.

## 0. Produce the artifact

```bash
python3 scripts/normalize_sarif.py semgrep.sarif codeql.sarif gitleaks.sarif \
  | python3 scripts/dedupe_findings.py \
  | python3 scripts/to_workunits.py --min-severity low -o workunits.json
```

`workunits.json` is a CLEAN top-level JSON array — rupu's `for_each:`
JSON-parses any value that starts with `[`, so no wrapper object, no
trailing prose, nothing on stdout except the array when `-o` is omitted.

## 1. Workflow: read_file + for_each over the work-unit array

```yaml
# triage-fanout.yaml
name: sarif-triage-fanout
steps:
  - id: normalize
    run: >
      python3 skills/sarif-triage/scripts/normalize_sarif.py out/*.sarif
      | python3 skills/sarif-triage/scripts/dedupe_findings.py
      | python3 skills/sarif-triage/scripts/to_workunits.py
        --min-severity low -o out/workunits.json

  - id: load-units
    tool: read_file
    args:
      path: out/workunits.json

  - id: verify-unit
    for_each: "{{ steps.load-units.output }}"   # parsed: starts with '['
    prompt: |
      Load the `sarif-triage` skill. Verify work unit {{ item.id }}:
      "{{ item.title }}".
      Open each target in {{ item.targets }} and read the surrounding code.
      Hints: tools={{ item.hints.tools }}, severity={{ item.hints.severity }},
      cwe={{ item.hints.cwe }}, rule={{ item.hints.rule }},
      code_flow={{ item.hints.code_flow }}.
      Walk the code flow source -> sink; confirm no sanitizer breaks the path;
      build a concrete trigger input where feasible.
      If verified: load the `finding-report` skill and file it with
      findings.report, carrying fingerprint {{ item.hints.fingerprint }}.
      Either way, mark the files you reviewed with assets.mark.
```

## 2. Lead-agent fan-out with dispatch

A lead agent reads `workunits.json`, then fans out one child per unit (or
per `--group file` unit so each child owns one file):

```
units = json.load(open("out/workunits.json"))
for unit in units:                    # already sorted by priority
    dispatch(
        task="verify-finding",
        prompt=f"Load the `sarif-triage` skill. Verify {unit['id']}: "
               f"{unit['title']}. Targets: {unit['targets']}. "
               f"Hints: {json.dumps(unit['hints'])}. "
               "If verified, load the `finding-report` skill and file it "
               "with findings.report; mark reviewed files with assets.mark.",
    )
```

Batching tip: dispatch high/critical units individually; batch medium/low by
file (`to_workunits.py --group file`) so one child reads each file once.

## 3. Coverage: assets.mark

The code-review asset model is the repository, the scanned files/modules, and
the dependency packages. Mark all three so coverage is trackable:

```
assets.mark {"type": "repository", "id": "git@example.com:app/api.git",
             "status": "scanned",
             "notes": "semgrep+codeql+gitleaks via sarif-triage, 214 raw -> 87 unique"}

assets.mark {"type": "file", "id": "app/db.py",
             "status": "reviewed",
             "notes": "wu-0001-ab12cd34 verified (CWE-89)"}

assets.mark {"type": "package", "id": "npm:lodash@4.17.20",
             "status": "vulnerable",
             "notes": "trivy CVE in deduped set; fixed in 4.17.21"}
```

Mark every file that appears in any unit's `targets` when its unit is
processed — including units closed as false positives — so "reviewed" means
reviewed, not "had no findings". Mark every dependency package that the SCA
inputs covered (trivy/npm-audit records carry `hints.package`).

## 4. Reporting: findings.report via the finding-report skill

For each unit a child agent VERIFIES in source, load the `finding-report`
skill and file the record. Carry the triage metadata through verbatim:

```
findings.report {
  "title": "SQL injection in app/db.py:42 (query built from request.args)",
  "severity": "high",
  "cwe": "CWE-89",
  "asset": "git@example.com:app/api.git",
  "location": "app/db.py:42",
  "fingerprint": "ab12cd34ef567890",
  "tools": ["codeql", "semgrep"],
  "rule": "py/sql-injection; python.django.security.injection.sql.sql-injection-db-cursor-execute",
  "evidence": "code_flow: app/views.py:10 request.args['q'] -> app/db.py:42 cursor.execute; verified: payload \"' OR 1=1--\" alters query",
  "recommendation": "parameterize the query (cursor.execute(sql, params))"
}
```

Rules of the road:

- `fingerprint` from the work unit goes into the finding — it is the join
  key back to the deduped record and prevents double-filing across waves.
- Corroborating `tools` list goes in as-is; it is evidence weight.
- A unit that fails verification is NOT filed; re-queue it with
  confidence downgraded (edit `hints.confidence` to `low`) or close it with
  an `assets.mark` note on the file explaining why it is a false positive.

## 5. Full chain, end to end

1. Run every scanner, SARIF out (see SKILL.md §1).
2. `normalize_sarif.py` → `dedupe_findings.py` → `to_workunits.py -o workunits.json`.
3. `assets.mark` the repository + dependency packages covered by the scan.
4. Load the `work-units` skill; feed it `workunits.json` (it is already in
   the splitter's array format — `read_file` + `for_each:` or `dispatch`).
5. Children verify units, `assets.mark` each reviewed file, and for every
   verified issue load the `finding-report` skill and call `findings.report`.

— vulture (cobalt-slope)
