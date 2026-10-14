# rupu wiring for gosec output

## 1. Produce the work-unit array

```sh
python3 scripts/run_gosec.py --repo /work/repo --outdir /work/out
# or, if gosec already ran:
python3 scripts/gosec_to_workunits.py --json /work/out/gosec.json \
    --sarif /work/out/gosec.sarif --out /work/out/workunits.json
```

`/work/out/workunits.json` is a clean top-level JSON array:

```json
[
  {
    "id": "gosec-G204-0001",
    "title": "G204: Subprocess launched with a potential tainted input or cmd arguments (internal/runner/exec.go:42)",
    "targets": ["internal/runner/exec.go:42"],
    "hints": {
      "rule_id": "G204",
      "severity": "HIGH",
      "confidence": "HIGH",
      "cwe": "CWE-78",
      "details": "Subprocess launched with a potential tainted input or cmd arguments",
      "code": "exec.Command(\"sh\", \"-c\", userCmd)",
      "suppressed": "false"
    }
  }
]
```

Load the **`work-units`** skill to split/normalize this array — do not
re-implement the splitter here.

## 2. Workflow consumption (`read_file` + `for_each:`)

rupu's `for_each:` JSON-parses any value that starts with `[`, so the file can
be fed directly:

```yaml
steps:
  - id: scan
    run: python3 skills/gosec/scripts/run_gosec.py --repo {{repo}} --outdir {{out}}

  - id: load_units
    tool: read_file
    args:
      path: "{{out}}/workunits.json"

  - id: review_each
    for_each: "{{steps.load_units.output}}"
    as: unit
    steps:
      - id: verify
        prompt: >
          Verify gosec finding {{unit.id}} ({{unit.hints.rule_id}},
          {{unit.hints.cwe}}) at {{unit.targets}}. Open the file, trace
          whether the flagged value is attacker-controlled, check for
          sanitizers and #nosec justifications. If dataflow is unclear, load
          the `taint-analysis` skill and corroborate with semgrep/codeql Go
          results. If verified, load the `finding-report` skill and file it
          with findings.report.
```

## 3. Lead-agent fan-out (`dispatch`)

```
units = json.parse(read_file("/work/out/workunits.json"))
for unit in units:
    dispatch(
      task=f"Verify and, if real, report gosec finding {unit['id']} "
           f"({unit['hints']['rule_id']}) at {unit['targets'][0]}. "
           f"Load the gosec skill section 8 and the finding-report skill.",
      context={"unit": unit, "repo": "/work/repo", "sarif": "/work/out/gosec.sarif"}
    )
```

Batch by `hints.rule_id` when the count is high (one agent per rule class
reviews patterns consistently).

## 4. Coverage: `assets.mark`

Mark the repo, the scanned files (from gosec JSON `Stats` / per-issue `file`),
and dependency packages (from `go list -m all`):

```
assets.mark(asset_type="repository", identifier="git.example.com/example/app",
            status="scanned", tool="gosec",
            notes="gosec v2 full run, -tests -track-suppressions")

assets.mark(asset_type="file", identifier="internal/runner/exec.go",
            status="scanned", tool="gosec")

# files listed under "Golang errors" in gosec.json did NOT get scanned:
assets.mark(asset_type="file", identifier="gen/proto/api.pb.go",
            status="not-scanned", tool="gosec",
            notes="build error during gosec load; rerun with -tags / fixed deps")

assets.mark(asset_type="package", identifier="golang.org/x/crypto@v0.17.0",
            status="inventoried", tool="go-list",
            notes="dependency of scanned module; SCA via govulncheck/osv-scanner")
```

`gosec_to_workunits.py --assets-out out/assets.json` emits the file/repo asset
list ready to replay into `assets.mark`.

## 5. Reporting: `findings.report`

File only **verified** issues. Load the **`finding-report`** skill for the
full pack; example call shape:

```
findings.report(
  title="Command injection via unvalidated job name in runner (gosec G204)",
  severity="high",
  cwe="CWE-78",
  asset="git.example.com/example/app",
  location="internal/runner/exec.go:42",
  evidence="exec.Command(\"sh\", \"-c\", userCmd) — userCmd originates from "
           "POST /api/jobs 'name' field (handlers/jobs.go:88) with no "
           "sanitization; confirmed by tracing handler -> queue -> runner.",
  reproduction="POST /api/jobs name='x; id' against staging at 203.0.113.10 "
               "executes id in the runner container.",
  tool="gosec",
  rule="G204"
)
```

## 6. SARIF handoff

Send `/work/out/gosec.sarif` to the **`sarif-triage`** skill to merge/dedupe
with semgrep and codeql SARIF for the same repo before fan-out, when multiple
scanners run — triage once over the merged set, not per tool.
