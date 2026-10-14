# code-review — full narrative flow with exact commands

This is the command-level walkthrough behind the routing map in SKILL.md.
Example repo path throughout: a checkout of `https://git.example.com/example/app.git`
in `./app`. All artifacts land in `./out/`.

```
mkdir -p out/sarif out/native
cd app
```

## PHASE 0 — Profile

```
python3 ../skills/code-review/scripts/profile_repo.py . -o ../out/repo-profile.json
python3 ../skills/code-review/scripts/plan_review.py ../out/repo-profile.json -o ../out/plan.json
```

Cross-check the census if counters are installed (any one of):

```
scc --format json . > ../out/scc.json
tokei -o json . > ../out/tokei.json
cloc --json . > ../out/cloc.json
```

Read `repo-profile.json`:
- `languages` sorted by LOC — the biggest languages drive the SAST routing.
- `manifests`/`ecosystems` drive the SCA routing.
- `entry_points` with reasons like `http-route`, `deserialization`, `raw-sql`,
  `command-exec`, `auth-logic` are your taint-phase targets and trust boundaries.

Mark the repo asset immediately (`assets.mark`, see `rupu.md`).

## PHASE 1 — SAST

**semgrep** (load the `semgrep` skill for ruleset depth and custom rules):

```
semgrep scan --config p/default --config p/security-audit --config p/owasp-top-ten \
  --sarif --output ../out/sarif/semgrep.sarif .
# add per-language packs from the profile, e.g. --config p/python --config p/javascript
```

**codeql** (load the `codeql` skill) on high-value targets:

```
codeql database create ../out/cqldb --language=python --source-root .
codeql database analyze ../out/cqldb codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output ../out/sarif/codeql.sarif
```

**Language linters** (load each named skill):

```
bandit -r . -f sarif -o ../out/sarif/bandit.sarif          # python
gosec -fmt sarif -out ../out/sarif/gosec.sarif ./...       # go
brakeman -o ../out/sarif/brakeman.sarif -f sarif .         # rails
njsscan --sarif -o ../out/sarif/njsscan.sarif .            # node/js
# find-sec-bugs: build first, then spotbugs + findsecbugs plugin, sarif output
spotbugs -textui -pluginList findsecbugs-plugin.jar -sarif:../out/sarif/fsb.sarif target/classes
```

Hand each SARIF file to the `sarif-triage` skill as it lands (or batch them in
Phase 5 — both work; batching dedups better).

## PHASE 2 — Secrets

Load the `gitleaks` and `trufflehog` skills. Scan history AND worktree:

```
gitleaks git  --report-format sarif --report-path ../out/sarif/gitleaks-git.sarif .
gitleaks dir  --report-format json  --report-path ../out/native/gitleaks-dir.json .
trufflehog git file://. --json > ../out/native/trufflehog.json
trufflehog filesystem . --json >> ../out/native/trufflehog.json
```

trufflehog entries with `"Verified": true` are live credentials — file them
immediately via the `finding-report` skill at high/critical with the detector
name, commit, and file:line; don't wait for Phase 5.

## PHASE 3 — SCA + SBOM

Load `grype-syft`, `osv-scanner`, and the ecosystem-specific skills:

```
syft dir:. -o cyclonedx-json=../out/native/sbom.cdx.json
grype sbom:../out/native/sbom.cdx.json -o sarif > ../out/sarif/grype.sarif
osv-scanner scan source -r . --format sarif --output ../out/sarif/osv.sarif
dependency-check --scan . --format SARIF --out ../out/sarif/   # maven/gradle/nuget present
retire --path . --outputformat json --outputpath ../out/native/retire.json
cargo audit --json > ../out/native/cargo-audit.json            # Cargo.lock present
```

`assets.mark` every package named in `sbom.cdx.json` (`components[].purl`) —
the SBOM is the authoritative dependency inventory.

During verification, prefer reachable vulnerabilities: grep the codebase for
imports/calls into the vulnerable package before ranking.

## PHASE 4 — Taint

Load the `taint-analysis` skill. Inputs: `repo-profile.json: entry_points`
(sources) and the per-language sink packs from that skill. Core loop:

1. Pick a source class (e.g. all `http-route` files).
2. Run the skill's semgrep taint-mode rules and ripgrep sink patterns scoped to
   those files and everything they import.
3. For each hit, walk the dataflow by hand in the source: source → transforms →
   sanitizers (or lack of) → sink. Record the full path.
4. Confirmed paths become findings; ambiguous ones become work units with the
   partial trace in `hints.trace`.

Target classes: SQLi, command injection, LDAP injection, SSTI, insecure
deserialization, SSRF, path traversal, IDOR/missing authz, crypto misuse,
hardcoded secrets.

## PHASE 5 — Triage, verify, report

1. Load the `sarif-triage` skill; feed it `out/sarif/*.sarif` and
   `out/native/*.json`. Output: one deduplicated, severity-ranked finding set.
2. Load the `work-units` skill; split that set into `out/work-units.json`
   (clean top-level JSON array). This is THE fan-out artifact.
3. Fan out (rupu `read_file` + `for_each:` or lead `dispatch` — see `rupu.md`).
   Each worker: open the code, confirm exploitability, build a PoC input,
   or discard with a reason.
4. Load the `finding-report` skill; `findings.report` each verified issue.
5. Final `assets.mark` sweep: repo, scanned files/modules, SBOM packages.

## Artifact checklist

| Artifact | Produced by | Consumed by |
|---|---|---|
| `out/repo-profile.json` | profile_repo.py | plan_review.py, taint phase |
| `out/plan.json` | plan_review.py | rupu for_each / dispatch |
| `out/sarif/*.sarif` | all SAST/SCA/secret tools | sarif-triage |
| `out/native/*.json` | trufflehog, retire, cargo-audit, syft | sarif-triage, assets.mark |
| `out/work-units.json` | work-units skill | rupu for_each / dispatch |
