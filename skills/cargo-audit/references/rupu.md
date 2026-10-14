# rupu wiring for cargo-audit output

How to plug the cargo-audit work-unit array into rupu. Splitting is owned by
the shared `work-units` skill; reporting by the `finding-report` skill — load
both BY NAME from your steps; do not re-implement them.

## 1. Produce the work-unit array

```sh
python3 scripts/run_cargo_audit.py /work/example-service \
        --out audit.json --workunits workunits.json
```

`workunits.json` is a clean top-level JSON array — rupu's `for_each:`
JSON-parses any value starting with `[`. No wrapper object, no prose.

## 2. Workflow: `read_file` + `for_each:` over the array

```yaml
steps:
  - id: audit
    run: >
      python3 skills/cargo-audit/scripts/run_cargo_audit.py /work/example-service
      --out audit.json --workunits workunits.json

  - id: load_units
    tool: read_file
    args:
      path: workunits.json

  - id: triage_unit
    for_each: "{{ steps.load_units.output }}"   # parsed as JSON array
    prompt: |
      Load the `work-units` skill. You are verifying one RustSec finding:
        crate:    {{ item.targets[0] }}
        advisory: {{ item.hints.rustsec }} ({{ item.hints.cve }})
        kind:     {{ item.hints.kind }}   severity: {{ item.hints.severity }}
        patched:  {{ item.hints.patched }}
      In /work/example-service: run `cargo tree -i {{ item.targets[0] }}` to
      recover the dependency path, grep the codebase for the affected
      functions listed in the advisory, confirm the enabling feature flags,
      and demonstrate the vulnerable behavior against the built artifact.
      Then load the `finding-report` skill and file the result with
      findings.report.
```

## 3. Lead-agent fan-out with `dispatch`

```text
units = json.parse(read_file("workunits.json"))
for unit in units:
    dispatch(
      agent="code-review-worker",
      skill_hints=["cargo-audit", "work-units", "finding-report"],
      payload=unit,
      title=unit["title"],
    )
```

One unit per worker; each worker loads `work-units` to interpret the unit
and `finding-report` to file verified issues.

## 4. Coverage: `assets.mark`

Mark the repo, every lockfile audited, and the crate packages. The full
package inventory comes from `Cargo.lock` itself (every `[[package]]`
entry); `lockfile.dependency-count` in audit.json is the sanity check.

```text
assets.mark(kind="repository", id="example-service",
            attrs={"vcs": "git", "tool": "cargo-audit"})

assets.mark(kind="file", id="example-service:Cargo.lock",
            attrs={"scanner": "cargo-audit",
                   "dependency_count": "312",
                   "db_last_commit": "<database.last-commit>"})

assets.mark(kind="package", id="cargo:openssl@0.10.54",
            attrs={"source": "crates.io", "scanner": "cargo-audit",
                   "status": "vulnerable", "advisory": "RUSTSEC-2023-0044"})

assets.mark(kind="package", id="cargo:serde@1.0.193",
            attrs={"source": "crates.io", "scanner": "cargo-audit",
                   "status": "clean"})
```

For `cargo audit bin` runs, mark the binary too:
`assets.mark(kind="binary", id="example-service:/opt/example/bin/ingestd", attrs={"scanner": "cargo-audit", "audit_info": "embedded"})`.

## 5. Reporting: `findings.report` (via the `finding-report` skill)

For each VERIFIED vulnerable crate, load the `finding-report` skill and file:

```text
findings.report(
  title="Vulnerable crate: openssl 0.10.54 (RUSTSEC-2023-0044 / CVE-2023-0044) — X509VerifyParamRef::set_host over-read",
  asset="cargo:openssl@0.10.54",
  severity="high",
  cwe="CWE-125",
  evidence={
    "rustsec": "RUSTSEC-2023-0044",
    "aliases": ["CVE-2023-0044", "GHSA-xcf7-rvmh-g6q4"],
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "lockfile": "example-service/Cargo.lock",
    "dependency_path": "example-service -> native-tls 0.2.11 -> openssl 0.10.54",
    "reachability": "src/tls.rs:88 calls set_host() with client-supplied SNI",
    "poc": "oversized hostname triggers over-read; crash reproduced against staging build"
  },
  remediation="Upgrade openssl crate to >=0.10.55 (cargo update -p openssl); rebuild and re-run cargo audit to confirm."
)
```

File `unmaintained` / `unsound` / `yanked` warnings as lower-severity
supply-chain findings with `kind` in the evidence; keep severity from CVSS
when present, else map vulnerability=medium-floor, warnings=low unless
reachability analysis raises it.

— vulture (fuchsia-pavilion)
