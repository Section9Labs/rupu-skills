---
name: cargo-audit
description: Audit Rust projects with cargo-audit (RustSec) by checking Cargo.lock — or compiled binaries via `cargo audit bin` — against the RustSec Advisory Database for vulnerable, unmaintained, unsound, and yanked crates, then normalize results into rupu work units for triage, verification, and reporting.
license: MIT
metadata:
  author: Section9Labs
---

# cargo-audit — RustSec dependency auditor

cargo-audit resolves the exact crate versions pinned in `Cargo.lock` against
the RustSec Advisory Database (https://github.com/rustsec/advisory-db). It is
the ecosystem-native SCA tool for Rust: RustSec advisories carry Rust-specific
metadata (affected functions, feature flags, patched versions) that generic
scanners flatten or miss.

## 1. Install

```sh
cargo install cargo-audit --locked
cargo audit --version
```

The advisory DB is fetched/updated automatically into
`~/.cargo/advisory-db` on each run (skip with `-n`/`--no-fetch`).

## 2. Run the audit

From the crate/workspace root (where `Cargo.lock` lives):

```sh
cargo audit                 # human-readable
cargo audit --json > audit.json   # machine output (one JSON doc on stdout)
```

Key flags (full table in `references/cli.md`):

- `-f, --file <path>/Cargo.lock` — audit a specific lockfile without cd'ing
  into the project; essential when sweeping a monorepo with multiple
  workspaces: `cargo audit --json -f services/auth/Cargo.lock`.
- `-d, --db <dir>` — alternate advisory-db checkout (air-gapped mirror or a
  pinned snapshot for reproducible audits); `--url <repo>` to fetch from a
  mirror.
- `-n, --no-fetch` — offline mode, use the already-cloned DB as-is.
- `--stale` — proceed even if the local DB copy is outdated (pair with
  `--no-fetch` on disconnected hosts).
- `--ignore RUSTSEC-2021-0001` — waive a specific advisory (repeatable).
- `-D, --deny warnings|unmaintained|unsound|yanked` — escalate warning
  classes to errors (repeatable). `--deny warnings` makes *every* warning
  fail the run.
- No `Cargo.lock`? Generate one first: `cargo generate-lockfile` (uses
  `Cargo.toml` constraints; commit the real lockfile when possible so the
  audit reflects the shipped resolution).

Exit code is **non-zero when vulnerabilities (or denied warning classes) are
found**, zero when clean.

## 3. Advisory kinds

| Kind | Meaning | Default handling |
|---|---|---|
| **vulnerability** | Security flaw with a RUSTSEC id (often CVE/GHSA aliases) | error |
| **unmaintained** | Crate abandoned by its maintainers — supply-chain risk | warning |
| **unsound** | API allows UB/memory-unsafety from safe Rust | warning |
| **yanked** | Exact pinned version was yanked from crates.io | warning |

## 4. Audit compiled binaries

`cargo audit bin` audits binaries built with
[`cargo auditable`](https://github.com/rust-secure-code/cargo-auditable),
which embeds the full dependency list (audit-info) into the executable:

```sh
cargo audit bin target/release/example-server /opt/vendor/bin/*
```

For binaries built *without* cargo-auditable it falls back to recovering
crate names/versions from panic/debug strings (less complete — treat results
as a lower bound). Use this to audit third-party Rust binaries on target
hosts, shipped appliances, and release artifacts where you have no source.

For CI *policy gating* beyond auditing (license checks, source allowlists,
ban lists), the superset tool is `cargo deny` — see `references/cli.md`.

## 5. Read the output

Text output per vulnerability: `Crate`, `Version`, `Title`, `Date`, `ID`
(RUSTSEC-YYYY-NNNN), `URL`, `Severity`/CVSS, `Solution` (patched versions,
e.g. `upgrade to >=0.21.3`), and the **dependency tree** showing the path
from your workspace crates down to the vulnerable crate — use that path to
find which of *your* code pulls it in and whether the vulnerable API is
reachable.

JSON (`--json`) structure:

- `vulnerabilities.list[]` — each with `advisory` (`id`, `title`,
  `description`, `aliases` → CVE/GHSA, `cvss` vector, `categories`,
  `keywords`), `versions.patched[]` / `versions.unaffected[]`, `affected`
  (functions/platforms/features — crucial for reachability triage), and
  `package` (`name`, `version`, `source`).
- `warnings` — map of kind (`unmaintained`, `unsound`, `yanked`) to entries
  with `package` and (where applicable) `advisory`.
- `lockfile.dependency-count` — total crates audited (record for coverage).

Verification workflow per finding: check `affected.functions` against the
codebase (`grep -rn 'vulnerable_fn' src/`), check whether the crate is a
direct or transitive dep (`cargo tree -i <crate>@<version>`), confirm the
feature flags enabling the vulnerable code are on, then demonstrate the
impact (e.g. craft the malformed input that triggers the parser overflow,
the decompression bomb, the TLS verification bypass) against the built
service.

## 6. Normalize → work units → fan-out (rupu)

Helper scripts (Python 3 stdlib):

```sh
# one-shot: run cargo audit --json + emit work units
python3 scripts/run_cargo_audit.py /work/example-service \
        --out audit.json --workunits workunits.json

# or parse an existing JSON report
python3 scripts/cargoaudit_to_workunits.py audit.json -o workunits.json
```

`workunits.json` is a **clean top-level JSON array**:

```json
[{"id": "cargoaudit-9b1e22ab", "title": "openssl@0.10.54 — RUSTSEC-2023-0044",
  "targets": ["openssl@0.10.54"],
  "hints": {"rustsec": "RUSTSEC-2023-0044", "cve": "CVE-2023-0044",
            "severity": "high", "cvss": "CVSS:3.1/AV:N/...",
            "patched": [">=0.10.55"], "kind": "vulnerability"}}]
```

Handoff:

1. Load the `work-units` skill to split/shape the normalized findings into
   work units (do not re-invent the splitter).
2. `assets.mark` the repository, each audited `Cargo.lock`, and every crate
   package (vulnerable or not — use `lockfile.dependency-count` plus the
   lockfile itself for the full inventory).
3. Fan out: rupu workflow consumes `workunits.json` via `read_file` +
   `for_each:`; a lead agent dispatches one unit per worker. Concrete YAML,
   `dispatch` pattern, and `assets.mark`/`findings.report` examples:
   `references/rupu.md`.
4. For each **verified** vulnerable crate, load the `finding-report` skill
   and file it with `findings.report` (crate@version, RUSTSEC id + CVE
   aliases, CVSS, dependency path, reachability evidence, patched version).

## 7. Where cargo-audit fits in the SCA step

cargo-audit is the Rust-native source of truth. For cross-ecosystem sweeps
of the same repo, `osv-scanner` also reads `Cargo.lock` (OSV mirrors RustSec)
and `grype-syft` covers Rust binaries in container images — expect overlap;
RustSec metadata (affected functions, unsound/unmaintained classes) is the
differentiator that makes cargo-audit worth running directly.

— vulture (fuchsia-pavilion)
