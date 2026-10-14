# cargo-audit CLI reference

## `cargo audit` flags

| Flag | Meaning |
|---|---|
| `-f, --file <path>` | Path to a `Cargo.lock` to audit (default: `./Cargo.lock`). Lets you sweep many lockfiles without changing directory. |
| `--json` | Emit the full report as a single JSON document on stdout. |
| `-d, --db <dir>` | Advisory database directory (default `~/.cargo/advisory-db`). Point at a pinned/air-gapped checkout of https://github.com/rustsec/advisory-db for reproducible or offline audits. |
| `-u, --url <url>` | Git URL to fetch the advisory DB from (mirror). |
| `-n, --no-fetch` | Do not fetch/update the advisory DB (offline mode). |
| `--stale` | Allow using an advisory DB whose last commit is older than the staleness window instead of erroring. |
| `--ignore <RUSTSEC-ID>` | Waive a specific advisory, e.g. `--ignore RUSTSEC-2021-0001`. Repeatable. |
| `-D, --deny <class>` | Treat a warning class as an error: `warnings` (all), `unmaintained`, `unsound`, `yanked`. Repeatable, e.g. `-D unsound -D yanked`. |
| `--target-arch <arch>` / `--target-os <os>` | Only report advisories affecting the given platform (uses advisory `affected.arch`/`affected.os`). |
| `-q, --quiet` | Suppress non-error output. |
| `-c, --color <when>` | `auto`/`always`/`never`. |
| `--ignore-source` | Ignore advisories' source (registry) matching requirements. |

Persistent configuration lives in `~/.cargo/audit.toml` (or
`.cargo/audit.toml` in the project): `[advisories] ignore = [...]`,
`informational_warnings = ["unmaintained", "unsound"]`, `[output] deny = [...]`,
`[database] path/url/fetch/stale`, `[target] arch/os`.

## `cargo audit bin`

```sh
cargo audit bin [FLAGS] <binary>...
```

Audits compiled executables:

1. **audit-info path (preferred):** binaries built with `cargo auditable
   build --release` carry a compressed JSON dependency manifest in a
   dedicated section (`.dep-v0`). `cargo audit bin` reads it and audits the
   exact dependency set — same fidelity as a lockfile audit, no source
   needed.
2. **Fallback:** for ordinary binaries it recovers crate names/versions from
   panic messages and debug metadata. Incomplete by design — report it as a
   lower bound and say so in findings.

Same DB/ignore/deny flags apply. Use it on vendor appliances, release
artifacts, and anything found on target hosts
(`cargo audit bin /opt/example/bin/ingestd --json`).

## Warning / deny classes

| Class | Trigger | Why it matters offensively |
|---|---|---|
| `vulnerability` | RUSTSEC vulnerability advisory matches a pinned version | Direct exploit candidates; check `affected.functions` for reachability. |
| `unmaintained` | Crate flagged abandoned | Supply-chain pivot: no patches coming; known bugs stay exploitable; typosquat/successor confusion risk. |
| `unsound` | Safe API can cause UB | Memory-safety primitives reachable from "safe" app code — overflow/UAF building blocks. |
| `yanked` | Pinned version yanked from crates.io | Often yanked *because* of a serious bug; investigate the yank reason. |

Vulnerabilities always fail the run; warnings fail only under `--deny`.

## Advisory database

- Repo: `https://github.com/rustsec/advisory-db` — one TOML/Markdown advisory
  per `RUSTSEC-YYYY-NNNN` under `crates/<name>/`.
- Advisory fields worth reading during triage: `aliases` (CVE-*/GHSA-*),
  `cvss` (v3.x vector), `patched`/`unaffected` version requirements,
  `affected.functions` (fully-qualified paths of vulnerable functions),
  `affected.features` (only vulnerable with these cargo features enabled),
  `affected.os`/`affected.arch`, `informational = "unmaintained"|"unsound"|"notice"`.
- Pin a snapshot for repeatable engagement results:
  `git clone https://github.com/rustsec/advisory-db ~/advisory-db && git -C ~/advisory-db checkout <commit>`,
  then `cargo audit -n -d ~/advisory-db`.

## `cargo audit --json` anatomy

```json
{
  "database": {"advisory-count": 700, "last-commit": "...", "last-updated": "..."},
  "lockfile": {"dependency-count": 312},
  "settings": {"ignore": [], "severity": null},
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2023-0044",
          "package": "openssl",
          "title": "`openssl` X509VerifyParamRef::set_host buffer over-read",
          "description": "...",
          "date": "2023-06-22",
          "aliases": ["CVE-2023-0044", "GHSA-xcf7-rvmh-g6q4"],
          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
          "categories": ["memory-corruption"],
          "keywords": [],
          "url": "https://github.com/sfackler/rust-openssl/issues/..."
        },
        "versions": {"patched": [">=0.10.55"], "unaffected": []},
        "affected": {"functions": {"openssl::x509::verify::X509VerifyParamRef::set_host": ["<0.10.55"]}},
        "package": {"name": "openssl", "version": "0.10.54",
                    "source": "registry+https://github.com/rust-lang/crates.io-index"}
      }
    ]
  },
  "warnings": {
    "unmaintained": [
      {"kind": "unmaintained",
       "package": {"name": "net2", "version": "0.2.39"},
       "advisory": {"id": "RUSTSEC-2020-0016", "title": "`net2` crate has been deprecated", "aliases": []}}
    ],
    "yanked": [
      {"kind": "yanked", "package": {"name": "quale", "version": "1.0.0"}}
    ]
  }
}
```

Note: the JSON does **not** include the rendered dependency tree — recover
the path with `cargo tree -i openssl@0.10.54` in the workspace, or read the
text-mode output.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities and no denied warning classes. |
| `1` | Vulnerabilities found, or warnings escalated via `--deny`. |
| `2` | Usage/IO/DB error. |

## `cargo deny` (policy-gate superset)

`cargo install cargo-deny` → `cargo deny check advisories` covers the same
RustSec data, but adds `check bans` (duplicate/banned crates),
`check licenses`, and `check sources` (registry/git allow-lists) driven by a
`deny.toml` policy file. Use cargo-deny when the engagement needs a full
supply-chain policy verdict; use cargo-audit (this skill) for advisory-focused
auditing and the `bin` capability, which cargo-deny lacks.

— vulture (fuchsia-pavilion)
