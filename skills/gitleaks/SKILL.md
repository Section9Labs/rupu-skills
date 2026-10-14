---
name: gitleaks
description: Scan git history and filesystems for hardcoded secrets with Gitleaks v8+ (fast regex + entropy over every commit); use at the start of any code review / SAST pass to find leaked credentials, API keys, tokens and private keys, then hand verified hits to the finding-report flow. Pair with the trufflehog skill for live credential verification.
license: Apache-2.0
metadata:
  author: Section9Labs
  tool: gitleaks
  tool_min_version: "8.19"
---

# Gitleaks — hardcoded secret scanning over git history

Gitleaks is the fast first-pass secret scanner: hundreds of provider-specific
regex rules plus Shannon-entropy checks, run over **every blob in every
commit** of a repository. It does NOT verify credentials against provider
APIs — that is the complementary **`trufflehog`** skill (load it to confirm
which of Gitleaks' hits are live). Run gitleaks first (it is fast and
exhaustive on history), then trufflehog on the same target to verify.

## Commands (v8.19+)

The modern subcommands replace the deprecated `detect`/`protect` (those still
work but are hidden):

| Command | Scans | Replaces |
|---|---|---|
| `gitleaks git <repo>` | full commit history of a git repo (local path or already-cloned) | `gitleaks detect` |
| `gitleaks dir <path>` | files on disk, no git metadata (works on non-repos, extracted archives, build output) | `gitleaks detect --no-git` |
| `gitleaks stdin` | piped content (e.g. `cat config.yml \| gitleaks stdin`) | `gitleaks detect --pipe` |

**Exit codes:** `0` = no leaks, `1` = leaks found, `126` = unexpected error.
Treat exit 1 as *success with findings* in automation.

## Core invocations

Full-history scan with both machine formats:

```sh
git clone --mirror https://example.com/org/app.git /tmp/app.git
gitleaks git /tmp/app.git --report-format json  --report-path gitleaks.json -v
gitleaks git /tmp/app.git --report-format sarif --report-path gitleaks.sarif
```

Only commits new since a known-clean baseline ref (incremental / PR scan),
via `--log-opts` which passes arguments straight to `git log -p`:

```sh
gitleaks git /tmp/app.git --log-opts="origin/main..HEAD" --report-format json --report-path new.json
gitleaks git /tmp/app.git --log-opts="--since=2024-01-01 --all"      # time-bounded, all refs
gitleaks git /tmp/app.git --log-opts="--all --full-history"          # every ref incl. deleted branches
```

Filesystem (no git) — vendor drops, container layers, backup dumps:

```sh
gitleaks dir /srv/extracted-image --report-format json --report-path dir.json \
  --max-target-megabytes 50
```

Other key flags (full list in `references/cli.md`):

- `--report-format {json,sarif,csv,junit}` and `--report-path <file>`
- `-v` / `--verbose` — print each finding to stderr as found
- `--redact` / `--redact=80` — redact (fully or N%) the secret in output; use
  when the report will be stored or shipped
- `--baseline-path old.json` — suppress findings already present in a prior
  JSON report (only report NEW leaks)
- `-c, --config gitleaks.toml` — custom ruleset (see `references/rules.md`)
- `--max-target-megabytes N` — skip huge blobs (minified JS, lockfiles, binaries)
- `--exit-code N` — change the leaks-found exit code
- `--no-banner`, `--log-level debug`

## Why full history matters

A secret committed once and "removed" in a later commit is still in every
clone's object store (`git log -p`, `git show <commit>:<path>` recover it).
Rotation, not deletion, is the only fix. Always run `gitleaks git` on the
full history (and `--log-opts="--all"` to catch deleted branches and tags),
not just `gitleaks dir` on the working tree. Scan the working tree too
(`gitleaks dir`) to catch untracked/ignored files — `.env`, `*.pem`,
`terraform.tfstate` — which `git` mode never sees.

## Rules

The default embedded ruleset covers hundreds of providers: AWS access keys,
GCP service-account keys, Azure, GitHub/GitLab PATs (`ghp_`, `gho_`,
`glpat-`), Stripe, Slack tokens/webhooks, Twilio, SendGrid, PKCS/OpenSSH/PGP
private key blocks, JWTs, database connection strings, and generic
`api[_-]?key` / high-entropy assignments. Write custom rules in
`.gitleaks.toml` (regex + `entropy` threshold + `allowlist` of paths, regexes
and stopwords; `[extend] useDefault = true` to layer on the defaults).
Inline `# gitleaks:allow` on a line suppresses that line. Full TOML grammar
and recipes: `references/rules.md`. When reviewing a codebase, check its
committed `.gitleaks.toml` for over-broad allowlists — a path allowlist on
`config/` is itself a finding.

## Reading a finding

Each JSON finding (top-level array) has:

- `RuleID` — which rule fired (`aws-access-token`, `generic-api-key`, ...)
- `File`, `StartLine`/`EndLine`, `StartColumn`/`EndColumn`
- `Commit`, `Author`, `Email`, `Date`, `Message` — where it entered history
  (empty in `dir` mode)
- `Secret` — the captured secret; `Match` — the full matched line
- `Entropy` — Shannon entropy of the secret; `Fingerprint` — stable ID
  (`commit:file:rule:line`), used by `--baseline-path`

Triage order: provider-specific rules (near-zero FP rate) → private keys →
JWTs (decode the payload, check `exp`) → `generic-api-key` sorted by entropy
descending (entropy > 4.5 is rarely noise; placeholder values like
`CHANGEME`/`xxxx` sit low).

## Workflow

1. Mirror-clone the target, run `gitleaks git` (full history, `--log-opts="--all"`)
   and `gitleaks dir` on a working-tree checkout. Use
   `python3 scripts/run_gitleaks.py --mode git /tmp/app.git --out-dir out/`
   to do both report formats and parse in one step.
2. Normalize to work units:
   `python3 scripts/gitleaks_to_workunits.py gitleaks.json -o workunits.json`
   (accepts gitleaks native JSON and/or SARIF; emits a clean top-level JSON
   array; secret values are redacted in hints).
3. Mark the repo and scanned files as covered assets with `assets.mark`
   (wiring in `references/rupu.md`).
4. **Load the `work-units` skill** to split `workunits.json` into per-finding
   work units and fan out (rupu `for_each:` / lead-agent `dispatch`).
5. For each unit: confirm the secret is real (not a test fixture or
   placeholder), recover it from history (`git show <commit>:<file>`), and
   **load the `trufflehog` skill** to live-verify the credential type.
6. **Load the `finding-report` skill** to file every verified secret via
   `findings.report` — include rule, commit, author, file:line, verification
   status, and blast radius of the credential.

## References

- `references/cli.md` — every flag, `--log-opts` recipes, baseline workflow
- `references/rules.md` — default rule coverage, custom TOML, allowlisting
- `references/rupu.md` — rupu workflow YAML, `dispatch`, `assets.mark`,
  `findings.report` examples for gitleaks output
