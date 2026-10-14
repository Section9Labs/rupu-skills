---
name: trufflehog
description: Find AND live-verify leaked credentials with TruffleHog v3 — 800+ detectors that call each provider's API to confirm a secret is active; scan git history, GitHub orgs, filesystems, S3/GCS buckets and Docker images; use whenever you need to know which leaked keys actually work, and to confirm hits from the gitleaks skill. Normalizes JSONL output into rupu work units.
license: MIT
metadata:
  author: Section9Labs
  tool: trufflehog
  tool_min_version: "3.63"
---

# TruffleHog v3 — secret detection with LIVE verification

TruffleHog's differentiator over regex-only scanners is **verification**: for
each detected credential it calls the provider's own API (AWS STS
`GetCallerIdentity`, GitHub `/user`, Stripe, Slack `auth.test`, ...) and
reports `Verified: true` only if the credential is **live right now**. That
turns "a string that looks like a key" into "an active credential with
provable impact". The complementary **`gitleaks`** skill is the fast
regex/entropy pass over full history — run gitleaks for breadth, trufflehog
to verify and for its extra sources (GitHub org, S3, Docker).

## Sources (subcommands)

```sh
trufflehog git file:///tmp/app.git                      # local repo, full history
trufflehog git https://github.com/example/app.git       # remote repo (clones it)
trufflehog github --org=example --token=$GITHUB_TOKEN   # every repo in an org
trufflehog github --repo=https://github.com/example/app --issue-comments --pr-comments
trufflehog filesystem /srv/code /etc/app.env            # files/dirs, no git needed
trufflehog s3 --bucket=example-backups                  # S3 bucket objects
trufflehog gcs --project-id=example-prod                # GCS buckets
trufflehog docker --image=example.com/app:latest        # image layers incl. deleted files
trufflehog stdin < dump.txt                             # piped content
trufflehog syslog --address=192.0.2.10:514 --protocol=tcp
```

Full per-source flag tables: `references/sources.md`. The `git` source
scans **every commit on every branch** — secrets deleted from HEAD are found.

## Verification flags — the core workflow

```sh
# everything the detectors match, with live verification attempted (default)
trufflehog git file:///tmp/app.git --json > all.jsonl

# only credentials confirmed live (newer syntax; older: --only-verified)
trufflehog git file:///tmp/app.git --results=verified --json > verified.jsonl

# live + indeterminate (provider unreachable/ratelimited/ambiguous) — recommended
trufflehog git file:///tmp/app.git --results=verified,unknown --json --fail > tri.jsonl
echo $?   # 183 = at least one verified secret found (with --fail); 0 otherwise
```

- `--results=verified,unknown,unverified,filtered_unverified` — choose which
  classes to emit. `verified` = provider confirmed live. `unknown` =
  verification errored (network, 429, non-definitive response) — treat as
  possibly live. `unverified` = provider said invalid, or no verifier exists.
- `--only-verified` — deprecated alias for `--results=verified`.
- `--fail` + exit code **183**: gate pipelines on verified secrets.
- **Scan both ways.** `--results=verified` slashes false positives to ~zero,
  but misses revoked-yet-sensitive keys (a rotated AWS key still proves the
  leak path and may recur) and detectors without verifiers. Do a verified
  pass for immediate-impact findings, and a full pass for the complete leak
  inventory. Details: `references/verification.md`.

## Other key flags

- `--json` — one JSON object **per line** (JSONL, not an array); parse with
  the script below. `--json-legacy` for the v2 format (git only).
- `--no-update` — skip self-update (always set in automation).
- `--concurrency N` — worker count (default = CPUs; raise for I/O-bound
  sources, lower to avoid tripping provider rate limits during verification).
- `--no-verification` — detection only, no provider calls (quiet mode when
  outbound traffic from the scan host is unwanted).
- `--since-commit <sha>` / `--branch <name>` (git) — incremental scans.
- `-x, --exclude-paths exclude.txt` / `-i, --include-paths` — newline-
  separated regex files to skip vendored noise.
- `--archive-max-size=100MB --archive-max-depth=8 --archive-timeout=5m` —
  nested archive extraction limits (trufflehog descends into zips/tars).
- `--include-detectors="aws,github,stripe"` / `--exclude-detectors` — detector
  filter by name/ID.
- `--config custom.yml` — custom regex detectors with optional webhook
  verification (see `references/sources.md`).
- `--verifier URL --custom-verifiers-only` — route verification through your
  own endpoint.

## 800+ detectors & custom detectors

Built-in detectors cover AWS/GCP/Azure, GitHub/GitLab/Bitbucket, Stripe,
Slack, Twilio, SendGrid, OpenAI, databases (Postgres/MySQL/Mongo URIs —
verified by actually connecting), JWTs, private keys, and hundreds more.
Custom regex detectors go in a YAML config:

```yaml
# custom.yml
detectors:
  - name: examplecorp-token
    keywords: [excorp_]
    regex:
      token: 'excorp_(?:live|test)_[a-z0-9]{32}'
    verify:
      - endpoint: https://auth.example.com/api/verify   # optional live check
        unsafe: false
        headers: ["Authorization: Bearer {token}"]
```

Run with `trufflehog filesystem /srv/code --config custom.yml --json`.

## Reading the JSON output

One object per finding, one per line. Key fields:

- `DetectorName` / `DetectorType` — which detector (e.g. `AWS`, `Github`)
- `Verified` — boolean; `VerificationError` — why verification was `unknown`
- `Raw` / `RawV2` — the secret (RawV2 includes bound context like username);
  `Redacted` — safe display form
- `SourceMetadata.Data.Git` — `file`, `line`, `commit`, `email`, `timestamp`,
  `repository`; `.Filesystem` — `file`, `line`; other sources analogous
- `ExtraData` — provider enrichment: AWS account ID + ARN, GitHub username +
  token scopes, Slack team — **this is your blast-radius evidence**, quote it
  in the finding.

## Workflow

1. Run the source (git for repos — mirror-clone first so all refs are local):
   `python3 scripts/run_trufflehog.py git file:///tmp/app.git --out-dir out/`
   (runs `--json --results=verified,unknown --fail --no-update` and parses).
   Optionally a second full pass: add `--results all`.
2. Normalize JSONL to work units:
   `python3 scripts/trufflehog_to_workunits.py out/trufflehog.jsonl -o out/workunits.json`
   — clean top-level JSON array, raw secrets redacted, verified hits sorted
   first.
3. Mark the repo / files / buckets scanned with `assets.mark`
   (wiring in `references/rupu.md`).
4. **Load the `work-units` skill** to split `out/workunits.json` into
   per-secret work units for rupu `for_each:` / lead-agent `dispatch`.
5. For each unit: `verified: true` units go straight to reporting with the
   `ExtraData` blast radius; `unknown` units get re-verified (rerun that one
   detector, or exercise the credential directly against the provider);
   `unverified` units from a full pass are cross-checked against the
   **`gitleaks`** skill output and triaged by context.
6. **Load the `finding-report` skill** and file each verified secret via
   `findings.report` — detector, file:line@commit, verification evidence,
   account/scope from `ExtraData`.

## References

- `references/sources.md` — every source with its full flag set, custom detectors
- `references/verification.md` — verification mechanics, verified/unknown/
  unverified semantics, exit 183 gating, rate limits and tokens
- `references/rupu.md` — rupu workflow YAML, `dispatch` fan-out,
  `assets.mark` / `findings.report` examples
