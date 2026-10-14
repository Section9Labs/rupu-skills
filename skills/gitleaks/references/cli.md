# Gitleaks CLI reference (v8.19+)

## Subcommands

```
gitleaks git <repo-path>      # scan git history (replaces: gitleaks detect)
gitleaks dir <path>...        # scan files/dirs, no git (replaces: detect --no-git)
gitleaks stdin                # scan piped input (replaces: detect --pipe)
gitleaks detect / protect     # deprecated, hidden, still functional
gitleaks version / completion
```

`gitleaks git` with no argument scans the current directory's repo.
`gitleaks dir` accepts multiple paths and follows the directory tree.

## Global flags

| Flag | Meaning |
|---|---|
| `-c, --config <file>` | custom TOML ruleset. Resolution order: `--config` → `$GITLEAKS_CONFIG` → `<repo>/.gitleaks.toml` → embedded default |
| `-v, --verbose` | print findings live to stderr |
| `--report-format <fmt>` | `json` (default when path given), `sarif`, `csv`, `junit`, `template` |
| `-r, --report-path <file>` | write report here (`-` is not supported; omit for no report) |
| `--report-template <tmpl>` | Go template for `--report-format template` |
| `--redact[=N]` | redact secrets in report/stdout; optional percentage `--redact=80` keeps a 20% prefix for triage |
| `-b, --baseline-path <json>` | prior gitleaks JSON report; findings whose `Fingerprint` matches are suppressed |
| `--exit-code <n>` | code to return when leaks found (default 1) |
| `--max-target-megabytes <n>` | skip files/blobs larger than N MB (0 = no limit) |
| `--max-decode-depth <n>` | recursively decode base64/hex/percent-encoded content N levels deep (default 0 = off; set 3+ to catch encoded secrets) |
| `--max-archive-depth <n>` | descend into nested archives (zip/tar/gz) N levels (newer builds) |
| `--enable-rule <id>` / `--ignore-gitleaks-allow` | run only named rules / ignore inline `gitleaks:allow` comments |
| `--no-banner`, `--no-color`, `-l, --log-level {trace,debug,info,warn,error}` | output control |
| `--diagnostics`, `--follow-symlinks` | profiling; symlink traversal in `dir` mode |

## `git` mode flags

| Flag | Meaning |
|---|---|
| `--log-opts "<opts>"` | passed verbatim to `git log -p <opts>` — the main power knob |
| `--platform {github,gitlab,azuredevops}` | generate correct permalinks in reports |
| `--remote-url <url>` | override link base |

### `--log-opts` recipes

```sh
# only commits on a feature branch not in main (PR gate)
gitleaks git . --log-opts="origin/main..HEAD"

# everything, including deleted branches, tags, reflog-reachable refs
gitleaks git . --log-opts="--all --full-history"

# a single suspect commit
gitleaks git . --log-opts="--no-merges -1 203f1e2 -p"

# commit range by time
gitleaks git . --log-opts="--since=2024-06-01 --until=2024-12-31 --all"

# one author's commits
gitleaks git . --log-opts='--author=dev@example.com --all'

# only commits touching a path
gitleaks git . --log-opts="--all -- config/ deploy/"
```

Caveat: `--log-opts` changes what diffs gitleaks sees; a secret introduced
outside the range is invisible. Default (no `--log-opts`) scans the full
history of the current branch only — add `--all` to cover every ref.

## Baseline workflow (only report new leaks)

```sh
gitleaks git . --report-format json --report-path baseline.json ; true
# ...later / in CI...
gitleaks git . --baseline-path baseline.json \
  --report-format json --report-path new-leaks.json
```

The baseline must be gitleaks **JSON** format. Baselines are a triage
convenience — during an engagement, review the baseline file itself: it is a
list of acknowledged leaked secrets, every one of which may still be live.

## stdin mode

```sh
cat terraform.tfstate | gitleaks stdin -v --report-format json --report-path tfstate.json
kubectl get secrets -A -o yaml | base64 -d 2>/dev/null | gitleaks stdin -v
git show 203f1e2:config/prod.yml | gitleaks stdin -v
```

## Recovering a secret found in history

```sh
git show <Commit>:<File> | sed -n '<StartLine>p'      # exact line at that commit
git log --all --oneline -- <File>                      # lifetime of the file
git branch -a --contains <Commit>                      # which branches still carry it
```

Even if the file was deleted or the branch removed, `git show <Commit>:<File>`
works as long as the object is in the clone — which is why you mirror-clone
(`git clone --mirror`) before scanning.

## Exit codes & automation

- `0` no leaks, `1` leaks (override with `--exit-code`), `126` error.
- In pipelines: `gitleaks git . -r out.json; rc=$?; [ $rc -le 1 ] || exit $rc`
  then branch on whether `out.json` is non-empty.

## Performance

- `--max-target-megabytes 20` skips minified bundles and binaries that
  dominate scan time and produce entropy noise.
- Mirror clones (`--mirror`) are smaller and include all refs.
- gitleaks parallelizes per-commit automatically; `GOMAXPROCS` tunes it.
