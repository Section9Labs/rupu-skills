# Brakeman CLI Reference

## Invocation

```sh
brakeman [options] [app_path]
brakeman -p /src/example-app        # equivalent to positional path
```

Brakeman never executes the app. It needs the Rails source tree only
(`app/`, `config/`, `lib/`, `Gemfile[.lock]`).

## Output

| Flag | Effect |
|---|---|
| `-o FILE` | Write report; format inferred from extension (`.json`, `.sarif`, `.html`, `.csv`, `.md`, `.txt`, `.tabs`, `.junit.xml`). Repeatable: `-o a.json -o b.sarif -o c.html` writes all in one scan. |
| `-f FORMAT` | Force format: `text`, `html`, `json`, `sarif`, `csv`, `markdown`, `tabs`, `codeclimate`, `junit`, `sonar`. |
| `--summary` / `--no-summary` | Only / never print the summary table. |
| `-q` / `--quiet` | Suppress informational output (keep for scripting). |
| `--no-pager` | Don't pipe text report through a pager (required in non-TTY/agent runs). |
| `--table-width N` / `-m` | Text report width / highlight repeated warnings. |
| `--absolute-paths` | Report absolute instead of app-relative paths. |
| `--github-repo user/repo` | Make HTML/markdown links point at GitHub blobs. |

## Scan scope and depth

| Flag | Effect |
|---|---|
| `-A`, `--run-all-checks` | Enable optional checks (always on engagements). |
| `-t Check1,Check2` | Run only listed checks (names from `--checks`). |
| `-x Check1,Check2` | Skip listed checks. |
| `--checks` / `--optional-checks` | List available / optional check names. |
| `--add-engine-path PATH` | Also scan a Rails engine (repeatable). |
| `--only-files f1,f2` / `--skip-files f1,f2` | Restrict/exclude files or dirs (prefix match, supports globs). |
| `--skip-libs` | Don't scan `lib/`. |
| `--add-libs-path PATH` | Scan additional library paths. |
| `--interprocedural` | Follow method calls with tainted arguments (slower, deeper). |
| `--branch-limit N` | Max branches tracked per value (default 5; raise for depth, 0 to disable branching). |
| `--parser-timeout SECONDS` | Per-file parse timeout (default 10). |
| `--rails3`..`--rails7` | Force Rails version assumptions. |
| `--faster` | Disable some slow analysis (`--no-branching` etc.) - avoid on engagements. |

## Confidence and filtering

| Flag | Effect |
|---|---|
| `-w1` | Report Weak+Medium+High (use this; filter downstream). |
| `-w2` | Medium+High (default). |
| `-w3` | High only. |
| `--no-informational` | Hide informational warnings. |

## Ignoring / baselines

| Flag | Effect |
|---|---|
| `-I`, `--interactive-ignore` | Interactive walkthrough; writes `config/brakeman.ignore`. |
| `-i FILE` | Use a specific ignore file. |
| `--ignore-model-output` | Treat model attributes as safe for XSS (reduces Medium XSS noise; use deliberately). |
| `--ignore-protected` | Suppress mass-assignment warnings for `attr_protected` models. |
| `--ensure-ignore-notes` | Error if any ignore entry lacks a note. |
| `--show-ignored` | Include ignored warnings in output. |
| `--compare OLD.json` | Diff against previous JSON report; outputs `{new, fixed}`. |

## Exit codes / CI

| Flag | Effect |
|---|---|
| (default) | Exit 3 if warnings, 4 on errors, 0 clean. |
| `--no-exit-on-warn` | Exit 0 even with warnings. |
| `--no-exit-on-error` | Exit 0 even with scan errors. |
| `--exit-on-fatal-errors` | Nonzero exit if files could not be parsed. |
| `-z` | Exit nonzero on warnings (explicit). |

## Config file

`-c brakeman.yml` loads options from YAML; `-C` prints the effective config.
A committed `config/brakeman.yml` in the target repo tells you what the
dev team suppresses - read it, then override: skipped checks (`skip_checks:`)
are prime hunting ground. Re-run with `-A -w1` and no config
(`brakeman -c /dev/null` is not supported; instead pass explicit flags which
override file config) to see everything.

## Useful inspection flags

```sh
brakeman --checks            # list all checks with descriptions
brakeman --rake              # generate a rake task
brakeman -d                  # debug output (why a file was skipped, etc.)
brakeman --report-direct     # only warn when user input is used directly
```
