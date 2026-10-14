# TruffleHog v3 sources — full flag reference

Global flags apply before/after any subcommand: `--json`, `--results=...`,
`--fail`, `--no-update`, `--concurrency N`, `--no-verification`,
`--verifier URL`, `--custom-verifiers-only`, `--config file.yml`,
`--include-detectors` / `--exclude-detectors`, `--exclude-paths` /
`--include-paths`, `--archive-max-size` / `--archive-max-depth` /
`--archive-timeout`, `--filter-entropy=N`, `--log-level=N` (0..5),
`--profile` (pprof on :18066).

## git

```sh
trufflehog git file:///tmp/app.git
trufflehog git https://example.com/org/app.git
trufflehog git ssh://git@example.com/org/app.git
```

| Flag | Meaning |
|---|---|
| `--branch=<name>` | scan a single branch instead of all refs |
| `--since-commit=<sha>` | only commits after SHA (incremental / PR scans) |
| `--max-depth=<n>` | limit commit depth |
| `--bare` | treat target as a bare/mirror repo |
| `-i/-x --include-paths/--exclude-paths <file>` | newline-separated path regexes |

Mirror-clone first so deleted branches/tags are present:
`git clone --mirror https://example.com/org/app.git /tmp/app.git` then
`trufflehog git file:///tmp/app.git --bare`.

## github

```sh
trufflehog github --org=example --token=$GITHUB_TOKEN --json
trufflehog github --repo=https://github.com/example/app
```

| Flag | Meaning |
|---|---|
| `--org=` / `--repo=` | org-wide (every repo) or single repo |
| `--token=` | PAT; unauthenticated works for public but rate-limits hard |
| `--include-members` | also scan org members' personal repos |
| `--include-forks` | include forks |
| `--issue-comments`, `--pr-comments`, `--gist-comments` | scan comment bodies — classic leak location (pasted configs, debug output) |
| `--include-repos=` / `--exclude-repos=` | glob filters, repeatable |
| `--endpoint=https://github.example.com` | GitHub Enterprise |

Also: `trufflehog github-experimental --repo=... --object-discovery` hunts
secrets in **hidden/dangling commits** still served by GitHub even after
force-push "removal".

## gitlab

```sh
trufflehog gitlab --token=$GITLAB_TOKEN                      # all repos token can see
trufflehog gitlab --token=$T --endpoint=https://gitlab.example.com --repo=https://gitlab.example.com/g/app.git
```

## filesystem

```sh
trufflehog filesystem /srv/code /etc/app /home/dev/.aws --json
```

No git required. Descends directories, extracts archives (respect
`--archive-max-*`). Use for: deploy artifacts, extracted container layers,
backup tarballs, home directories, `.env` files, IDE config, shell history.

## s3 / gcs

```sh
trufflehog s3 --bucket=example-backups --json
trufflehog s3 --bucket=example-backups --role-arn=arn:aws:iam::123456789012:role/audit
trufflehog gcs --project-id=example-prod --json
```

| Flag | Meaning |
|---|---|
| `--bucket=` (repeatable) / omit to enumerate all buckets the creds can list | |
| `--role-arn=` | assume-role before listing (s3) |
| `--include-buckets` / `--exclude-buckets` | filters (gcs) |
| `--cloud-environment` | use ambient instance credentials |

Credentials from the standard env/profile chain (`AWS_PROFILE`,
`GOOGLE_APPLICATION_CREDENTIALS`).

## docker

```sh
trufflehog docker --image=example.com/app:latest --json
trufflehog docker --image=file:///tmp/app.tar
```

Scans **every layer**, so secrets `COPY`'d in and `rm`'d in a later layer are
found. Pull from a registry, local daemon (`docker://`), or a saved tarball.

## Other sources (pointers)

- `trufflehog stdin < blob.txt` — anything pipeable: `git show`, `kubectl get
  secret -o yaml | base64 -d`, HTTP responses, memory dumps run through
  `strings`.
- `trufflehog syslog --address=192.0.2.10:514 --protocol=tcp --cert=... --key=...`
  — live log streams (apps love logging Authorization headers).
- `trufflehog circleci --token=...`, `trufflehog travisci --token=...` — CI
  build logs.
- `trufflehog jenkins --url=https://jenkins.example.com --username=... --password=...`
- `trufflehog postman --token=... --workspace-id=...` — collections/environments.
- `trufflehog elasticsearch`, `trufflehog huggingface`, `trufflehog hibp`.

## Custom detectors (`--config custom.yml`)

```yaml
detectors:
  - name: examplecorp-token
    keywords:                 # cheap prefilter; chunk must contain one
      - excorp_
    regex:                    # named capture groups; ALL must match
      token: 'excorp_(?:live|test)_[a-z0-9]{32}'
    entropy: 3.5              # optional minimum entropy on the match
    exclude_regexes_capture:
      - 'excorp_test_0{32}'
    verify:                   # optional live verification webhook
      - endpoint: https://auth.example.com/api/verify
        unsafe: false         # true allows http://
        headers:
          - "Authorization: Bearer {token}"   # {group} substitution
        successRanges: ["2xx"]
```

A detector with a `verify` block participates in `--results=verified` like a
built-in. Without one, its hits are always `unverified` — include
`unverified` in `--results` or they vanish from output.

## Path filter files

`--exclude-paths exclude.txt`, one regex per line:

```
(^|/)node_modules/
(^|/)vendor/
\.min\.(js|css)$
package-lock\.json$
testdata/
```
