# TruffleHog verification — mechanics and semantics

## How verification works

When a detector's regex matches, trufflehog builds a real request to the
credential's provider and classifies the response:

- **AWS**: `sts:GetCallerIdentity` signed with the key pair → on success,
  `ExtraData` carries the **account ID and ARN** (`arn:aws:iam::123456789012:user/deploy`).
- **GitHub**: `GET /user` with the token → login, token **scopes**, expiry.
- **Slack**: `auth.test` → team and bot identity.
- **Stripe**: `GET /v1/charges?limit=1` with the key → live/test mode.
- **Database URIs** (Postgres/MySQL/MongoDB/Redis): trufflehog **opens a
  real connection** and authenticates.
- **Generic webhook-verified custom detectors**: your endpoint decides.

The scan host therefore makes outbound HTTPS/TCP to each provider — plan
egress accordingly, and know that verification attempts can appear in the
provider's audit logs (e.g. CloudTrail records the `GetCallerIdentity`).
Use `--no-verification` when that visibility is unacceptable, or
`--verifier https://198.51.100.7:8443 --custom-verifiers-only` to route all
verification through a controlled relay.

## Result classes (`--results=`)

| Class | Meaning | Triage stance |
|---|---|---|
| `verified` | provider confirmed the credential is live | report immediately; `ExtraData` = blast radius |
| `unknown` | verification attempted but non-definitive: timeout, 429, 5xx, ambiguous body (`VerificationError` says why) | treat as possibly live; retry with lower `--concurrency`, or exercise the credential manually |
| `unverified` | provider rejected it, OR the detector has no verifier | leak path still real; key may be rotated/re-enabled; context decides severity |
| `filtered_unverified` | unverified hits suppressed by detector-level FP filters | include only for maximum-recall sweeps |

Syntax notes:
- Newer builds: `--results=verified`, `--results=verified,unknown`,
  `--results=verified,unknown,unverified,filtered_unverified`.
- Older builds: `--only-verified` ≡ `--results=verified` (still accepted,
  deprecated). `--allow-verification-overlap` lets multiple detectors verify
  the same candidate string.
- No `--results` flag at all = emit everything except `filtered_unverified`.

## The two-pass doctrine

1. **Impact pass** — `--results=verified,unknown --fail`: near-zero false
   positives; everything here is an actionable finding or needs one manual
   check. This is what you gate and report first.
2. **Inventory pass** — `--results` with all classes (or no flag): the
   complete leak surface. A revoked AWS key is still a finding (the leak
   mechanism exists; CloudTrail from the commit date needs auditing; the
   same pipeline will leak the replacement key). Detectors lacking verifiers
   (many internal/B2B products) only ever appear here.

Diff the passes: anything in pass 2 matching a high-value detector but
`unverified` deserves a manual check — rotation is recent news, not absence
of impact.

## Exit code 183 and gating

With `--fail`, trufflehog exits **183** iff at least one result in the
selected `--results` classes was found (otherwise 0). 183 was chosen to be
distinct from shell/tool conventions.

```sh
trufflehog git file:///tmp/app.git --results=verified --fail --json > v.jsonl
case $? in
  0)   echo "no verified secrets";;
  183) echo "VERIFIED secrets present — see v.jsonl";;
  *)   echo "scanner error" >&2;;
esac
```

In CI, pair with `--since-commit $BASE --branch $HEAD` so the gate only
fires on newly introduced secrets.

## Rate limits, tokens, retries

- Verification calls hit provider rate limits at high `--concurrency`;
  symptoms are a spike of `unknown` results with 429/`Retry-After` in
  `VerificationError`. Lower `--concurrency` (e.g. 4) and re-run just those
  detectors with `--include-detectors=`.
- The **github source** (not verification) needs `--token=$GITHUB_TOKEN` for
  any serious org scan: unauthenticated = 60 req/h; a PAT = 5000 req/h.
- Mass re-verification of a single detector:
  `trufflehog git file:///tmp/app.git --include-detectors="aws" --results=verified,unknown --json`.
- `VerificationError` text is preserved in the JSON — the work-unit parser
  (scripts/trufflehog_to_workunits.py) copies it into `hints` so the triage
  agent knows whether to retry or test manually.

## Manually confirming an `unknown`

Use the recovered raw value directly (examples; adapt per provider):

```sh
# AWS pair
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
# GitHub token
curl -s -H "Authorization: Bearer ghp_..." https://api.github.com/user
# Slack
curl -s -H "Authorization: Bearer xoxb-..." https://slack.com/api/auth.test
# Postgres URI
psql "postgres://user:pass@203.0.113.5:5432/app" -c 'select current_user;'
```

Capture the response as verification evidence for `findings.report`, then
enumerate what the credential can actually reach (scopes, buckets, repos) —
that enumeration is the impact section of the finding.
