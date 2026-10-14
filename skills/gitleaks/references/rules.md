# Gitleaks rules: default coverage and custom TOML

## Default ruleset coverage (embedded, ~190 rules, hundreds of providers)

High-confidence provider rules (distinct prefixes/formats, near-zero FP):

- **Cloud:** `aws-access-token` (`AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 chars),
  GCP API keys (`AIza...`) and service-account JSON, Azure AD client
  secrets / storage keys, Alibaba, DigitalOcean (`dop_v1_`, `doo_v1_`),
  Heroku, Databricks (`dapi...`)
- **VCS/CI:** GitHub PAT/fine-grained/OAuth/app/refresh (`ghp_`, `github_pat_`,
  `gho_`, `ghu_`, `ghs_`, `ghr_`), GitLab (`glpat-`, `glrt-`, pipeline/runner
  tokens), Bitbucket, CircleCI, Travis, Jenkins
- **SaaS:** Stripe (`sk_live_`, `rk_live_`), Slack (`xoxb-`/`xoxp-`/`xoxa-`,
  webhook URLs), Twilio (`SK...`), SendGrid (`SG....`), Mailgun, Mailchimp,
  Datadog, New Relic, PagerDuty, Shopify (`shpat_`, `shpss_`), Square,
  PayPal/Braintree, Telegram bot tokens, Discord, OpenAI (`sk-...`),
  HuggingFace (`hf_`), npm (`npm_`), PyPI (`pypi-`), RubyGems, NuGet
- **Infra:** HashiCorp Vault (`hvs.`, `hvb.`), Terraform Cloud, Pulumi,
  Cloudflare, Fastly, Grafana (`glc_`, `glsa_`), Artifactory, Docker Hub
- **Crypto material:** `private-key` — PEM blocks for RSA/EC/OpenSSH/PGP/
  PKCS8 (`-----BEGIN ... PRIVATE KEY-----`), age secret keys
- **Tokens:** `jwt` (`eyJ...` three-segment) — always base64-decode the
  payload during triage: issuer, audience, scopes, `exp`
- **Generic:** `generic-api-key` — `(key|api|token|secret|password)` style
  assignment with an entropy-gated value. This is where both the long tail
  and the noise live; sort by `Entropy` descending.

## Custom `.gitleaks.toml`

```toml
title = "example.com engagement rules"

[extend]
# layer on top of the embedded default ruleset
useDefault = true
# or inherit from another file/url: path = "../base.toml"
# disabledRules = ["generic-api-key"]   # drop a default rule by id

[[rules]]
id          = "examplecorp-internal-token"
description = "ExampleCorp internal service token"
regex       = '''(?i)excorp_(?:live|test)_[a-z0-9]{32}'''
entropy     = 3.5                 # min Shannon entropy of the secret group
keywords    = ["excorp_"]         # cheap pre-filter before regex (big speedup)
secretGroup = 0                   # which regex capture group is the secret
path        = ''''''              # optional: only match in files matching this regex
tags        = ["custom", "internal"]

    # per-rule allowlist
    [[rules.allowlists]]
    description = "test fixtures"
    paths       = ['''tests?/fixtures/''']
    regexes     = ['''excorp_test_0{32}''']
    stopwords   = ["example", "sample"]
    # condition = "AND"   # require ALL criteria to match (default OR)

# global allowlist — applies to every rule
[allowlist]
description = "global ignores"
paths = [
  '''(?:^|/)vendor/''',
  '''(?:^|/)node_modules/''',
  '''\.min\.js$''',
  '''(?:^|/)go\.sum$''',
]
regexes   = ['''AKIAIOSFODNN7EXAMPLE''']    # AWS doc example key
stopwords = ["changeme", "placeholder", "your_api_key"]
commits   = ["203f1e2a..."]                 # specific known-benign commits
# regexTarget = "match"   # apply regexes to full match instead of secret
```

Rule fields: `id` (unique), `regex` (RE2 syntax — no backreferences or
lookaround), `entropy`, `keywords` (ANY must appear in the fragment, case-
insensitive), `path`, `secretGroup`, `tags`, nested `[[rules.allowlists]]`.
Validate a config quickly: `gitleaks dir testdata/ -c custom.toml -v`.

### Entropy guidance

Shannon entropy of the captured secret group. Rough bands over the usual
charset: random hex 32+ chars ≈ 3.8–4.0; random base64 ≈ 4.5–5.5+; English
words/placeholders ≈ 2.5–3.5. Set `entropy = 3.5`–`4.0` on generic rules to
cut placeholder noise; provider rules with strong prefixes don't need it.

### Writing a quick custom rule from a leaked sample

Given an internal token format `svc-9f3a...` (24 hex after `svc-`):

```toml
[[rules]]
id       = "svc-token"
regex    = '''svc-[0-9a-f]{24}'''
keywords = ["svc-"]
entropy  = 3.0
```

## Inline allowlisting

A line ending in a comment containing `gitleaks:allow` is skipped:

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow
```

During review, grep for these — they are curated lists of things developers
decided were "fine": `grep -rn "gitleaks:allow" .` Audit each one; also run
with `--ignore-gitleaks-allow` to see what they hide. Likewise audit the
repo's committed `.gitleaks.toml`: broad `paths` allowlists (`config/`,
`deploy/`, `*.env`) are themselves findings — they tell you exactly where
secrets accumulate.

## Decoding layers

`--max-decode-depth 3` makes gitleaks recursively decode base64 / hex /
percent-encoded blobs before matching — catches secrets hidden in
base64-encoded Kubernetes `Secret` manifests, data-URIs, and double-encoded
config values that plain regex misses.
