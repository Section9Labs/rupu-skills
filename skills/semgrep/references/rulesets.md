# Semgrep Registry rulesets — catalog and selection

Registry packs are referenced as `--config p/<name>`. Combine several in one
run; Semgrep dedupes rules shared between packs. Browse live at
https://semgrep.dev/explore and https://semgrep.dev/r.

## General-purpose packs

| Pack | Contents | When to use |
|---|---|---|
| `p/default` | Broad baseline across languages (what `--config auto` roughly resolves to) | Quick, general first pass |
| `p/security-audit` | Security-relevant rules, including noisier "audit" rules that flag dangerous APIs regardless of taint | Manual security review — the fleet default. Expect FPs; that's the point of audit rules |
| `p/ci` | High-confidence, low-FP subset | CI gates, diff-aware scans, `--error` runs |
| `p/owasp-top-ten` | Rules mapped to OWASP Top 10 2021 categories | Compliance-framed reviews, web apps |
| `p/cwe-top-25` | Rules mapped to CWE Top 25 | Compliance-framed reviews |
| `p/r2c-best-practices` | Correctness/robustness, not strictly security | Code-quality sweep |

## Secrets

| Pack | Notes |
|---|---|
| `p/secrets` | Hardcoded credentials, API keys, tokens, private keys across file types. Run on EVERY engagement — cheap, high value. Pair with a dedicated secrets scanner (gitleaks/trufflehog) for git-history coverage, which Semgrep does not do. |
| `p/gitleaks` | Gitleaks regex patterns ported to Semgrep. |

## Vulnerability-class packs

Use these to go deep on one bug class after the broad pass flags a theme:

- `p/sql-injection` — SQLi across languages/ORMs
- `p/xss` — reflected/DOM XSS patterns
- `p/command-injection` — shell/exec sinks
- `p/insecure-transport` — plaintext HTTP, disabled TLS verification
- `p/jwt` — alg confusion, missing verification, weak secrets
- `p/xxe` — XML external entity misconfig
- `p/ssrf` — server-side request forgery sinks
- `p/insecure-deserialization` — pickle/ObjectInputStream/yaml.load etc.

## Language packs

`p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/kotlin`,
`p/ruby`, `p/php`, `p/csharp`, `p/scala`, `p/rust`, `p/c`, `p/elixir`.
Each bundles that language's security + correctness rules. Add the pack for
every language with meaningful LOC in the repo.

## Framework packs

| Pack | Stack |
|---|---|
| `p/django` | Django: raw SQL, `mark_safe`, template injection, settings misconfig |
| `p/flask` | Flask: `render_template_string`, debug mode, unsafe redirects |
| `p/express` | Express: `res.send` injection, open redirect, missing helmet |
| `p/nodejs` | Node core: `child_process`, `eval`, prototype pollution |
| `p/react` | `dangerouslySetInnerHTML`, href injection |
| `p/nextjs` | Next.js-specific SSR/API-route issues |
| `p/rails` | Rails: mass assignment, `html_safe`, SQL fragments |
| `p/spring` | Spring: SpEL injection, CSRF config, actuator exposure |
| `p/laravel` | Laravel-specific sinks |

## Infrastructure / supply chain

| Pack | Stack |
|---|---|
| `p/docker` / `p/dockerfile` | Dockerfile hardening (root user, ADD vs COPY, latest tags) |
| `p/kubernetes` | K8s manifests: privileged pods, hostPath, missing securityContext |
| `p/terraform` | Terraform: open security groups, unencrypted storage, public buckets |
| `p/github-actions` | Workflow injection (`${{ }}` into run:), untrusted checkout |
| `p/semgrep-rule-lints` | Lints your own custom rules |

## Selection strategy for a review

1. Always: `p/security-audit` + `p/secrets`.
2. Add one language pack per language present (check with
   `git ls-files | sed 's/.*\.//' | sort | uniq -c | sort -rn`).
3. Add framework packs matching dependencies (look at
   `requirements.txt` / `package.json` / `go.mod` / `pom.xml`).
4. Add IaC packs if `Dockerfile`/`*.tf`/`k8s/` exist.
5. After first-pass triage, drill into a class pack (e.g. `p/sql-injection`)
   plus custom rules modeling the repo's own DB/exec wrappers.

Example for a Django + React monorepo at `/src/example.com-app`:

```bash
semgrep scan \
  --config p/security-audit --config p/secrets \
  --config p/python --config p/django \
  --config p/javascript --config p/typescript --config p/react \
  --config p/docker --config p/github-actions \
  --metrics=off --jobs 12 --sarif -o semgrep.sarif .
```

## Pinning and vendoring

Registry packs change over time. For reproducible engagements, vendor rules:

```bash
git clone --depth 1 https://github.com/semgrep/semgrep-rules /opt/semgrep-rules
semgrep scan --config /opt/semgrep-rules/python --config /opt/semgrep-rules/javascript .
```

The semgrep-rules repo mirrors most registry content organized by
`<language>/<framework>/security/`.
