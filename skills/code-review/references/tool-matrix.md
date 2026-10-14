# code-review — routing matrices

Which sub-skill to load for which stack. Load the named skill for flags,
rulesets, and output parsing — this file only routes.

## Language → SAST

| Language | Always | Deep linter (load skill) | Interprocedural |
|---|---|---|---|
| Python | `semgrep` | `bandit` | `codeql` (python) |
| JavaScript / TypeScript / Node | `semgrep` | `njsscan` | `codeql` (javascript) |
| Go | `semgrep` | `gosec` | `codeql` (go) |
| Ruby / Rails | `semgrep` | `brakeman` | `codeql` (ruby) |
| Java / Kotlin / Scala (JVM) | `semgrep` | `find-sec-bugs` | `codeql` (java) |
| C# / .NET | `semgrep` | — | `codeql` (csharp) |
| C / C++ | `semgrep` | — | `codeql` (cpp) |
| PHP | `semgrep` (p/php) | — | — |
| Rust | `semgrep` | — | — (SCA via `cargo-audit`) |
| Shell | `semgrep` (p/bash) | — | — |
| Terraform / YAML / IaC | `semgrep` (p/terraform, p/kubernetes) | — | — |

Rule of thumb: `semgrep` on everything, the per-language linter where it exists,
`codeql` only on high-value modules (auth, payments, deserialization, anything
on a trust boundary) because database builds are expensive.

## Ecosystem → SCA

| Manifest / lockfile | Ecosystem | Load skills |
|---|---|---|
| requirements.txt, Pipfile[.lock], poetry.lock, pyproject.toml | python | `osv-scanner`, `grype-syft` |
| package.json, package-lock.json, yarn.lock, pnpm-lock.yaml | npm | `osv-scanner`, `grype-syft`, `retire-js` |
| go.mod / go.sum | go | `osv-scanner`, `grype-syft` |
| pom.xml | maven | `dependency-check`, `osv-scanner`, `grype-syft` |
| build.gradle[.kts] | gradle | `dependency-check`, `osv-scanner`, `grype-syft` |
| Gemfile[.lock] | rubygems | `osv-scanner`, `grype-syft` |
| Cargo.toml / Cargo.lock | cargo | `cargo-audit`, `osv-scanner` |
| composer.json / composer.lock | composer | `osv-scanner`, `grype-syft` |
| *.csproj / packages.lock.json | nuget | `dependency-check`, `grype-syft` |
| Dockerfile / container images | docker | `grype-syft` (syft the image, grype the SBOM) |
| vendored JS in static/ or public/ | npm (unmanifested) | `retire-js` (scans bundles by hash/signature) |

Prefer lockfiles over manifests when both exist — exact resolved versions beat
ranges. `osv-scanner` reads lockfiles natively; `grype-syft` catalogs everything
syft can see, including vendored and container contents.

## Service / pattern → taint approach (all via the `taint-analysis` skill)

| Vulnerability class | Sources | Typical sinks | Approach |
|---|---|---|---|
| SQL injection | HTTP params/body, headers | `execute/query/raw` with string building | semgrep taint-mode + grep for f-string/concat SQL |
| Command injection | HTTP params, filenames, env | `os.system`, `subprocess`, `exec.Command`, `child_process`, backticks | ripgrep sink pack, then trace argv construction |
| LDAP injection | login forms, search fields | LDAP filter string building | grep `(&(`-style filter concat |
| Template injection (SSTI) | any user string | `render_template_string`, `Template(user)`, `new Function`, ejs with user template | semgrep taint-mode |
| Insecure deserialization | request bodies, queues, cookies, files | `pickle.loads`, `yaml.load`, `ObjectInputStream.readObject`, `Marshal.load`, `unserialize` | sink-first: find the sink, trace input backwards |
| SSRF | URL/host params, webhooks | `requests.get(user)`, `fetch(user)`, `http.Get(user)`, redirects followed | trace URL construction + allowlist checks |
| Path traversal | filename params, archive entries | `open/readFile/SendFile` with joined user path | trace path joins, check canonicalization |
| Authz gaps (IDOR / missing checks) | object IDs in routes | DB fetch by ID without ownership check | codeql/structural: route handlers lacking the auth decorator/middleware the rest have |
| Crypto misuse | — (config class) | ECB mode, MD5/SHA1 for passwords, static IV/key, `verify=False` | semgrep crypto rules + grep constants |
| Hardcoded secrets | — | string literals, config files, git history | Phase 2 tools (`gitleaks`, `trufflehog`), plus taint pack for literals passed to auth APIs |

## Secrets

| Need | Load skill |
|---|---|
| Fast regex+entropy scan of full git history | `gitleaks` |
| Detector-based scan with live verification of credentials | `trufflehog` |

Run both: gitleaks has broader generic coverage; trufflehog's verified hits are
confirmed-valid and skip straight to `findings.report`.

## Normalization and handoff (always)

| Step | Load skill |
|---|---|
| Normalize/dedup every SARIF + native JSON | `sarif-triage` |
| Split into the fan-out JSON array | `work-units` |
| File each verified issue | `finding-report` |
