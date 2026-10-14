# njsscan — flags, config, and rule reference

## CLI reference

```
njsscan [-h] [--json] [--sarif] [--sonarqube] [--html] [-o OUTPUT]
        [-c CONFIG] [--missing-controls] [-w] [-v] [path ...]
```

| Flag | Effect |
|---|---|
| `path ...` | One or more files/directories to scan. |
| `--json` | Emit the native JSON result map (richest: match strings, positions, full metadata). |
| `--sarif` | Emit SARIF 2.1.0 (`runs[0].tool.driver.name = "njsscan"`). Best for `sarif-triage` and code-scanning upload. |
| `--sonarqube` | SonarQube generic-issue JSON. |
| `--html` | Standalone HTML report. |
| `-o OUTPUT` | Write the report to a file (otherwise stdout). |
| `-c CONFIG` | Explicit `.njsscan` config path. Without it, njsscan looks for `.njsscan` in the scan root. |
| `--missing-controls` | Enable missing-security-control checks (helmet, CSRF middleware, rate limiting on Express/Koa). Disabled by default. |
| `-w, --exit-warning` | Non-zero exit also on WARNING severity (default: only ERROR). |
| `-v, --version` | Print version. |

Only one output format per run — invoke twice for JSON + SARIF
(`scripts/run_njsscan.py` automates this).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above the exit threshold. |
| 1 | ERROR findings present (or WARNING with `-w`). |
| ≥2 | Usage error / crash — rerun with a smaller path set to isolate. |

## `.njsscan` config format

YAML list of single-key maps. All keys optional:

```yaml
---
- nodejs-extensions:      # files run through the semgrep (nodejs) engine
  - .js
  - .mjs
  - .cjs
- template-extensions:    # files run through the regex (templates) engine
  - .ejs
  - .hbs
  - .pug
  - .html
  - ''                    # empty string = extensionless files
- ignore-filenames:
  - skip.js
  - jquery.js
- ignore-paths:
  - node_modules
  - dist
  - build
  - coverage
  - __MACOSX
- ignore-extensions:
  - .min.js
  - .jsx                  # (route JSX/TSX to eslint-plugin-security / semgrep instead)
- ignore-rules:
  - regex_injection_dos
  - node_username
```

Inline suppression on a specific line:

```js
const out = execSync(cmd); // njsscan-ignore: node_child_process
```

Audit tip: `grep -rn 'njsscan-ignore' .` — manually re-review every
suppressed line; suppressions accumulate exactly where developers argued
with the scanner.

## JSON result schema

```json
{
  "njsscan_version": "0.4.x",
  "nodejs":    { "<rule_id>": { "files": [ {"file_path","match_lines":[s,e],
                 "match_position":[c1,c2], "match_string"} ],
                 "metadata": {"severity","cwe","owasp","description"} } },
  "templates": { "same shape — regex engine hits (templates, secrets)" },
  "errors":    [ "per-file parse/scan errors — nonempty means blind spots" ]
}
```

Notes:
- `match_lines` is `[start_line, end_line]` of the match (often equal).
- `severity` ∈ {`ERROR`, `WARNING`, `INFO`}.
- `cwe` is a string like `"CWE-78: Improper Neutralization of Special
  Elements used in an OS Command ('OS Command Injection')"` — the parser
  extracts the `CWE-NN` token.
- Check `errors` — files semgrep could not parse (new syntax, huge bundles)
  are silently uncovered; scan those with eslint/semgrep separately.

## SARIF mapping

- `runs[0].tool.driver.rules[]` — rule metadata (`id`, `fullDescription`,
  tags carrying CWE/OWASP).
- `results[].ruleId`, `results[].level` (`error`/`warning`/`note`),
  `results[].locations[].physicalLocation.artifactLocation.uri` +
  `.region.startLine`.

## Representative rule ids by class

Rule ids are stable identifiers from the njsscan rules repo
(`nodejs/` semgrep rules + `template/`/`regex` rules). Representative set:

| Class | Rule ids (representative) | Severity |
|---|---|---|
| SQL injection | `node_sqli_injection` | ERROR |
| NoSQL injection | `node_nosqli_injection` (Mongo `$where`, query-object injection) | ERROR |
| Command injection | `node_child_process`, `child_process` (exec/execSync/spawn shell) | ERROR |
| Code injection | `node_eval`, `eval_require`, `eval_nodejs`, `node_vm` (vm.runIn*) | ERROR |
| Deserialization | `node_deserialize` (node-serialize `unserialize`) | ERROR |
| Path traversal / LFI | `express_lfr`, `generic_path_traversal` | ERROR |
| SSRF | `node_ssrf`, `node_curl_ssrf` | ERROR |
| XXE | `node_xxe`, `expat_xxe` | ERROR |
| XSS | `express_xss`, `node_xss` + template rules (`pug_jade_template`, `handlebar_mustache_template`, `ejs_template`, `dust_template`, `squirrelly_template`) | ERROR/WARNING |
| Open redirect | `express_open_redirect` | ERROR |
| Header injection / host header | `header_injection`, `host_header_injection` | WARNING |
| Weak crypto | `node_md5`, `node_weak_crypto`, `node_insecure_random_generator`, `node_aes_ecb` | WARNING |
| TLS verification off | `node_tls_reject`, `node_curl_sslverify_disable` | ERROR |
| Hardcoded secrets | `node_password`, `node_secret`, `node_api_key`, `node_aws_access_key`, `node_username`, `jwt_hardcoded`, `generic_hardcoded_secret` | WARNING |
| JWT misuse | `jwt_none_algorithm`, `jwt_exposed_credentials`, `jwt_express_hardcoded` | ERROR |
| Cookies/session | `cookie_session_no_httponly`, `cookie_session_no_secure`, `cookie_session_no_samesite`, `cookie_session_default`, `express_session_hardcoded` | WARNING |
| Security headers | `express_default_helmet` / missing-controls rules (helmet, csurf, rate-limit) | WARNING |
| ReDoS | `regex_dos`, `regex_injection_dos` (RegExp from user input) | ERROR/WARNING |
| Prototype pollution | merge/extend and `__proto__` assignment rules | ERROR |
| Timing attacks | non-constant-time secret comparison rules | WARNING |

Exact ids vary slightly across versions — treat the `rule_id` in the JSON as
authoritative and read its `metadata.description`. When in doubt, the rule
sources live under njsscan's `njsscan/rules/semantic_grep/` and
`njsscan/rules/pattern_matcher/` directories in the installed package.

## Per-class verification notes

- **node_deserialize**: payload shape is
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec(...)}()"}` —
  if the `unserialize()` argument is request-derived, this is direct RCE.
- **node_child_process**: `execFile`/`spawn` without `shell: true` and with
  an array argv is usually safe unless the *binary path* or flags like
  `-o/--output` are attacker-controlled. `exec`/`execSync` always go through
  a shell.
- **node_nosqli_injection**: confirm `express.json()`/`qs` lets objects
  through — `?user[$gt]=` in query strings and JSON bodies both smuggle
  operators. `$where` strings execute JS server-side on MongoDB.
- **express_lfr / path traversal**: check for `path.normalize` +
  prefix-containment after joining; `path.join(base, req.params.f)` alone
  does NOT prevent `..` escape. `res.sendFile` with a `root` option is the
  safe variant.
- **Prototype pollution**: match → find the merge target; pollution of a
  shared object + a gadget (e.g. `child_process` `shell` option, EJS
  `outputFunctionName`) upgrades to RCE. Hand to `taint-analysis`.
- **cookie_session_***: confirm against actual deployment (secure flag may
  be set by a proxy) before filing.
- **Secrets rules**: validate the secret is live (not a test fixture) and
  check git history for rotation.
