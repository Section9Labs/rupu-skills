---
name: njsscan
description: Static security scanning of Node.js/JavaScript codebases with njsscan (MobSF's semgrep+regex SAST) — install, run with JSON/SARIF output, tune with .njsscan configs and --missing-controls, triage SQLi/NoSQLi/command-injection/eval/prototype-pollution/secret findings, convert results into rupu work units, and route to eslint-plugin-security, semgrep, codeql, or taint-analysis for deeper coverage. Use whenever a target repo contains JavaScript/TypeScript server code (Express/Koa/Fastify, Electron main process, Node CLIs, template files).
license: Apache-2.0
metadata:
  author: Section9Labs
---

# njsscan — Node.js/JavaScript SAST

njsscan is the Node-focused static analyzer from the MobSF team. It wraps a
curated semgrep ruleset (pattern + metavariable rules for `.js` files) and a
regex engine (for templates, config, and secrets) tuned specifically for
Node.js server code. It is the fastest first pass over any Node repo: low
setup cost, Node-aware rules, SARIF output. Run it before generic scanners.

## 1. Install and smoke test

```sh
pip install njsscan            # or: pipx install njsscan
njsscan --version
```

njsscan vendors `libsast` + `semgrep` as dependencies; no Node runtime is
required to scan. If pip-installed semgrep conflicts with a system semgrep,
install njsscan in its own venv/pipx environment.

## 2. Run it

```sh
# Human-readable table to stdout
njsscan src/

# JSON for machine parsing
njsscan --json -o njsscan.json .

# SARIF 2.1.0 for triage pipelines / code-scanning upload
njsscan --sarif -o njsscan.sarif .

# Also check for MISSING security controls (helmet, csurf, rate limiting...)
njsscan --missing-controls --json -o njsscan.json .

# Scan a single file or several paths
njsscan server.js routes/ views/
```

Key flags (full table in `references/njsscan.md`):

- `--json` / `--sarif` / `--sonarqube` / `--html` — output format. One format
  per invocation; run twice if you want both JSON (richest metadata) and
  SARIF (for `sarif-triage`). `scripts/run_njsscan.py` does both.
- `-o FILE` — write output to file instead of stdout.
- `-c / --config FILE` — explicit path to a `.njsscan` config (otherwise it
  auto-discovers `.njsscan` in the scanned root).
- `--missing-controls` — enable the "missing security control" ruleset
  (Express apps without helmet, missing CSRF middleware, no rate limiting).
  Off by default; always turn it on for Express/Koa web apps.
- `-w / --exit-warning` — exit non-zero on WARNING-severity findings too.
- `-v / --version`, standard `-h`.

Exit codes: `0` = clean, `1` = ERROR-severity findings (plus WARNINGs when
`-w` is set), anything else = scanner/usage error. In CI-style wrappers treat
0 and 1 as "scan succeeded", everything else as failure.

### `.njsscan` config — tune scope and rules

Drop a `.njsscan` YAML file in the repo root (or pass `-c`) to control which
files are scanned and which rules fire:

```yaml
---
- nodejs-extensions:
  - .js
  - .mjs
- template-extensions:
  - .ejs
  - .hbs
  - .pug
- ignore-filenames:
  - test_fixtures.js
- ignore-paths:
  - node_modules
  - dist
  - vendor
- ignore-extensions:
  - .min.js
- ignore-rules:
  - regex_injection_dos
```

Always ignore `node_modules`, build output (`dist/`, `build/`, `.next/`),
and minified bundles — they drown real findings and inflate runtime. Scan
dependencies separately with SCA tooling, not SAST.

Inline suppression: a line containing a match can be suppressed by appending
`// njsscan-ignore: <rule_id>` on that line. Grep for existing suppressions
(`grep -rn "njsscan-ignore" src/`) — developer-silenced findings are often
the most interesting ones to re-review manually.

## 3. What njsscan catches (hunt list)

Each rule carries severity (ERROR/WARNING/INFO), CWE, and OWASP tags in its
metadata. The classes worth chasing to confirmed exploitability:

- **SQL injection** — string-built queries into `mysql`/`pg`/`sequelize.query`
  from `req.params`/`req.query`/`req.body` (`node_sqli_injection`).
- **NoSQL injection** — Mongo `$where` with user input, unvalidated objects
  passed into `collection.find(req.body)`, `$regex`/`$gt` operator smuggling
  (`node_nosqli_injection`).
- **Command injection** — `child_process.exec`/`execSync`/`spawn` with
  `shell: true` fed tainted strings (`node_child_process`, `child_process`).
- **Code injection** — `eval()`, `new Function()`, `vm.runInNewContext`,
  `setTimeout/setInterval` with string args (`node_eval`, `node_vm`,
  `eval_require`).
- **Deserialization RCE** — `node-serialize`'s `unserialize()` on user input
  (`node_deserialize`) — classic IIFE-in-payload RCE.
- **Path traversal** — `fs.readFile`/`res.sendFile`/`express.static` built
  from request data without normalization (`express_lfr`, path-traversal
  rules).
- **Prototype pollution** — unsafe deep merge/extend of request bodies,
  `__proto__`/`constructor.prototype` writes.
- **SSRF** — `http.get`/`request`/`axios`/`node-curl` URLs from user input
  (`node_curl_ssrf`, `node_ssrf`).
- **XXE** — XML parsers (`libxmljs` with `noent: true`, expat) on user XML.
- **XSS / template injection** — `res.send` of raw input, `dangerouslySetInnerHTML`,
  unescaped `<%- %>`/`{{{ }}}` in EJS/Handlebars/Pug templates (regex rules
  over template files — this is why `template-extensions` matters).
- **Insecure crypto** — MD5/SHA1, DES/RC4, ECB mode, static IVs,
  `Math.random()` for secrets (`node_md5`, `node_insecure_random_generator`).
- **Hardcoded secrets** — API keys, passwords, JWT secrets in source
  (`node_password`, `node_api_key`, `node_secret`, `node_aws_access_key`).
- **Cookie/session flags** — `express-session`/`cookie-session` without
  `httpOnly`, `secure`, `sameSite`; weak session secrets
  (`cookie_session_no_httponly`, `cookie_session_no_secure`).
- **Security-header gaps** — missing helmet/CSP/HSTS, `X-Powered-By` left on
  (surface these with `--missing-controls`).
- **Regex DoS** — evil regexes and `new RegExp(userInput)`
  (`regex_injection_dos`, `regex_dos`).
- **Open redirect, host-header injection, timing-unsafe comparisons, TLS
  verification disabled** (`NODE_TLS_REJECT_UNAUTHORIZED=0`,
  `rejectUnauthorized: false`).

Full rule-id reference and per-class triage notes: `references/njsscan.md`.

## 4. Read the output

JSON structure — a map of rule id → matches, per engine:

```json
{
  "njsscan_version": "0.4.x",
  "nodejs": {
    "node_sqli_injection": {
      "files": [
        {"file_path": "routes/user.js", "match_lines": [42, 44],
         "match_position": [10, 68], "match_string": "db.query(`SELECT ... ${req.params.id}`)"}
      ],
      "metadata": {"severity": "ERROR", "cwe": "CWE-89: SQL Injection",
                   "owasp": "A1: Injection", "description": "Untrusted user input in a raw SQL query..."}
    }
  },
  "templates": { "...regex template/secret findings, same shape..." },
  "errors": []
}
```

Triage order: ERROR severity first, then by exploit class (RCE classes —
deserialization, eval, command injection — before info leaks), then WARNING.
For each hit, open `file_path` at `match_lines[0]`, trace the matched
expression's inputs back to a request/file/env source, and confirm the sink
actually executes with attacker-controlled data. njsscan's semgrep rules are
intraprocedural: a match proves the sink pattern, not the full taint path —
verifying the source→sink path is the agent's job.

## 5. Normalize → work units → fan-out (rupu)

Use the bundled scripts to run and normalize in one shot:

```sh
# Runs njsscan twice (JSON + SARIF), then parses JSON into work units
python3 scripts/run_njsscan.py /path/to/repo --missing-controls -o out/

# Or parse existing output (JSON and/or SARIF; auto-detected)
python3 scripts/njsscan_to_workunits.py njsscan.json njsscan.sarif -o workunits.json
```

`workunits.json` is a **clean top-level JSON array** of
`{"id", "title", "targets": ["path:line", ...], "hints": {"rule", "severity",
"cwe", "owasp", ...}}` — directly consumable by a rupu workflow's
`read_file` + `for_each:` or a lead agent's `dispatch` fan-out.

Handoff protocol:

1. Mark coverage: record the repository, each scanned file/module, and the
   dependency packages (from `package.json`/lockfile) with `assets.mark`.
   Concrete calls in `references/rupu.md`.
2. Load the **`work-units`** skill to split/normalize the work-unit array —
   do not re-invent the splitter; feed it `workunits.json`.
3. Route `njsscan.sarif` to the **`sarif-triage`** skill for cross-tool
   dedup and severity reconciliation alongside other scanners' SARIF.
4. For every finding you verify (traced source→sink, confirmed reachable),
   load the **`finding-report`** skill and file it with `findings.report`.

## 6. Second opinion: eslint-plugin-security

Run ESLint with `eslint-plugin-security` as a complementary heuristic pass —
it flags sink *usages* (`detect-child-process`,
`detect-non-literal-fs-filename`, `detect-eval-with-expression`,
`detect-object-injection`, `detect-unsafe-regex`, ...) that njsscan's
tighter patterns may skip, and it covers TypeScript via typescript-eslint.
It is noisy by design (no dataflow), so use it to generate leads, not
findings. Full flat-config setup, rule list, and the
`@microsoft/eslint-formatter-sarif` SARIF export (feed that SARIF to the
same `njsscan_to_workunits.py` / `sarif-triage` pipeline):
`references/eslint-security.md`.

## 7. Limits — when to escalate

njsscan is pattern-based and intraprocedural. Escalate when:

- **Cross-function/cross-file dataflow** is needed to confirm a lead →
  `semgrep` skill with the `p/javascript`, `p/nodejs`, `p/expressjs`,
  `p/react` packs and **taint mode** rules (`mode: taint` with
  `pattern-sources: req.body/req.query/req.params`).
- **Whole-program analysis** (callbacks, promises, framework routing) →
  `codeql` skill: build the JavaScript database
  (`codeql database create --language=javascript`) and run
  `codeql-javascript` security queries (js/sql-injection,
  js/command-line-injection, js/prototype-pollution, js/zipslip, ...).
- **Prototype pollution and gadget chains, custom sink dataflow** → the
  `taint-analysis` skill with its JavaScript sink catalog
  (`child_process.*`, `vm.*`, `eval`, `fs.*`, Mongo query objects, deep-merge
  sinks) to trace sources to sinks manually.
- **Dependency vulnerabilities** are out of scope for njsscan entirely —
  hand `package.json` + lockfiles to the SCA tooling.
