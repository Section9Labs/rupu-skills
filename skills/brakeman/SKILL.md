---
name: brakeman
description: Static analysis of Ruby on Rails applications with Brakeman - run the scanner against a Rails repo, interpret warning types/confidence/user-input paths, tune ignores, emit JSON+SARIF, and convert results into rupu work units for triage, verification, and reporting. Use whenever the target codebase is a Rails app (Gemfile with rails, app/ + config/routes.rb present).
license: MIT
metadata:
  author: Section9Labs
---

# Brakeman - Rails Static Analysis

Brakeman is a purpose-built SAST scanner for Ruby on Rails. It parses the app
without running it, understands Rails conventions (routes, controllers, models,
views, filters, mass-assignment config), and performs dataflow from
`params`/`cookies`/`request` into dangerous sinks. It is the first tool to run
on any Rails codebase; follow up with `semgrep` ruby packs for non-Rails Ruby.

## 1. Install and detect the target

```sh
gem install brakeman          # or: gem install brakeman --pre for latest
brakeman --version
```

Confirm the repo is a Rails app before scanning: `Gemfile` referencing
`rails`, `config/routes.rb`, `app/controllers/`. Note the pinned Rails version
(`Gemfile.lock`) - Brakeman adjusts checks by Rails version (e.g. CVE checks,
default protections), and you should too. If Brakeman misdetects the version,
force it with `--rails7` / `--rails6` / `--rails5` / `--rails4` / `--rails3`.

## 2. Run the scan

From the app root, or pointed at it:

```sh
brakeman                      # scan current directory
brakeman -p /src/example-app  # scan a path
```

Standard full-signal invocation for an engagement (one run, both machine
formats plus a human summary on stdout):

```sh
brakeman -p /src/example-app -q --no-pager \
  -o brakeman.json -o brakeman.sarif -o brakeman.html
```

Output format is inferred from the extension; `-f json|sarif|html|csv|text|
markdown|codeclimate|junit|tabs` forces it, `--summary` prints only the
overview table. Key extras:

- `-A` / `--run-all-checks` - enable optional checks that are off by default
  (always use this on a security engagement).
- `-w1|-w2|-w3` - minimum confidence to report (1 = include Weak, 3 = High
  only). Default is 2. Use `-w1` when scanning for review; filter later.
- `--add-engine-path path/to/engine` - include Rails engines; repeatable.
  Scan `engines/` and `components/` directories explicitly, Brakeman does not
  descend into them by default.
- `--no-exit-on-warn --no-exit-on-error` - exit 0 even with findings, so CI
  wrappers and scripts don't misread warnings as crashes (exit code 3 =
  warnings found, 4 = errors, both with findings still written).
- `--interprocedural`, `--branch-limit 10` - deeper dataflow on large apps.
- `-t`/`-x` to run/skip specific checks, e.g. `-t SQL,Execute,Deserialize`.

Full flag reference: `references/cli.md`.

## 3. Read a warning

Each warning carries:

- **Check / warning_type** - e.g. `SQL Injection`, `Command Injection`,
  `Cross-Site Scripting`, `Remote Code Execution`. See the full catalog with
  vulnerable-code examples in `references/checks.md`.
- **Confidence** - High / Medium / Weak. High means Brakeman traced direct
  user input (`params[...]`) into the sink. Medium usually means indirect or
  model-attribute input. Weak means the sink is dangerous but the input source
  is unproven - these are still worth manual review, not auto-dismissal.
- **Message + file:line + code** - the exact sink expression, e.g.
  `User.where("name = '#{params[:name]}'")` at
  `app/controllers/users_controller.rb:42`.
- **User input path** - the tainted fragment Brakeman identified
  (`params[:name]`). For template XSS, `render_path` shows which
  controller action rendered the view - follow it to find where the value is
  assigned.
- **Fingerprint** - stable hash used by the ignore file; use it as the work
  unit id.
- **link / cwe_id** - Brakeman docs URL and CWE id(s) for the hint block.

Triage order: High-confidence injection/RCE classes first (SQL Injection,
Command Injection, Remote Code Execution, Unsafe Reflection, Deserialize,
Dangerous Send, Dynamic Render Path, File Access), then XSS variants, then
redirect/SSRF, then config classes (CSRF, session settings, secrets, default
routes, weak crypto, Regex DoS, mail_to).

## 4. Verify, don't just report

Brakeman shows the sink; you confirm reachability and exploitability:

1. Open the file:line. Trace the tainted value back through
   before_actions, strong parameters, and model scopes.
2. Check routing: is the action reachable (`config/routes.rb`,
   `rails routes` output if available)? Admin-only? Behind authentication?
3. Build the concrete exploit input. For
   `where("name = '#{params[:name]}'")` that is
   `?name=' OR '1'='1`; for `render params[:template]` that is
   `?template=../../config/environments/production` (dynamic render LFI) or a
   view path yielding RCE on older Rails; for `Marshal.load(cookies[:x])` a
   crafted Marshal payload. `references/checks.md` gives per-class payload
   shapes and what "exploitable" means for each warning type.
4. Downgrade/record false positives via the ignore file (next section) with a
   note, so reruns stay clean.

## 5. False positives, ignores, baselining

```sh
brakeman -I                     # interactive: step through warnings,
                                # (i)gnore, add note, (s)kip, quit+save
brakeman -i config/brakeman.ignore   # use a specific ignore file
brakeman --ensure-ignore-notes  # fail if ignore entries lack notes
```

`config/brakeman.ignore` is JSON keyed by warning fingerprint, so entries
survive line-number churn but break on code changes (good - forces re-review).
For diff-based scanning against a baseline:

```sh
brakeman -o new.json
brakeman --compare old.json     # emits {new: [...], fixed: [...]}
```

Audit the ignore file itself on every engagement - previously "ignored"
warnings are a classic place real bugs hide. `jq '.ignored_warnings[] |
{fingerprint, warning_type, file, note}' config/brakeman.ignore`.

## 6. Limits - route the rest

Brakeman only follows Rails conventions. It will miss:

- Plain Ruby services, Sinatra/Rack apps, rake tasks, background jobs with
  non-Rails entry points, metaprogramming-heavy code.
- Logic flaws, authz gaps (IDOR), business logic.
- Non-Ruby code and dependency CVEs (it checks some Rails gem CVEs, but is
  not an SCA tool - run `bundler-audit` / an SCA skill for `Gemfile.lock`).

Hand those off: load the `semgrep` skill with the ruby packs
(`p/ruby`, `p/rails`) for pattern coverage outside Rails conventions, and load
the `taint-analysis` skill (ruby sinks: `eval`, `send`, `constantize`,
`Open3`, `Kernel#open`, ERB construction) for manual source-to-sink tracing of
anything Brakeman marked Weak or did not model.

## 7. Parse and hand off (rupu)

```sh
# Run scan + convert in one step:
python3 scripts/run_brakeman.py -p /src/example-app -o out/

# Or convert existing output (Brakeman JSON and/or SARIF):
python3 scripts/brakeman_to_workunits.py out/brakeman.json \
  --sarif out/brakeman.sarif -o out/workunits.json
```

`out/workunits.json` is a clean top-level JSON array of
`{id, title, targets: ["path:line"], hints: {check, confidence, cwe, message,
code, user_input, link, rule, severity}}` - directly consumable by a rupu
workflow (`read_file` + `for_each:`) or a lead agent `dispatch` fan-out.

Then:

1. Mark coverage: record the repository, every scanned file, and the
   `Gemfile.lock` packages with `assets.mark` (examples in
   `references/rupu.md`).
2. Load the `work-units` skill to split the normalized findings into work
   units and distribute them to review agents.
3. Route `out/brakeman.sarif` to the `sarif-triage` skill for cross-tool
   dedup/merge with semgrep and other SARIF producers.
4. For each warning you verify exploitable, load the `finding-report` skill
   and file it with `findings.report` (fingerprint as id, file:line target,
   CWE, confidence, PoC input). Concrete call examples: `references/rupu.md`.
