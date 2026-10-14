---
name: retire-js
description: Scan JavaScript/Node codebases with Retire.js to detect known-vulnerable JS libraries — including bundled, minified, copy-pasted or CDN-vendored front-end libs (jquery, angular, bootstrap, lodash...) that lockfile-based SCA misses — and normalize results into rupu work units for triage, verification, and reporting.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Retire.js — known-vulnerable JavaScript library scanner

Retire.js detects JavaScript libraries with published vulnerabilities. Its
unique strength over lockfile SCA: it **fingerprints library files by
content** — filename patterns, embedded version comments, content hashes, and
AST/regex signatures — so it identifies a minified `jquery-1.8.1.min.js`
dropped into `static/vendor/` even when no `package.json` or lockfile mentions
it. Use it on every engagement that has front-end assets, built `dist/`
output, or vendored JS.

## 1. Install / update

```sh
npm install -g retire
retire --version
```

Retire.js downloads its vulnerability repository (`jsrepository-v4.json`) on
each run and caches it (`~/.retire-cache/`). Force a fresh pull with
`--nocache`; behind TLS interception use `--insecure`; behind a proxy use
`--proxy http://198.51.100.7:8080`.

## 2. Run the scan

From the repo root or against any directory:

```sh
retire --path /work/example.com-webapp --outputformat json --outputpath retire.json
```

Key points:

- `--path <dir>` — directory to scan (default: cwd). Point it at the **built
  output** too (`dist/`, `build/`, `public/`, `static/`, `wwwroot/`,
  `assets/vendor/`) — that is where fingerprinting of bundled/minified libs
  pays off. Scan both source and build trees in separate runs if they differ.
- Scopes: legacy versions support `--js` (scan only JS files) and `--node`
  (scan only node modules/`package.json`); use `--jspath <dir>` /
  `--nodepath <dir>` to point each scope at a different tree. Retire.js v3+
  is JS-file focused by default — route full npm dependency-tree scanning to
  the `osv-scanner`, `grype-syft`, or `dependency-check` skills.
- `--deep` scans inside files it would otherwise skip; `--ext js,map,html`
  widens the extension list (HTML gets inline `<script src=...>` references
  checked too).
- `--severity high` gates the non-zero exit on severity ≥ high;
  `--exitwith 13` sets the exit code used when vulnerabilities are found
  (default 13 — anything else from the process means a tool error, not
  findings).
- `--ignorefile .retireignore.json` / repeated `--ignore <path|component>`
  waive accepted findings. Ignore-file schema and all flags: see
  `references/cli.md`.
- Output formats: `--outputformat json|text|cyclonedx|cyclonedx-json|depcheck`
  with `--outputpath <file>`. Use `json` for the pipeline; `cyclonedx` when
  you need an SBOM artifact for other tooling.

Typical full invocation:

```sh
retire --path /work/example.com-webapp \
       --outputformat json --outputpath retire.json \
       --severity low --exitwith 13 \
       --ignorefile .retireignore.json --verbose
```

Exit code 0 = clean, 13 (or `--exitwith` value) = vulnerable libs found.

## 3. Read the output

JSON structure (v3/v4): `{"version": ..., "data": [...], "errors": [...]}` —
each `data[]` entry is a scanned **file** with `results[]`, each result a
detected **component** (`component`, `version`, `detection`) carrying
`vulnerabilities[]`:

- `severity` — low / medium / high / critical.
- `identifiers` — `CVE` (array), `githubID` (GHSA), `issue`, `bug`,
  `summary` (one-line description).
- `info` — URLs to advisories/release notes (use these during verification).
- `below` / `atOrAbove` — the vulnerable version range; compare against the
  detected `version` to confirm the match and against the fix boundary when
  recommending an upgrade target.

Verification workflow per finding: confirm the detected version (open the
file — version is usually in the banner comment or `jQuery.fn.jquery` style
constants), confirm the vulnerable code path is actually reachable in the app
(e.g. jQuery `$.parseHTML`/`.html()` XSS sinks fed with attacker input,
AngularJS sandbox escapes in templates rendering user data), and then build a
concrete PoC against the app where feasible — a fingerprinted vulnerable lib
plus a reachable sink is an exploitable issue, not just an inventory entry.

## 4. Normalize → work units → fan-out (rupu)

Helper scripts (Python 3 stdlib):

```sh
# one-shot: run retire + emit work units
python3 scripts/run_retirejs.py /work/example.com-webapp \
        --out retire.json --workunits workunits.json

# or parse an existing report
python3 scripts/retirejs_to_workunits.py retire.json -o workunits.json
```

`workunits.json` is a **clean top-level JSON array**:

```json
[{"id": "retirejs-3f2a1c9d", "title": "jquery@1.8.1 — CVE-2012-6708",
  "targets": ["jquery@1.8.1"],
  "hints": {"file": "static/vendor/jquery.min.js", "severity": "medium",
            "cve": "CVE-2012-6708", "identifiers": {...}, "below": "1.9.0"}}]
```

Handoff:

1. Load the `work-units` skill to split/shape the normalized findings into
   work units for the crew (do not re-invent the splitter).
2. `assets.mark` the repository, the scanned JS trees, and **every detected
   component@version** as covered assets.
3. Fan out: a rupu workflow consumes `workunits.json` with `read_file` +
   `for_each:`; a lead agent dispatches one unit per sub-agent. Concrete
   workflow YAML, `dispatch` pattern, and example `assets.mark` /
   `findings.report` calls: `references/rupu.md`.
4. For each **verified** vulnerable library, load the `finding-report` skill
   and file it with `findings.report` (component, version, file path, CVE/GHSA,
   severity, reachable sink / PoC evidence, fix version from `below`).

## 5. Where retire-js fits in the SCA step

| Signal | Tool |
|---|---|
| Vendored/minified/CDN-copied front-end JS by content | **retire-js (this skill)** |
| npm dependency tree via lockfiles (package-lock, yarn.lock, pnpm) | `osv-scanner` skill |
| Container images / SBOM-wide | `grype-syft` skill |
| Multi-ecosystem CVE sweep incl. JARs with bundled JS | `dependency-check` skill |

Run retire-js **in addition to** the lockfile scanners — overlap is expected,
but each run surfaces libs the others cannot see.

— vulture (fuchsia-pavilion)
