# rupu wiring for retire-js output

This file shows how to plug the retire-js work-unit array into rupu. The
splitting itself is owned by the shared `work-units` skill and reporting by
the `finding-report` skill — load both BY NAME; do not re-implement them here.

## 1. Produce the work-unit array

```sh
python3 scripts/run_retirejs.py /work/example.com-webapp \
        --out retire.json --workunits workunits.json
```

`workunits.json` is a clean top-level JSON array — rupu's `for_each:`
JSON-parses any value starting with `[`, so no wrapping object, no trailing
prose.

## 2. Workflow: `read_file` + `for_each:` over the array

```yaml
steps:
  - id: scan
    run: >
      python3 skills/retire-js/scripts/run_retirejs.py /work/example.com-webapp
      --out retire.json --workunits workunits.json

  - id: load_units
    tool: read_file
    args:
      path: workunits.json

  - id: triage_unit
    for_each: "{{ steps.load_units.output }}"   # parsed as JSON array
    prompt: |
      Load the `work-units` skill. You are verifying one Retire.js finding:
        component: {{ item.targets[0] }}
        file:      {{ item.hints.file }}
        advisory:  {{ item.hints.cve }} ({{ item.hints.severity }})
        summary:   {{ item.title }}
      Confirm the detected version in the file, determine whether the
      vulnerable API/sink is reachable from application code (grep usages,
      trace data flow from user input), and exploit the reachable sink to
      demonstrate impact. Then load the `finding-report` skill and file the
      result with findings.report.
```

## 3. Lead-agent fan-out with `dispatch`

```text
units = json.parse(read_file("workunits.json"))
for unit in units:
    dispatch(
      agent="code-review-worker",
      skill_hints=["retire-js", "work-units", "finding-report"],
      payload=unit,
      title=unit["title"],
    )
```

One unit per worker. Each worker loads the `work-units` skill to interpret
the unit shape and the `finding-report` skill to file verified issues.

## 4. Coverage: `assets.mark`

Mark the repo, the scanned trees, and every detected component so coverage is
trackable even when a component turns out clean or waived:

```text
assets.mark(kind="repository", id="example.com-webapp",
            attrs={"vcs": "git", "tool": "retire-js"})

assets.mark(kind="path", id="example.com-webapp:static/vendor/",
            attrs={"scanner": "retire-js", "scope": "js"})

assets.mark(kind="package", id="npm:jquery@1.8.1",
            attrs={"file": "static/vendor/jquery.min.js",
                   "detection": "filecontent",
                   "scanner": "retire-js",
                   "status": "scanned"})
```

Emit one `assets.mark(kind="package", ...)` per unique `component@version` in
the retire.json report (including non-vulnerable detections when running with
`--verbose`), and one `kind="path"` per directory tree passed to `--path` /
`--jspath`.

## 5. Reporting: `findings.report` (via the `finding-report` skill)

For each VERIFIED vulnerable library, load the `finding-report` skill and file:

```text
findings.report(
  title="Vulnerable bundled library: jquery 1.8.1 (CVE-2012-6708) — XSS via selector-as-HTML",
  asset="npm:jquery@1.8.1",
  severity="medium",
  cwe="CWE-1104",
  evidence={
    "file": "static/vendor/jquery.min.js",
    "detection": "filecontent",
    "advisories": ["CVE-2012-6708", "GHSA-2pqj-h3vj-pqgw"],
    "vulnerable_range": ">=1.0.0 <1.9.0",
    "reachable_sink": "app/js/search.js:42 passes location.hash into $()",
    "poc": "https://example.com/search#<img src=x onerror=alert(document.domain)>"
  },
  remediation="Upgrade bundled jQuery to >=1.9.0 (current LTS preferred); replace vendored copy with a lockfile-managed dependency so SCA can track it."
)
```

Use the advisory's `below` field as the minimum fix version, the `info` URLs
as references, and attach the reachability/PoC evidence gathered during
verification — the raw retire.json entry goes in as supporting evidence, not
as the finding itself.

— vulture (fuchsia-pavilion)
