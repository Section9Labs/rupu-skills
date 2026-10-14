# rupu wiring — ghidra-headless

This skill parses tool output, so every run must end in rupu-ingestible data:
work units for fan-out, `assets.mark` for the asset graph, `findings.report`
for verified issues. Generic fan-out mechanics live in the shared `work-units`
skill; the finding field contract lives in the shared `finding-report` skill —
import both by name, do not reinvent them.

## Work units

`scripts/ghidra_headless.py` writes `<out>/work_units.json` — a file whose
content starts with `[`, so rupu `for_each:` can JSON-parse it directly. Each
element is exactly:

```json
{
  "id": "ghidra-sink-httpd-strcpy",
  "title": "httpd: 3 call site(s) of strcpy — trace argument provenance",
  "targets": [
    {"file": "/firmware/squashfs-root/bin/httpd",
     "function": "handle_request",
     "vaddr": "0x0040129c",
     "reason": "unbounded copy — overflow if source is attacker-controlled"}
  ],
  "hints": ["gdb-debugging", "vuln-classes"]
}
```

Rules: `id` is a stable lowercase `[a-z0-9-]` slug (binary + sink — reruns
produce the same ids); `targets` is never empty; `hints` is sorted and names
the next skills to run.

```yaml
for_each: gh_out/work_units.json
```

## Assets (assets.mark)

Binary-profile asset model, monotonic depth ladder
`discovered -> triaged -> analyzed -> vuln-identified -> exploited`:

- kind `binary:file` — coordinate `t=file`, `v=<sha256 or path>`
  (`meta.json` in each program's export dir carries the sha256). After a
  successful export run, mark it `analyzed`:

  ```
  assets.mark kind=binary:file coords=[{t: file, v: <sha256>}] depth=analyzed
  ```

- kind `binary:symbol` — coordinates: the file coordinate **plus**
  `t=symbol, v=<name>` or `t=vaddr, v=<0x...>`. Mark each candidate sink from
  `xrefs.json` as `triaged`; promote to `vuln-identified` only after the
  argument-provenance walk (decompiled C) shows attacker-reachable data:

  ```
  assets.mark kind=binary:symbol \
    coords=[{t: file, v: <sha256>}, {t: symbol, v: handle_request}, {t: vaddr, v: 0x0040129c}] \
    depth=vuln-identified
  ```

Never lower a depth; the ladder is monotonic.

## Findings (findings.report)

When a sink is confirmed (static provenance is airtight, or dynamic
confirmation via the `gdb-debugging` skill), call rupu's `findings.report`
with the field contract from the shared `finding-report` skill. Evidence to
attach/reference: the decompiled function file
(`<out>/<prog>/decompiled/<fn>_<vaddr>.c`), the `xrefs.json` entry, and the
call-site vaddr. Do not write a separate report file.

## Evidence

Everything under `--out` (per-program JSON/text/decompiled C plus
`analyzeHeadless.log`) is run evidence. Keep it in the run workspace; never
delete it. The Ghidra *project* is disposable (`-deleteProject`) unless you
plan interactive follow-up in the GUI — then keep `--project-dir` and re-run
with `--process`.
