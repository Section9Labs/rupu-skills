# rupu wiring — radare2

This skill parses tool output, so every run must end in rupu-ingestible data:
work units for fan-out, `assets.mark` for the asset graph, `findings.report`
for verified issues. Generic fan-out mechanics live in the shared `work-units`
skill; the finding field contract lives in the shared `finding-report` skill —
import both by name, do not reinvent them.

## Work units

`scripts/r2_triage.py` writes `<out>/work_units.json` — content starts with
`[`, so rupu `for_each:` JSON-parses it directly. Each element is exactly:

```json
{
  "id": "r2-sink-httpd-system",
  "title": "httpd: 2 call site(s) of system — trace argument provenance",
  "targets": [
    {"file": "/opt/fw/bin/httpd",
     "function": "system",
     "vaddr": "0x00401a30",
     "caller": "sym.do_cmd"}
  ],
  "hints": ["gdb-debugging", "ghidra-headless", "vuln-classes"]
}
```

Rules: `id` is a stable lowercase `[a-z0-9-]` slug (binary + sink, identical
across reruns); `targets` non-empty; `hints` sorted, naming the next skills —
`ghidra-headless` for the full decompiled-provenance pass, `gdb-debugging` for
dynamic confirmation at the call-site vaddr, `vuln-classes` for
classification.

```yaml
for_each: r2_out/work_units.json
```

## Assets (assets.mark)

Binary-profile asset model, monotonic depth ladder
`discovered -> triaged -> analyzed -> vuln-identified -> exploited`:

- kind `binary:file` — coordinate `t=file`, `v=<sha256 or path>` (the script
  prints the sha256). A completed triage run means at least `triaged`;
  if you also walked the callers interactively, `analyzed`:

  ```
  assets.mark kind=binary:file coords=[{t: file, v: <sha256>}] depth=triaged
  ```

- kind `binary:symbol` — coordinates: the file coordinate **plus**
  `t=symbol, v=<caller or sink name>` or `t=vaddr, v=<call-site>`. Each sink
  call site from `sink_xrefs.json` starts at `triaged`; promote to
  `vuln-identified` after you have shown attacker data reaches the sink:

  ```
  assets.mark kind=binary:symbol \
    coords=[{t: file, v: <sha256>}, {t: symbol, v: sym.do_cmd}, {t: vaddr, v: 0x00401a30}] \
    depth=vuln-identified
  ```

Depths never go down.

## Findings (findings.report)

Confirmed issue (e.g. `system()` fed by a `recv` buffer, verified in `pdf`
output or under `r2 -d`/the `gdb-debugging` skill): call rupu's
`findings.report` using the shared `finding-report` skill's field contract.
Evidence: the relevant `sink_xrefs.json` entry, the `pdf @ caller`
disassembly (save with `pdf @ sym.do_cmd > evidence.txt` or keep the JSON
dumps), protections from `info.json`. Do not write a separate report file.

## Evidence

Everything the script writes under `--out`
(`info.json`, `functions.json`, `imports.json`, `strings.json`,
`sink_xrefs.json`, `work_units.json`) is run evidence — keep it in the run
workspace, never delete it.
