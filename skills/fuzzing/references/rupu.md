# rupu wiring for fuzzing

This skill parses fuzzer output (crash dirs, ASan reports), so it must end
by producing rupu-ingestible data. Import the shared `work-units` and
`finding-report` skills by name for the generic mechanics; this file maps
fuzzing results onto them.

## Work units: unique crashes → fan-out

`scripts/triage_crashes.py --units units.json` writes a clean JSON array
(file content starts with `[`, so rupu `for_each:` can JSON-parse it
directly). One unit per **unique crash signature** (bug class + top
non-sanitizer frames), each object exactly:

```json
{
  "id": "heap-buffer-overflow-parse-chunk-a1b2c3",
  "title": "heap-buffer-overflow in parse_chunk (3 crashing inputs)",
  "targets": [
    {
      "file": "/work/targets/example_parser",
      "crash_input_path": "/work/out/main/crashes/id:000004,sig:06,...",
      "bug_class": "heap-buffer-overflow",
      "faulting_function": "parse_chunk",
      "frames": ["parse_chunk", "parse_file", "LLVMFuzzerTestOneInput"]
    }
  ],
  "hints": ["gdb-debugging", "pwntools", "vuln-classes"]
}
```

- `id`: stable lowercase `[a-z0-9-]` slug derived from the signature —
  re-running triage on the same crashes yields the same ids (idempotent
  fan-out).
- `targets`: non-empty; one entry per distinct crashing input kept for the
  signature (the smallest/minimized one first).
- `hints`: sorted; always includes `vuln-classes` (classification is the
  next step), plus `gdb-debugging` and the likely exploitation skill once
  known (`heap-exploitation`, `rop-chains`, `format-string-exploitation`,
  `pwntools`).

Typical rupu stanza (see the `work-units` skill for the full contract):

```yaml
- run: python3 skills/fuzzing/scripts/triage_crashes.py --crash-dir out --target './target_asan @@' --units units.json
- for_each: units.json
  do: ...   # per-crash classification/exploitation flow
```

## Assets: assets.mark

Binary-profile asset model, monotonic depth ladder
`discovered -> triaged -> analyzed -> vuln-identified -> exploited`:

- `binary:file` — coordinate `t=file`, `v=<sha256 of the binary>` (fallback:
  absolute path). Mark `triaged` when the campaign produced crashes;
  `analyzed` once every unique crash has been replayed and classified;
  `vuln-identified` when `vuln-classes` confirms a class; `exploited` is
  owned by the exploitation skills.
- `binary:symbol` — coordinates: the file coordinate plus `t=symbol`,
  `v=<faulting function name>` (or `t=vaddr`, `v=0x401100` when stripped).
  Mark each faulting function `triaged` at crash time, `vuln-identified`
  after classification.

Never lower a depth; `assets.mark` calls are additive.

## Findings: findings.report

A crash is a **finding** once confirmed, i.e. it reproduces outside the
fuzzer and the ASan class implies a primitive (controlled PC, OOB write,
UAF, double-free, controlled format string). Report it with rupu's
`findings.report` tool using the field contract from the shared
`finding-report` skill. Include as evidence:

- the minimized crashing input path (afl-tmin / `-minimize_crash=1` output),
- the full ASan report text,
- the exact replay command (`./target_asan crash.min`, env vars included),
- fuzzer provenance (engine, node name, `id:` filename, `fuzzer_stats`).

Severity: lead with the primitive, not the crash — a write-what-where UAF
outranks a read-only OOB read.

## Evidence retention

Keep the entire fuzzer output tree under the run workspace: `out/<node>/`
(queue, crashes, hangs, `fuzzer_stats`, `plot_data`), honggfuzz
`HONGGFUZZ.REPORT.TXT` + crash files, libFuzzer `crash-*`/`fuzz-*.log`,
and every ASan report captured by `triage_crashes.py` (run it with
`--save-reports` so it writes `<crash>.asan.txt` next to each replayed
input). Never delete raw output.
