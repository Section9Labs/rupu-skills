# rupu wiring for libc-identification

This skill parses `find`/`dump` (or libc.rip API) output; it must end by
producing rupu-ingestible data. Import the shared `work-units` skill for the
generic fan-out mechanics and the shared `finding-report` skill for the
findings field contract — do not reinvent either.

## Work units

`scripts/libc_id.py` writes `libc-id-work-units.json` in the run workspace: a
clean JSON array (file content starts with `[` so rupu `for_each:` can parse
it). Each object is EXACTLY `{id, title, targets, hints}`:

```json
[
  {
    "id": "libc-match-libc6-2-31-0ubuntu9-9-amd64",
    "title": "Matched libc libc6_2.31-0ubuntu9.9_amd64 (base 0x7f3c6a400000)",
    "targets": [
      {"t": "libc-id", "v": "libc6_2.31-0ubuntu9.9_amd64"},
      {"t": "libc-base", "v": "0x7f3c6a400000"}
    ],
    "hints": ["heap-exploitation", "one_gadget", "rop-chains"]
  }
]
```

- `id`: stable lowercase slug derived from the build id (and `-candidate-N`
  when multiple builds remain).
- `targets`: never empty; one object per matched build, plus the computed
  base when full leak addresses were supplied.
- `hints`: sorted short strings naming the next skill/tool.

Ambiguous match (N candidates) → N units, each hinting
`libc-identification` again ("narrow with a second symbol").

## Assets (rupu `assets.mark`)

Depth ladder (monotonic): discovered → triaged → analyzed → vuln-identified
→ exploited.

- kind `binary:file`, coordinate `t=file, v=<sha256 of downloaded db/<id>.so
  or its path>` — mark `analyzed` once the build is identified and offsets
  dumped.
- kind `binary:symbol`, coordinates: the file plus `t=symbol` for each
  resolved sink (`system`, `str_bin_sh`, `__free_hook`, `_IO_list_all`,
  one_gadget vaddrs as `t=vaddr`). Mark `triaged` when resolved; the
  consuming skill (`rop-chains`/`heap-exploitation`) raises them to
  `exploited` when used in a working chain.

## Findings

Libc identification alone is not a finding. The upstream leak (info
disclosure) and the downstream code execution are findings — report them
with rupu's `findings.report` from the skill that proved them, per the
shared `finding-report` contract, attaching the matched libc id and base in
the evidence.

## Evidence

Keep raw output under the run workspace, never delete:
`evidence/libc-find.txt` (verbatim `./find` output), `evidence/libc-dump-
<id>.txt`, raw libc.rip JSON responses, and the downloaded `.so` files.
