# rupu wiring — binary-triage

Triage parses tool output, so it MUST end by producing rupu-ingestible data.
Three channels: work units (fan-out), assets (state), findings (verified
issues). Raw tool output stays on disk under the run workspace as evidence —
never deleted.

## Work units

`scripts/triage.py -o work-units.json` writes a clean JSON **array** (file
content starts with `[`, which is what rupu's `for_each:` JSON-parses). One
unit per input binary, each object EXACTLY `{id, title, targets, hints}`:

```json
[
  {
    "id": "target-3f1a9b2c",
    "title": "Triage follow-up: target (ELF x86-64 64-bit)",
    "targets": [
      {
        "file": "/work/samples/target",
        "sha256": "3f1a9b2c4d5e…",
        "format": "elf",
        "arch": "x86-64",
        "bits": 64,
        "pie": true,
        "stripped": true,
        "dangerous_imports": ["gets", "printf", "system"]
      }
    ],
    "hints": ["binary-protections", "ghidra-headless", "radare2"]
  }
]
```

Rules:
- `id`: stable lowercase `[a-z0-9-]` slug — slugified basename plus the first
  8 hex chars of the sha256, so re-runs on the same sample dedupe.
- `targets`: non-empty; one target object per binary with the fields above.
- `hints`: **sorted** array of short strings naming the next skill/tool.
  Triage always emits `binary-protections`; add `ghidra-headless` and
  `radare2` when there is code to reverse, `pwntools` when a trivially
  reachable sink (e.g. `gets` on stdin) is already confirmed.

Generic fan-out mechanics (how units are claimed, retried, merged): see the
shared **`work-units`** skill — do not reinvent its contract here.

## Assets — `assets.mark`

Asset model for this domain:

- kind **`binary:file`** — coordinate `{t: file, v: <sha256>}` (fall back to
  path only if hashing is impossible). Depth ladder, monotonic:

  `discovered → triaged → analyzed → vuln-identified → exploited`

  Triage moves a binary from `discovered` to **`triaged`**:

  ```
  assets.mark  kind=binary:file  coords=[{t: file, v: 3f1a9b2c4d5e…}]
               depth=triaged
               note="target: ELF x86-64 PIE, dynamic, stripped; dangerous imports:
                     gets,printf,system; surface: stdin+network"
  ```

  Never mark downward: if another unit already marked `analyzed`, a late
  triage re-run must not reset it (rupu enforces monotonicity; don't fight it).

- kind **`binary:symbol`** — for interesting functions/sinks found during
  triage. Coordinates: the file coordinate PLUS either `{t: symbol, v: name}`
  or `{t: vaddr, v: 0x401a30}` for stripped binaries:

  ```
  assets.mark  kind=binary:symbol
               coords=[{t: file, v: 3f1a9b2c…}, {t: symbol, v: gets}]
               depth=discovered
               note="imported; call site unknown yet — xref in radare2"
  ```

`scripts/triage.py` prints the exact `assets.mark` line per binary at the end
of its report (prefixed `[rupu]`) so the operator or orchestrator can replay
it verbatim.

## Findings — `findings.report`

Triage itself rarely proves a vulnerability, but it DOES surface instant
findings: hardcoded credentials, private keys, internal URLs. Report those
immediately with rupu's `findings.report` tool — field contract lives in the
shared **`finding-report`** skill (import it by name; do not write a separate
report file). Attach the evidence path (the saved `strings` output) and the
string's file offset so the claim is reproducible.

Everything that is merely *suspicious* (dangerous import, `%n` format string)
is NOT a finding yet — it is a work-unit hint for `binary-protections` /
`ghidra-headless` / `radare2` to confirm, and a `binary:symbol` asset at
`discovered`.
