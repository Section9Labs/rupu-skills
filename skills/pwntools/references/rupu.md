# rupu wiring for the pwntools skill

The working exploit script is the PoC artifact. This skill's outputs feed rupu as
follows — import the shared `work-units` and `finding-report` skills by name for
the generic mechanics; do not reinvent their contracts.

## Assets (`assets.mark`)

Binary profile asset model:

- kind `binary:file` — coordinates `t=file`, `v=<sha256 of the binary>` (or path
  when the hash is unavailable). Depth ladder (monotonic, never downgrade):
  `discovered -> triaged -> analyzed -> vuln-identified -> exploited`.
- kind `binary:symbol` — coordinates: the file's coordinates plus `t=symbol` with
  `v=<name>` (or `t=vaddr`, `v=0x...`) for the vulnerable function / sink
  (e.g. the function holding the overflowing `read`).

Marks made from this skill:

| moment | mark |
|---|---|
| `context.binary = ELF(...)` loads, checksec read | `binary:file` → `triaged` |
| offset found (`cyclic`/corefile), overflow confirmed | `binary:file` → `vuln-identified`; mark the vulnerable function as `binary:symbol` |
| `p.interactive()` yields a shell (local on the target build, or remote) | `binary:file` → `exploited` |

## Findings (`findings.report`)

When the exploit lands, file ONE finding via `findings.report` using the
`finding-report` skill's field contract. Include:

- the technique chain (e.g. "stack BOF → ret2plt puts leak → ret2libc system"),
- the exact offset, leaked symbol, resolved libc build (from
  `libc-identification`),
- the exploit script path and the `context.log_file` transcript path as evidence,
- target coordinates (binary sha256; remote `host:port` when exploited remotely,
  e.g. `203.0.113.10:1337`).

Do NOT write a separate report file — the finding record plus the script is the
deliverable.

## Work units

When a run of this skill surfaces follow-on work (unknown remote libc, a second
binary on the ssh box, a service variant on another port), emit a JSON array file
(content starts with `[`) of work units, each EXACTLY
`{id, title, targets, hints}`:

```json
[
  {
    "id": "identify-libc-target-203-0-113-10",
    "title": "Identify remote libc for ./target from puts/setvbuf leaks",
    "targets": [
      {"kind": "binary:file", "t": "file", "v": "<sha256>", "host": "203.0.113.10", "port": "1337"}
    ],
    "hints": ["libc-identification", "rop-chains"]
  }
]
```

- `id`: stable lowercase `[a-z0-9-]` slug.
- `targets`: non-empty array of target objects.
- `hints`: sorted array of short next-skill/tool names.

rupu `for_each:` fans these out; see the shared `work-units` skill.

## Evidence

Keep raw artifacts under the run workspace, never delete:

- `context.log_file` tube transcripts,
- corefiles used for offset discovery,
- the final exploit script and any staged payload dumps (`rop.dump()` output).
