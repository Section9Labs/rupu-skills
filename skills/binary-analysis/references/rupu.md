# rupu wiring for the binary-analysis pack

This file is the single source of truth for how every sub-skill in the
binary-analysis pack records assets, fans out work, and reports findings via
rupu. Sub-skills reference this file instead of restating the contract.

## Asset model (`assets.mark`)

Two asset kinds, one monotonic depth ladder.

### Kind `binary:file`

One asset per analyzed binary. Coordinate:

- `t=file`, `v=<sha256>` — preferred, stable across renames; or
- `t=file`, `v=<workspace-relative path>` when hashing is impractical
  (e.g. a file still inside a mounted firmware tree). Pick one scheme per run
  and stay consistent.

Depth ladder (monotonic — only move up, never down):

| Step | Meaning | Set by |
|---|---|---|
| `discovered` | File exists; nothing known yet | intake, `binwalk-firmware` carving |
| `triaged` | Identified; strings/symbols/protections recorded | `binary-triage`, `binary-protections` |
| `analyzed` | Static RE done; function/sink inventory exists | `ghidra-headless`, `radare2` |
| `vuln-identified` | At least one bug confirmed dynamically | `vuln-classes` (+ Phase 3 skills) |
| `exploited` | Working exploit/primitive demonstrated | Phase 5 skills |

Example:

```
assets.mark kind=binary:file coords=[{t:file, v:3a1f…9c}] depth=triaged \
  note="ELF64 x86-64, dynamic, not stripped; NX+canary, no PIE, partial RELRO"
```

### Kind `binary:symbol`

One asset per interesting function/sink inside a file. Coordinates: the file
coordinate **plus** one of:

- `t=symbol`, `v=<name>` (e.g. `v=parse_packet`) when symbols exist; or
- `t=vaddr`, `v=<hex address>` (e.g. `v=0x401a30`) for stripped binaries.

```
assets.mark kind=binary:symbol \
  coords=[{t:file, v:3a1f…9c}, {t:symbol, v:parse_packet}] depth=analyzed \
  note="recv() buffer -> memcpy with attacker-controlled length at 0x401a7c"
```

Symbols follow the same ladder; a symbol at `vuln-identified` means the bug
lives in that function.

## Work units and fan-out

When Phase 1 (or Phase 2) yields multiple things to work on, emit a clean JSON
array file — content must start with `[` — of work units, each object EXACTLY:

```json
[
  {
    "id": "fw-httpd-elf",
    "title": "Analyze httpd carved from example.com router firmware",
    "targets": [
      {"kind": "binary:file", "file": "carved/squashfs-root/usr/sbin/httpd",
       "sha256": "3a1f…9c", "arch": "mips32be"}
    ],
    "hints": ["binary-protections", "binary-triage", "qiling-unicorn"]
  },
  {
    "id": "httpd-parse-packet-sink",
    "title": "Trace memcpy sink in httpd:parse_packet",
    "targets": [
      {"kind": "binary:symbol", "file": "carved/squashfs-root/usr/sbin/httpd",
       "symbol": "parse_packet", "vaddr": "0x401a30"}
    ],
    "hints": ["angr", "gdb-debugging", "vuln-classes"]
  }
]
```

Rules:

- `id`: stable lowercase slug, `[a-z0-9-]` only.
- `title`: human-readable, one line.
- `targets`: non-empty array of target objects (shape above; include whatever
  coordinates the next skill needs — path, hash, symbol, vaddr, arch).
- `hints`: **sorted** array of short strings naming the next skill/tool to run.

Granularity: one unit per binary for Phase 1→2 fan-out; one unit per candidate
sink/function for Phase 2→3/4 fan-out.

Fan-out mechanics — import the shared **`work-units`** skill by name; do not
reimplement. Two consumption paths:

- A rupu workflow step uses `for_each:` with `read_file` on the work-units
  file; rupu JSON-parses it (the file content must start with `[`) and runs
  the step body once per unit.
- A lead agent reads the file and uses `dispatch` to hand each unit to a
  worker agent, passing the unit object as the brief.

Write work-units files under the run workspace, e.g.
`work/<run>/units/binaries.json`, `work/<run>/units/sinks-httpd.json`.

## Findings (`findings.report`)

Record every verified bug with rupu's `findings.report` tool — import the
shared **`finding-report`** skill by name for the exact field contract. Do not
write a separate report file. A binary-pack finding should carry:

- the `binary:file` / `binary:symbol` coordinates (hash, path, symbol, vaddr),
- the vulnerability class (from `vuln-classes`) and the primitive it yields,
- reproduction: crash input path, exact command, gdb state excerpt,
- exploitation status (crash-only / primitive demonstrated / full exploit) and
  the exploit script path when one exists.

Report at `vuln-identified` time; update/attach the exploit when the asset
reaches `exploited`.

## Evidence discipline

All raw tool output stays under the run workspace as evidence — checksec and
rabin2 dumps, Ghidra decompilation exports, r2pipe JSON, strace/ltrace logs,
fuzzer queues and crash dirs, gdb session logs, angr solver outputs, exploit
scripts and their transcripts. Suggested layout:

```
work/<run>/
  triage/<sha256>/        file.txt strings.txt rabin2.json checksec.txt
  carved/                 binwalk extraction trees
  static/<sha256>/        ghidra-export/ r2/
  dynamic/<sha256>/       traces/ gdb/ crashes/ angr/
  fuzz/<sha256>/          in/ out/
  exploits/<sha256>/      exploit.py transcript.log
  units/                  *.json work-units files
```

Never delete anything under the workspace; findings and asset notes should
point at these paths.
