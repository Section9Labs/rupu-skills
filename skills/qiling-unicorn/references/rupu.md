# rupu wiring — qiling-unicorn

This skill parses emulation output (traces, hook logs, recovered algorithm results).
Every session MUST end with rupu-ingestible data. Do not reinvent formats: use the
shared `work-units` skill for fan-out mechanics and the shared `finding-report` skill
for the findings field contract.

## 1. Work units (fan-out to next skills)

Emit ONE clean JSON array file (content starts with `[` so rupu `for_each:` can parse
it). Each object has EXACTLY the keys `{id, title, targets, hints}`:

- `id`: stable lowercase slug `[a-z0-9-]`, e.g. `emu-httpd-authcheck-0x40a310`
- `title`: human-readable, e.g. `httpd auth check reachable with attacker stdin`
- `targets`: non-empty array of target objects, e.g.
  `{"file": "squashfs-root/usr/sbin/httpd", "sha256": "<hex>", "vaddr": "0x40a310", "arch": "mips32el"}`
- `hints`: **sorted** array of short strings naming the next skill/tool, e.g.
  `["angr", "pwntools", "rop-chains"]`

`scripts/qiling_run.py --work-units units.json` emits this file automatically (one
unit per hooked-function hit site plus one for the binary overall). Hand-written
example:

```json
[
  {
    "id": "emu-upnpd-stackbof-0x40a310",
    "title": "upnpd: 2048-byte memcpy into 512-byte stack buffer reached under emulation",
    "targets": [
      {"file": "squashfs-root/usr/sbin/upnpd",
       "sha256": "3b1f...c9", "vaddr": "0x40a310", "arch": "mips32"}
    ],
    "hints": ["angr", "pwntools", "rop-chains"]
  }
]
```

## 2. Assets — `assets.mark`

Binary profile asset model:

- kind `binary:file` — coordinate `t=file`, `v=<sha256>` (preferred) or `v=<path>`.
- kind `binary:symbol` — coordinates: the file coordinate PLUS `t=symbol`,
  `v=<name>` or `t=vaddr`, `v=0x40a310` for interesting functions/sinks.

Depth ladder (monotonic — never lower a depth):

`discovered -> triaged -> analyzed -> vuln-identified -> exploited`

Mapping for this skill:

| Event in emulation | mark |
|---|---|
| Binary loads and runs under Qiling | `binary:file` -> `triaged` |
| Full trace / call map collected, functions identified | `binary:file` -> `analyzed`; interesting fns as `binary:symbol` -> `analyzed` |
| Crash with attacker-controlled data, injected input reaches `system()`/`strcpy` sink, self-check bypassed to reach gated code | `binary:symbol` (the sink) -> `vuln-identified` |
| Working PoC input (fuzz crash replayed, brute-forced credential accepted, snapshot-replay exploit) | `binary:symbol` -> `exploited` |

## 3. Findings — `findings.report`

Report verified issues via rupu's `findings.report` tool; the field contract lives in
the shared `finding-report` skill. Do NOT write a standalone report file. Typical
qiling-unicorn findings:

- **Recovered algorithm/secret**: decrypted config blob, hardcoded credential found by
  brute under snapshot/restore, recovered checksum/keygen algorithm. Evidence: the
  Unicorn/Qiling harness script + recovered plaintext/key + the trace JSON.
- **Emulated-reachable vulnerability**: injected input via `set_syscall("read", ...)`
  reaches a dangerous sink (`system`, unbounded `strcpy`, format string) — include the
  exact input bytes, the hook log line showing the sink arguments, and the PC/register
  dump at the fault.
- **Anti-analysis bypass of security relevance**: self-check patched out exposing a
  gated backdoor path — include the patch (addr + bytes) and the post-patch trace.

Severity honestly: a crash is not automatically critical; attacker reachability in the
*real* deployment (network-facing CGI vs. local-only helper) sets it.

## 4. Evidence

Keep under the run workspace, never delete:
- `trace.json` / `units.json` from `scripts/qiling_run.py`
- Qiling `log_file` output, drcov coverage files
- snapshot files (`state.bin`), fuzz corpus + crashes directory
- harness scripts themselves (they are the reproduction steps)
