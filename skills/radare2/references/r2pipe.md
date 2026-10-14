# r2pipe — Python automation over radare2 / rizin

r2pipe spawns (or connects to) an r2 instance and gives you two calls:
`cmd(str) -> str` and `cmdj(str) -> parsed JSON`. That's the whole API — all
power comes from the command set (see radare2.md).

## Setup

```
pip install r2pipe        # radare2
pip install rzpipe        # rizin (identical API, import rzpipe)
```

The module shells out to `radare2`/`rizin` on PATH. Under the hood it runs
`r2 -q0 <file>`: commands go in on stdin terminated by `\n`, output comes back
NUL-terminated — trivial to reimplement with `subprocess` if the module is
missing (the shipped `scripts/r2_triage.py` does exactly that as a stdlib
fallback).

## Open modes

```python
import r2pipe
r2 = r2pipe.open("./target")                      # spawn, no analysis
r2 = r2pipe.open("./target", flags=["-A", "-2"])  # pass CLI flags
r2 = r2pipe.open("gdb://192.0.2.10:1234", flags=["-d"])   # remote debug
r2 = r2pipe.open("http://198.51.100.7:9090")      # connect to `r2 -c '=h 9090'`
r2 = r2pipe.open()                                # inside an r2 session (#!pipe)
...
r2.quit()                                         # always close (kills child)
```

## cmd vs cmdj

- `r2.cmd("pdf @ main")` — raw text, exactly what the console would print.
- `r2.cmdj("aflj")` — runs the command and `json.loads` the output. **Always
  prefer the `j` variant in scripts**; text output formats drift between
  versions, JSON is stable. If a command has no output `cmdj` returns `None`;
  wrap in a helper that maps `None`→`[]`.

Multiple commands: `r2.cmd("aaa; s main; pdf")` (semicolon-chained, returns
concatenated output).

## Common JSON shapes (abbreviated; fields can vary slightly by version)

`aflj` — list of functions:
```json
[{"offset": 4198496, "name": "sym.main", "size": 348, "nbbs": 12,
  "signature": "int main (int argc, char **argv);",
  "callrefs": [{"addr": 4198700, "type": "CALL", "at": 4198560}]}]
```
`offset` is the entry vaddr as an **integer** — format with `hex()`.

`iij` — imports:
```json
[{"ordinal": 1, "bind": "GLOBAL", "type": "FUNC", "name": "strcpy",
  "plt": 4198432, "libname": ""}]
```
`plt` (when present) is the address `axt` wants; otherwise use the flag name
`sym.imp.strcpy`.

`izzj` / `izj` — strings:
```json
[{"vaddr": 4210000, "paddr": 12000, "length": 23, "size": 24,
  "section": ".rodata", "type": "ascii", "string": "cmd: %s"}]
```
(older versions base64-encode `string` in izzj — check for a `string` vs
`name` field and decode if needed).

`axtj @ sym.imp.system` — xrefs to:
```json
[{"from": 4198700, "type": "CALL", "opcode": "call sym.imp.system",
  "fcn_addr": 4198496, "fcn_name": "sym.main"}]
```

`iIj` — binary info / protections:
```json
{"arch": "x86", "bits": 64, "canary": false, "nx": true, "pic": true,
 "relro": "full", "stripped": false, "static": false, "class": "ELF64",
 "lang": "c", "os": "linux"}
```

`pdfj @ addr` — function disassembly with per-op objects (`offset`, `esil`,
`bytes`, `disasm`, `jump`, `fail`) — enough to build your own CFG walker.

`drj` (debugging) — registers as a dict; `dmj` — memory maps.

## Patterns

Sink hunt core loop:

```python
r2 = r2pipe.open("./target"); r2.cmd("aaa")
imports = {i["name"] for i in r2.cmdj("iij") or []}
for sink in ("system", "strcpy", "gets", "memcpy"):
    if sink not in imports:
        continue
    for x in r2.cmdj(f"axtj @ sym.imp.{sink}") or []:
        print(f'{sink} <- {hex(x["from"])} in {x.get("fcn_name")}')
        # pull the caller's disassembly for argument provenance:
        listing = r2.cmd(f'pdf @ {x.get("fcn_addr", x["from"])}')
r2.quit()
```

Walk callers toward the entry point: `axtj @ <fcn_addr>` on each caller,
repeat; or read `callrefs`/`codexrefs` straight out of `aflj`.

ROP gadgets as JSON: `r2.cmdj("/Rj pop rdi")`. Writing/patching: open with
`flags=["-w"]` and `r2.cmd("wx 9090 @ 0x401234")`.

## Gotchas

- First command on a fresh `open()` without `-A`: run `aaa` yourself or
  function-level commands return nothing.
- `cmdj` on a command without a `j` variant returns `None` (JSON parse fails
  silently in some versions) — know your command set.
- Addresses are ints in JSON but strings like `"0x401234"` are accepted in
  commands; `@ {addr}` with a Python int works fine.
- Long `aaa` on big binaries: set `r2.cmd("e anal.timeout=120")` first.
- Always `r2.quit()` — orphaned r2 children accumulate otherwise.
