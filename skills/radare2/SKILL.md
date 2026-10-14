---
name: radare2
description: Interactive and scripted reverse engineering with radare2/rizin and r2pipe — analyze binaries (aaa), list and disassemble functions, follow xrefs, dump strings/imports/protections, search bytes and ROP gadgets, use visual graph mode, and automate everything from Python via cmdj JSON to hunt dangerous sinks (system/strcpy/gets/memcpy) and emit rupu work units. Use for fast binary triage, interactive deep-dives, and scripted sink hunting before heavier Ghidra passes.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# radare2 / rizin — interactive + scripted RE

radare2 (and its fork rizin) is the fastest path from "unknown binary" to
"these three functions call `system` with user data". Interactive for
deep-dives, fully scriptable over r2pipe for triage at scale. rizin is
command-compatible for everything used here; tool names differ
(`rabin2`→`rz-bin`, `rafind2`→`rz-find`, `ragg2`→`rz-gg`, `rax2`→`rz-ax`,
r2pipe→`rzpipe`). Cutter is the GUI front-end over rizin (also works with
radare2 builds) when you want the same analysis with a decompiler panel,
graph view and hex editor interactively.

## 1. Open and analyze

```
r2 -A ./target          # open + run aaa automatically
r2 -AA ./target         # deeper (aaaa)
r2 ./target             # open only, then type: aaa   (or aaaa for deeper/slower)
r2 -d ./target          # spawn under the built-in debugger
r2 -d gdb://192.0.2.10:1234   # attach to a remote gdbserver
r2 -w ./target          # open writable (patching)
r2 -n ./target          # no analysis, no bin parsing (raw view)
r2 -e bin.cache=true ./target  # needed to patch/relocate some files in-memory
```

`aaa` = analyze all: functions, calls, xrefs, basic blocks. `aaaa` adds
experimental passes (type/esil propagation) — slower, better xrefs. Progress is
printed; on huge binaries set `-e anal.timeout=120` or scope with `af @ addr`.

## 2. The command vocabulary

Commands are single letters that compose; `?` after anything shows help
(`af?`, `px?`). `~` is the internal grep, `@` is temporary seek, `j` suffix
emits JSON. Full reference with visual-mode keys and rizin notes:
`references/radare2.md`.

| Command | Meaning |
|---|---|
| `iI` | binary info: arch, bits, NX/canary/PIC/RELRO/stripped |
| `ie` / `is` / `ii` | entrypoints / symbols / imports |
| `iz` / `izz` | strings in data sections / whole file |
| `afl`, `afl~main` | list functions; grep the list |
| `s sym.main`, `s 0x401120` | seek to symbol/address (`s-` back) |
| `pdf @ sym.main` | disassemble function (at temporary seek) |
| `pdc` | decompile-ish pseudo-C (built in) |
| `pdg` | real decompile via r2ghidra (`r2pm -ci r2ghidra`; rizin: rz-ghidra) |
| `axt @ addr/sym` | xrefs TO (who references this) |
| `axf @ addr` | xrefs FROM (what this references) |
| `/ needle`, `/x 4883ec` | search string / hex bytes |
| `/R pop rdi` | ROP gadget search (`/R/` regex, `/Rj` JSON) |
| `pxr @ rsp` | telescoped pointer dump (great in `-d`) |
| `V`, `VV` | visual mode / visual graph (q to exit, `p` cycles views) |
| `agf`, `agc` | ASCII/graphviz function graph, call graph |

Typical interactive flow:

```
r2 -A ./target
[0x...]> iI                      # protections → note canary/NX/PIE for later exploitation
[0x...]> ii~system; ii~strcpy    # dangerous imports present?
[0x...]> axt @ sym.imp.system    # every call site of system()
[0x...]> s main; pdf             # or: s <caller from axt>; pdf
[0x...]> izz~passw               # credential/format-string hunting
[0x...]> VV                      # graph-walk the interesting caller
```

## 3. The dangerous-sink hunt

1. `ii` → shortlist imports: `system popen exec* gets strcpy strcat sprintf
   vsprintf scanf sscanf memcpy strncpy read recv recvfrom printf fprintf`.
2. For each: `axt @ sym.imp.<name>` → call sites + containing function
   (`fcn.000012a0` or `sym.handle_request`).
3. `pdf @ <caller>` (or `pdg`) and read backwards from the call: which
   registers/stack slots feed the sink's arguments? Fixed-size stack buffer
   into `strcpy`/`sprintf` with an attacker-reachable source, `memcpy` whose
   length comes from a packet field, `system` with any concatenated input,
   `printf` with a non-constant first arg — all candidates.
4. `axt` on the caller itself to walk toward the entry point / recv loop:
   a sink matters when the attack surface reaches it.
5. Record each candidate (work unit + asset, below), then confirm dynamically.

## 4. r2pipe automation

```python
import r2pipe
r2 = r2pipe.open("./target")        # also: open("gdb://...", flags=["-d"])
r2.cmd("aaa")
funcs   = r2.cmdj("aflj")           # j-commands → parsed JSON (list of dicts)
imports = r2.cmdj("iij")
strings = r2.cmdj("izzj")
info    = r2.cmdj("iIj")
xrefs   = r2.cmdj("axtj @ sym.imp.system")   # [{'from':…, 'fcn_name':…, 'type':'CALL'}]
r2.quit()
```

`cmd()` returns raw text, `cmdj()` JSON-parses the `j` variant — always prefer
`cmdj` in scripts. JSON shapes and gotchas: `references/r2pipe.md`.
(rizin: `pip install rzpipe`, `import rzpipe` — same API.)

## 5. Triage script

```
python3 scripts/r2_triage.py ./target --out ./r2_out
python3 scripts/r2_triage.py ./target --sinks "system,custom_eval" --deep --out ./r2_out
```

Uses r2pipe if installed, else speaks the `r2 -q0` pipe protocol directly
(stdlib only); clear message if neither r2pipe nor radare2/rizin exists. Runs
`aaa`, pulls `aflj` + `iij` + `izzj` + `iIj` + `axtj` for the dangerous-import
set, saves every raw JSON under `--out` (evidence — keep it), prints a
protections + sink summary, and writes `<out>/work_units.json`: a
rupu-ingestible array of candidate sinks
(`{id, title, targets:[{file, function, vaddr, caller}], hints}`).
rupu wiring (`for_each`, `assets.mark` for `binary:file`/`binary:symbol`,
`findings.report`): `references/rupu.md`.

## 6. Beyond triage

- **Debugging:** `r2 -d ./target`, then `db sym.main` (break), `dc` (continue),
  `dr` (regs), `pxr @ rsp` (telescope stack), `ds`/`dso` (step/step-over),
  `ood arg1` (re-run with args). Or hand off to the `gdb-debugging` skill with
  the call-site vaddrs from the work units.
- **Patching:** `r2 -w`, seek to the instruction, `wa jmp 0x401200` (assemble
  in place), `wx 9090` (raw bytes), `wz hello` (string).
- **Gadgets:** `/R pop rdi; ret` and `/Rj` to feed a ROP chain — then load the
  `pwntools` skill for exploitation.
- **Full decompiled corpus / bulk firmware:** load the `ghidra-headless` skill
  (the work-unit hints point there).
- **Classification of candidates:** load the `vuln-classes` skill.
