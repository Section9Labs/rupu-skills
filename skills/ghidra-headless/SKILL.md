---
name: ghidra-headless
description: Scriptable bulk static reverse engineering with Ghidra's headless analyzer (analyzeHeadless) — import single binaries or whole firmware trees, run Java/Jython postScripts to export function lists, full decompiled C, strings, imports/exports and cross-references as JSON+text, hunt dangerous sinks (system/memcpy/recv/strcpy) back to reachable entry points, and emit rupu work units. Use when you need repeatable, non-interactive decompilation at scale or a machine-readable static-analysis dump to feed vuln triage.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# Ghidra Headless — bulk static RE

Ghidra's headless analyzer gives you the full auto-analysis + decompiler pipeline
without the GUI. One command imports a binary (or a directory of binaries), runs
analysis, executes your script against the program database, and exports whatever
you ask for. This skill ships a ready postScript (`scripts/ghidra/ExportAnalysis.java`
and its Jython twin) plus a driver (`scripts/ghidra_headless.py`) that finds Ghidra,
runs the export, and turns sink cross-references into rupu work units.

## 1. Find analyzeHeadless

`analyzeHeadless` lives in `support/` inside the Ghidra install:

```
$GHIDRA_INSTALL_DIR/support/analyzeHeadless      # canonical
/opt/ghidra*/support/analyzeHeadless             # common manual install
/usr/share/ghidra/support/analyzeHeadless        # distro packages
~/ghidra_*_PUBLIC/support/analyzeHeadless        # unpacked release zip
```

Check: `find / -name analyzeHeadless -type f 2>/dev/null` or set
`GHIDRA_INSTALL_DIR`. Needs a JDK (17+ for current releases). The driver script
probes PATH, `GHIDRA_INSTALL_DIR`, and the common paths above, and prints
install guidance if nothing is found.

## 2. Core invocations

Import + analyze + script + throw the project away (the standard one-shot):

```
analyzeHeadless /tmp/ghproj projX \
  -import ./target_bin \
  -scriptPath ./scripts/ghidra \
  -postScript ExportAnalysis.java ./out \
  -deleteProject
```

Key variations (full flag reference: `references/ghidra-headless.md`):

- `-process [name]` — re-run scripts on an **already imported** program instead
  of `-import` (keep the project, drop `-deleteProject`). Wildcards allowed:
  `-process '*.so'`.
- `-overwrite` — replace an existing program of the same name on `-import`.
- `-recursive` — descend into a directory given to `-import` (whole firmware
  extraction tree, a `squashfs-root/`, a `bin/` dump).
- `-analysisTimeoutPerFile 600` — cap auto-analysis per binary (seconds);
  essential for bulk runs.
- `-loader BinaryLoader -processor ARM:LE:32:v7 -cspec default` plus
  `-loader-baseAddr 0x8000` — raw/firmware blobs with no container format
  (bare-metal images, bootloaders, MCU dumps). Processor IDs are Ghidra
  "language IDs" (`x86:LE:64:default`, `MIPS:BE:32:default`, ...).
- `-noanalysis` — import only; combine with `-preScript` to set memory maps or
  entry points before you trigger analysis yourself, or when you only need the
  loader's view.
- `-preScript Foo.java` — runs before analysis (set options, create segments);
  `-postScript` runs after.
- `-max-cpu N`, `-log`/`-scriptlog` for bulk-run hygiene.

Everything after the script name on `-postScript Script.java arg1 arg2` is
delivered to the script via `getScriptArgs()`.

## 3. The shipped postScript

`scripts/ghidra/ExportAnalysis.java` (Jython twin: `scripts/ghidra/export_analysis.py`)
writes, under `<outdir>/<program_name>/`:

- `functions.json` / `functions.txt` — every function: name, entry vaddr,
  C signature, size, thunk/external flags.
- `decompiled/<name>_<vaddr>.c` + `decompiled.c` (concatenated) — full
  decompiler output per function via `DecompInterface`.
- `strings.json` / `strings.txt` — every defined string with address and the
  functions that reference it.
- `imports.json`, `exports.json` — externals and entry-point symbols.
- `xrefs.json` / `xrefs.txt` — every cross-reference to a configurable sink
  list (`system, popen, exec*, gets, strcpy, strcat, sprintf, scanf, memcpy,
  strncpy, read, recv, recvfrom, printf, ...`): call site vaddr, calling
  function, reference type. Add sinks as a comma list in the second script arg.

Both scripts use only the FlatProgramAPI + decompiler interface; use them as
templates for your own exports. Full API walkthrough (SymbolTable,
`getReferencesTo`, `DecompInterface`, Java **and** Jython):
`references/scripting.md`.

## 4. Driver

```
python3 scripts/ghidra_headless.py ./target_bin --out ./gh_out
python3 scripts/ghidra_headless.py ./squashfs-root --recursive --timeout 300 --out ./gh_out
python3 scripts/ghidra_headless.py ./fw.bin --loader BinaryLoader \
    --processor ARM:LE:32:v7 --base 0x8000 --out ./gh_out
python3 scripts/ghidra_headless.py ./target_bin --sinks "sprintf,custom_parse" --out ./gh_out
```

It locates `analyzeHeadless`, runs the one-shot invocation above, collects every
per-program JSON export, prints a sink summary, and writes
`<out>/work_units.json` — a rupu-ingestible array of candidate-sink work units
(`{id, title, targets:[{file, function, vaddr, reason}], hints}`). Wiring into
rupu (`for_each`, `assets.mark`, `findings.report`): `references/rupu.md`.
Keep the whole `--out` directory as run evidence; never delete it.

## 5. Reading the output and working the leads

1. **Protections + shape first.** Skim `functions.txt` (how much did analysis
   recover?) and `imports.json` (what libc/network surface exists?).
2. **Start from sinks and strings, not from `main`.** `xrefs.json` tells you
   exactly which functions call `system`, `memcpy`, `recv`, `strcpy`.
   `strings.json` ties format strings, shell command templates, paths and error
   messages to the functions that use them — a `"%s %s"` next to a `system`
   xref in the same function is a lead.
3. **Walk back to input.** Open the caller's `decompiled/*.c`. Ask: where do
   its arguments come from? Grep the decompiled corpus for the caller's name to
   find *its* callers; repeat until you reach a reachable entry point (`main`,
   an exported handler, a `recv` loop). A sink is only a candidate until data
   from the attack surface reaches it.
4. **Rename/retype to make decompilation readable.** In scripted passes use
   `function.setName(...)`/`createLabel`, `HighFunctionDBUtil.updateDBVariable`
   for parameter retyping; interactively, open the same project in the GUI
   (drop `-deleteProject`) and press `L` (rename) / `Ctrl-L` (retype) — the
   decompiler re-propagates types instantly and bogus `undefined8` chains
   collapse into real structs. Re-run with `-process` to re-export.
5. **Mark candidates.** Each sink whose argument path plausibly reaches input
   becomes a work unit / `binary:symbol` asset (see `references/rupu.md`).

Decompiler reading heuristics (stack buffers, `__stack_chk_fail`, size
confusion in `memcpy` third args, `CONCAT`/`SUB` noise) are in
`references/scripting.md`.

## 6. Stripped + static binaries

For stripped, statically linked binaries, enable Ghidra's **Function ID**
analyzer (it is on by default; FidDb files for common libc builds ship with
Ghidra) — it matches function body hashes against known library code and
restores names like `strcpy` even with no symbols. Also helpful: the
"Demangler", "Shared Return Calls" and "Decompiler Parameter ID" analyzers,
and importing additional `.fidb` databases built from matching SDK libraries
(`Tools → Function ID` in the GUI, or a headless preScript setting analyzer
options). Without names, the sink hunt degrades to signature hunting: grep the
decompiled corpus for `while (*dst++ = *src++)` patterns and syscall wrappers.

## 7. Chaining

- Dynamic confirmation of a candidate sink: load the `gdb-debugging` skill
  (break on the call site vaddr, inspect the real buffer sizes).
- Quick interactive cross-checks, gadget hunting, lighter triage: load the
  `radare2` skill.
- Classifying what you found (overflow vs fmt-string vs injection): load the
  `vuln-classes` skill.
- Exploitation of a confirmed primitive: load the `pwntools` skill.
