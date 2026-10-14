# analyzeHeadless — full flag reference

`analyzeHeadless` is in `<ghidra_install>/support/`. General form:

```
analyzeHeadless <project_location> <project_name>[/<folder_path>]
    [-import <file|dir>...] | [-process [project_file]]
    [options...]
```

The first two positionals are always required: a directory that holds (or will
hold) the `.gpr`/`.rep` project, and the project name. A `/folder` suffix on
the name targets a folder inside the project
(`projX/firmware/router1`).

Server-shared projects are also supported:
`analyzeHeadless ghidra://192.0.2.5/RepoName/folder -p -import ./bin`
(`-p` prompts for credentials, `-commit ["msg"]` checks changes in,
`-keystore`, `-connect [user]` for PKI/SSH auth).

## Import vs process

| Flag | Meaning |
|---|---|
| `-import <path>...` | Import one or more files/dirs, analyze, run scripts. Multiple paths allowed. |
| `-process [name]` | Do NOT import; run analysis/scripts over programs **already in the project**. `name` may be a glob (`'*.so'`, quote it from the shell). No name = every program. |
| `-recursive [depth]` | With `-import`: descend into directories. With `-process`: recurse project folders. Optional depth limit in recent releases. |
| `-overwrite` | On `-import`, replace an existing program with the same project path. |
| `-deleteProject` | Delete the project when done (only valid with `-import`). The one-shot pattern. |
| `-readOnly` | Don't save changes (with `-process`, analysis results are discarded; with `-import`, program isn't saved). |

## Analysis control

| Flag | Meaning |
|---|---|
| `-noanalysis` | Skip auto-analysis entirely. Pair with `-preScript` that sets things up, or when you only need loader output. |
| `-analysisTimeoutPerFile <secs>` | Hard cap per binary. Analysis is interrupted but scripts still run — set it for every bulk run. |
| `-processor <languageID>` | Force the language, e.g. `x86:LE:64:default`, `ARM:LE:32:v7`, `MIPS:BE:32:default`, `AARCH64:LE:64:v8A`, `PowerPC:BE:32:default`, `avr8:LE:16:atmega256`. List: `Ghidra/Processors/*/data/languages/*.ldefs`, or the GUI language picker. |
| `-cspec <id>` | Compiler spec for the language (`default`, `gcc`, `windows`). Must accompany `-processor` when the language has several. |
| `-loader <name>` | Force a loader: `BinaryLoader` (raw blob), `ElfLoader`, `PeLoader`, `MachoLoader`, `IntelHexLoader`, `MotorolaHexLoader`. |
| `-loader-<arg> <val>` | Loader-specific args, e.g. `-loader-baseAddr 0x8000` (BinaryLoader load address), `-loader-blockName ROM`, `-loader-applyRelocations false` (ElfLoader), `-loader-imagebase 0x400000`. Available args: see each loader's options in the GUI import dialog. |
| `-max-cpu <n>` | Cap analysis worker threads. |
| `-propertiesPath <dir>` | Where `.properties` files answering script `ask*()` prompts live (headless scripts can't prompt). |

## Scripts

| Flag | Meaning |
|---|---|
| `-preScript <name> [args...]` | Run before analysis. Use to create memory blocks, set image base, disable specific analyzers (`setAnalysisOption(currentProgram, "Stack", "false")`). |
| `-postScript <name> [args...]` | Run after analysis. Arguments up to the next `-flag` are passed through; read them with `getScriptArgs()`. |
| `-scriptPath "<dir>[;<dir>...]"` | Where to find scripts. `$GHIDRA_SCRIPT_DIR` style paths OK; `~/ghidra_scripts` is always searched. |
| `-scriptlog <path>` / `-log <path>` | Script log / application log destinations. |
| `-okToDelete` | Required if a `-process` script deletes programs. |

Scripts can abort further processing of a file with `setHeadlessContinuationOption`
(e.g. a preScript that filters uninteresting files in a `-recursive` import:
`HeadlessScript.setHeadlessContinuationOption(ABORT)` — subclass
`ghidra.app.util.headless.HeadlessScript`).

## Raw / firmware blob recipes

Bare-metal ARM image loaded at 0x8000:

```
analyzeHeadless /tmp/proj p -import ./fw.bin \
  -loader BinaryLoader -loader-baseAddr 0x8000 \
  -processor ARM:LE:32:v7 -cspec default \
  -postScript ExportAnalysis.java ./out -deleteProject
```

Unknown base? Import with `-noanalysis`, run a preScript/postScript pass that
searches for self-referencing pointer tables or string xref density at trial
bases, re-import at the winner. For vector-table images (Cortex-M), the reset
vector at offset 4 reveals the base's high bits.

Whole extracted firmware root (ELFs auto-detected, everything else skipped by
loader failure):

```
analyzeHeadless /tmp/proj p -import ./squashfs-root -recursive \
  -analysisTimeoutPerFile 300 -postScript ExportAnalysis.java ./out -deleteProject
```

## Memory / JVM tuning

`analyzeHeadless` is a shell script around a JVM launcher. For huge binaries:
`export MAXMEM=8G` before invoking (consumed by the launcher), or edit
`support/analyzeHeadless` / `support/launch.properties`.

## Exit status and log reading

Exit code is nonzero on launcher failure, but **per-file** import/analysis
errors are only in the log. Grep the log for:

- `Import succeeded` / `Unable to import` — loader verdict per file.
- `ANALYZING all memory` / `Analysis succeeded` — analysis ran.
- `ERROR REPORT SCRIPT ERROR` — your postScript threw; the stack trace follows.
- `Analysis timed out` — raise `-analysisTimeoutPerFile` or accept partial.

The shipped driver (`scripts/ghidra_headless.py`) tees the full log to
`<out>/analyzeHeadless.log` and surfaces these lines.
