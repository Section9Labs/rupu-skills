# radare2 / rizin command reference

Commands compose from single letters; append `?` for help at any depth (`a?`,
`af?`, `pd?`). Modifiers: `~grep` (internal grep: `afl~main`, `~?` count,
`~{}` pretty-print JSON, `~[1]` column), `@addr` (temporary seek), `@@`
(iterator: `pdf @@ fcn.*` disassembles every function), `j` suffix (JSON),
`*` suffix (r2 commands), `> file` redirect, `|` pipe to shell, `.` interpret
output, `!cmd` shell escape, `#` comment, `;` command separator.

rizin is command-compatible for everything below. External tool names:
`rabin2`→`rz-bin`, `radiff2`→`rz-diff`, `rafind2`→`rz-find`, `ragg2`→`rz-gg`,
`rahash2`→`rz-hash`, `rasm2`→`rz-asm`, `rax2`→`rz-ax`, `r2pm`→`rz-pm`
(rz-ghidra/jsdec install via the package manager or distro packages).
Cutter = GUI over rizin with graph view, hex editor, decompiler panels.

## Invocation

```
r2 [-AdwnqcCe] file
  -A          run aaa after load            -AA   run aaaa
  -d          debug the file (or pid, or gdb://host:port)
  -w          open writable                 -n    no bin parsing / no analysis
  -nn         only raw r2 structures        -q    quit after -c/-i commands
  -c 'cmds'   run commands then prompt      -q0   pipe mode (NUL-terminated)
  -i file     run r2 script file            -2    close stderr
  -e k=v      set eval var (bin.cache=true, scr.color=0, anal.timeout=120)
  -B addr     base address for raw files    -b 16 asm.bits
  -a arm      arch for raw files            -m addr map file at addr
  -p proj     use project
```

Raw firmware blob: `r2 -n -a arm -b 32 -B 0x8000 -m 0x8000 fw.bin` then `aa`.

## Info (i-family) — also available standalone via rabin2/rz-bin

```
i          general info          iI    protections: canary,nx,pic,relro,stripped,static
ie         entrypoints           iee   entry/exit (constructors/destructors)
is         symbols               ii    imports            iE   exports
iz         strings (data secs)   izz   strings (whole bin) izzj JSON
il         linked libraries      ih    headers            iS   sections (perms!)
ic         classes (C++/ObjC)    ir    relocations        iV   version info
```

`rabin2 -zz file` / `rz-bin -zz file` = `izz` without opening a session.

## Analysis (a-family)

```
aa / aaa / aaaa    analyze: basic / +calls,refs,names / +esil,types (slow)
af                 analyze function at current seek      af @ 0x401100
afl                list functions (afll verbose, aflj JSON, afl~name grep)
afi                info about current function           afn newname  rename
afv                function variables/args               afvn  rename var
s sym.main         seek (s- undo, s+ redo, s.. partial addr)
axt @ addr/sym     xrefs TO addr   (axtj JSON)
axf @ addr         xrefs FROM addr
afx                call refs from current function
ax                 list all xrefs
aav                find pointer-sized values pointing into the binary (good for raw blobs)
```

## Printing / disassembly (p-family)

```
pdf @ sym.main    disassemble whole function   (pdfj JSON incl. ops)
pd 20 @ addr      disassemble N instructions
pdc               pseudo-C decompiler (built-in, rough)
pdg               r2ghidra decompiler  — install: r2pm -ci r2ghidra
                  (rizin: rz-ghidra, Cutter ships it; jsdec = pddo alternative)
pds               summarize function (calls + strings only)
px 64 @ addr      hexdump          pxw/pxq  word/qword dumps
pxr @ rsp         telescope: deref pointers recursively w/ flags (stack recon)
ps @ addr         print string     pf    format struct (pf.name xxd)
p8 16 @ addr      raw hex bytes (patch-friendly)
```

## Flags, searching, writing

```
f                  list flags (named addresses)   f name @ addr   set flag
fs                 flag spaces (fs imports; f)
/ foo              search string                 /j JSON
/x 4883ec08        search hex bytes              /x 48..ec  with wildcards
/R pop rdi         ROP gadget search             /R/ regex   /Rj JSON
/a jmp rax         assemble-and-search           /v 0x11223344 search value
e search.in=io.maps   control search range (dbg.maps when debugging)
wa jmp 0x401200 @ addr   write assembly (needs -w or e io.cache=true)
wx 9090 @ addr     write hex        wz str  write NUL-terminated string
wo?                write-op (xor/add on range: wox 41 @ addr!0x10)
```

## Visual modes

```
V        visual mode: p/P cycle views, c cursor, _ HUD fuzzy search,
         x/X xrefs to/from under cursor, d rename/define, : command line,
         o seek, u/U undo/redo seek, q quit
VV       visual graph: hjkl move, tab next node, t/f follow true/false edge,
         ' comments, _ search, R randomize theme, q quit
V!       visual panels (Cutter-like multi-pane TUI)
v        (rizin) visual panels
```

## Debugging (d-family, with -d or ood)

```
db sym.main      set breakpoint         db  list   db- del
dc               continue               dcu addr   continue until
ds / dso         step into / over       dsu addr   step until
dr               registers (dr rax=0 to set; drr telescoped)
dm               memory maps            dmm   modules
dbt              backtrace              ddc   (rizin naming may vary)
doo [args]       reopen in debugger with args   ood = same
dk 9             send signal
```

`r2 -d gdb://192.0.2.10:1234` attaches to a remote gdbserver;
`r2 frida://...` with the r2frida plugin for dynamic instrumentation.

## Diffing and other externals

```
radiff2 -g main a b | xdot -      graph-diff a function (rz-diff for rizin)
rasm2 -a x86 -b 64 'mov rdi,rsp'  assemble one-liners
rax2 0x41414141                   numeric conversions
ragg2 -P 200 -r                   De Bruijn pattern (offset finding)
rahash2 -a sha256 file            hashing
```

## Session hygiene

- `e scr.color=0` for clean logs; `e asm.pseudo=true` for pseudo syntax.
- Projects: `Ps name` save, `Po name` load (rizin: `Ps`/`Po` too) — or just
  re-run `aaa`, it's usually fast enough.
- Huge binary: `e anal.timeout=120`, analyze selectively with `af @ entry0`
  and `af @@ sym.*` instead of `aaa`.
