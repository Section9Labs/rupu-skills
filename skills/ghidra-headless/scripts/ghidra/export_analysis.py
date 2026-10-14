# export_analysis.py -- Jython twin of ExportAnalysis.java (Ghidra headless postScript).
# Exports functions (+ decompilation), strings (+ refs), imports/exports and
# sink xrefs as JSON + text under <outdir>/<program>/.
#
# Usage:
#   analyzeHeadless /tmp/proj p -import ./bin -scriptPath <this dir> \
#       -postScript export_analysis.py <outdir> [extra,sinks] -deleteProject
#
# Runs under Ghidra's Jython; the state (currentProgram, monitor, getScriptArgs,
# getReferencesTo, ...) is injected by GhidraScript. Not a standalone script.
# @category Export

from __future__ import print_function
import json
import os
import re
import sys

try:
    from ghidra.app.decompiler import DecompInterface
except ImportError:
    print("This is a Ghidra postScript (Jython). Run it via analyzeHeadless:")
    print("  analyzeHeadless /tmp/proj p -import ./bin -scriptPath <dir> "
          "-postScript export_analysis.py <outdir> -deleteProject")
    sys.exit(1)

DEFAULT_SINKS = [
    "system", "popen", "execve", "execl", "execle", "execlp", "execv", "execvp",
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "memcpy", "memmove", "strncpy", "strncat", "snprintf",
    "read", "recv", "recvfrom", "fread",
    "printf", "fprintf", "syslog", "dlopen", "LoadLibraryA", "WinExec",
    "CreateProcessA", "ShellExecuteA",
]
DECOMP_TIMEOUT_SECS = 60


def safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def dump(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=1)


args = getScriptArgs()
out_base = args[0] if len(args) > 0 else "ghidra_export"
sinks = list(DEFAULT_SINKS)
if len(args) > 1:
    sinks += [s.strip() for s in args[1].split(",") if s.strip()]

prog = currentProgram
out_dir = os.path.join(out_base, safe(prog.getName()))
decomp_dir = os.path.join(out_dir, "decompiled")
if not os.path.isdir(decomp_dir):
    os.makedirs(decomp_dir)

# ---- functions + decompilation ------------------------------------------
ifc = DecompInterface()
ifc.openProgram(prog)
functions = []
fm = prog.getFunctionManager()
all_c = open(os.path.join(out_dir, "decompiled.c"), "w")
txt = open(os.path.join(out_dir, "functions.txt"), "w")
for f in fm.getFunctions(True):
    if monitor.isCancelled():
        break
    entry = "0x%s" % f.getEntryPoint()
    sig = f.getSignature().getPrototypeString()
    txt.write("%s  %-40s  %s\n" % (entry, f.getName(), sig))
    decomp_file = ""
    if not f.isThunk() and not f.isExternal():
        res = ifc.decompileFunction(f, DECOMP_TIMEOUT_SECS, monitor)
        if res and res.decompileCompleted() and res.getDecompiledFunction():
            c = res.getDecompiledFunction().getC()
            fname = "%s_%s.c" % (safe(f.getName()), f.getEntryPoint())
            with open(os.path.join(decomp_dir, fname), "w") as cf:
                cf.write(c)
            all_c.write("// ---- %s @ %s ----\n%s\n" % (f.getName(), entry, c))
            decomp_file = "decompiled/" + fname
    functions.append({
        "name": f.getName(), "entry": entry, "signature": sig,
        "size": f.getBody().getNumAddresses(),
        "is_thunk": bool(f.isThunk()), "is_external": bool(f.isExternal()),
        "decomp_file": decomp_file,
    })
all_c.close()
txt.close()
ifc.dispose()
dump(os.path.join(out_dir, "functions.json"), functions)

# ---- strings + refs ------------------------------------------------------
strings = []
with open(os.path.join(out_dir, "strings.txt"), "w") as st_txt:
    for d in prog.getListing().getDefinedData(True):
        v = d.getValue()
        if not isinstance(v, (str, unicode)):  # noqa: F821 (Jython 2)
            continue
        a = d.getAddress()
        refs = []
        for r in getReferencesTo(a):
            fn = getFunctionContaining(r.getFromAddress())
            refs.append({"from": "0x%s" % r.getFromAddress(),
                         "function": fn.getName() if fn else ""})
        st_txt.write("0x%s  [%d refs]  %r\n" % (a, len(refs), v))
        strings.append({"vaddr": "0x%s" % a, "string": v, "refs": refs})
dump(os.path.join(out_dir, "strings.json"), strings)

# ---- imports / exports ---------------------------------------------------
st = prog.getSymbolTable()
imports = [{"name": s.getName(), "library": s.getParentNamespace().getName()}
           for s in st.getExternalSymbols()]
dump(os.path.join(out_dir, "imports.json"), imports)

exports = []
it = st.getExternalEntryPointIterator()
while it.hasNext():
    a = it.next()
    s = st.getPrimarySymbol(a)
    exports.append({"name": s.getName() if s else "", "vaddr": "0x%s" % a})
dump(os.path.join(out_dir, "exports.json"), exports)

# ---- sink xrefs ----------------------------------------------------------
xrefs = []
with open(os.path.join(out_dir, "xrefs.txt"), "w") as xr_txt:
    for sink in sinks:
        addrs = []
        for variant in (sink, "_" + sink):
            for s in st.getSymbols(variant):
                if s.getAddress() not in addrs:
                    addrs.append(s.getAddress())
            f = getFunction(variant)
            if f and f.getEntryPoint() not in addrs:
                addrs.append(f.getEntryPoint())
        for a in addrs:
            for r in getReferencesTo(a):
                fn = getFunctionContaining(r.getFromAddress())
                name = fn.getName() if fn else ""
                xr_txt.write("%-14s <- 0x%s in %s (%s)\n"
                             % (sink, r.getFromAddress(), name, r.getReferenceType()))
                xrefs.append({
                    "sink": sink, "from": "0x%s" % r.getFromAddress(),
                    "function": name, "type": str(r.getReferenceType()),
                    "is_call": bool(r.getReferenceType().isCall()),
                })
dump(os.path.join(out_dir, "xrefs.json"), xrefs)

# ---- meta ----------------------------------------------------------------
dump(os.path.join(out_dir, "meta.json"), {
    "program": prog.getName(),
    "exec_path": prog.getExecutablePath(),
    "sha256": prog.getExecutableSHA256(),
    "language": str(prog.getLanguageID()),
    "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
    "image_base": str(prog.getImageBase()),
})
print("[export_analysis] wrote %s" % out_dir)
