# Ghidra scripting — FlatProgramAPI, decompiler, xrefs (Java + Jython)

Headless scripts subclass `GhidraScript` (Java) or run as Jython modules with
the same state injected as globals: `currentProgram`, `currentAddress`,
`monitor`, plus every `FlatProgramAPI` method (`getFunction`, `getReferencesTo`,
`toAddr`, `createLabel`, ...). Script args from the `-postScript Name arg1 arg2`
command line arrive via `getScriptArgs()` (array of strings).

Scripts live in any dir passed with `-scriptPath` (and `~/ghidra_scripts`).
Java scripts are compiled on the fly; the filename must equal the class name.

## Walking functions

Java:
```java
FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
while (it.hasNext()) {
    Function f = it.next();
    println(f.getEntryPoint() + " " + f.getSignature().getPrototypeString());
}
```

Jython:
```python
for f in currentProgram.getFunctionManager().getFunctions(True):
    print(f.getEntryPoint(), f.getSignature().getPrototypeString())
```

Useful `Function` accessors: `getName()`, `getEntryPoint()`, `getBody()`
(AddressSetView; `.getNumAddresses()` ~ size), `isThunk()`, `getThunkedFunction(true)`,
`isExternal()`, `getParameters()`, `getCallingFunctions(monitor)`,
`getCalledFunctions(monitor)` — the last two give you an instant static call
graph for reachability walks.

## Decompiling — DecompInterface / DecompileResults

Java:
```java
import ghidra.app.decompiler.*;
DecompInterface ifc = new DecompInterface();
ifc.openProgram(currentProgram);
DecompileResults res = ifc.decompileFunction(f, 60, monitor);  // 60s timeout
if (res.decompileCompleted()) {
    String c = res.getDecompiledFunction().getC();      // full C text
    HighFunction hf = res.getHighFunction();            // SSA/pcode view
}
ifc.dispose();
```

Jython is identical modulo syntax. `getHighFunction()` opens the door to real
dataflow: `hf.getPcodeOps()` iterates pcode SSA ops; for a `CALL` op,
`op.getInput(0)` is the target, `op.getInput(1..n)` the arguments as Varnodes;
`varnode.getDef()` walks the def-use chain backward — that is how you trace a
`memcpy` length to its origin mechanically.

Decompiler options (null-arg form uses defaults):
```java
DecompileOptions opts = new DecompileOptions();
ifc.setOptions(opts);
ifc.setSimplificationStyle("decompile");   // or "normalize" for matching
```

## Cross-references

```java
Reference[] refs = getReferencesTo(toAddr(0x401130));       // FlatProgramAPI
for (Reference r : refs) {
    r.getFromAddress();                 // call/jump/data site
    r.getReferenceType();               // CALL, JUMP, DATA, READ, WRITE...
    r.getReferenceType().isCall();
    Function f = getFunctionContaining(r.getFromAddress()); // caller
}
```

Reverse direction: `getReferencesFrom(addr)`, or
`ReferenceManager rm = currentProgram.getReferenceManager()` for bulk iteration
(`rm.getReferenceIterator(startAddr)`).

To find the address of a named thing (symbols can be duplicated across
namespaces):

```java
SymbolTable st = currentProgram.getSymbolTable();
SymbolIterator si = st.getSymbols("system");       // every symbol named system
while (si.hasNext()) { Address a = si.next().getAddress(); ... }
```

Catch both the external symbol **and** its PLT thunk: references to an import
usually land on the thunk function, so also check
`getFunction("system")`/functions whose `getName()` matches, and `"_system"`
underscore variants (macOS, some libcs).

## SymbolTable quick map

- `st.getExternalSymbols()` — imports (parent namespace = library name).
- `st.getExternalEntryPointIterator()` — exported entry point addresses;
  `st.getPrimarySymbol(addr)` for the name.
- `st.getPrimarySymbol(addr)`, `st.getSymbols(name)`, `st.getSymbolIterator()`.
- `getSymbolAt(addr)` / `getSymbolAfter(...)` from FlatProgramAPI.

## Strings

Defined strings are Data whose value is a String:

```python
for d in currentProgram.getListing().getDefinedData(True):
    v = d.getValue()
    if isinstance(v, (str, unicode)):
        print(d.getAddress(), repr(v), len(getReferencesTo(d.getAddress())))
```

If analysis missed strings (raw blobs), run the "ASCII Strings" analyzer or
`createAsciiString(addr)` yourself; `findBytes(null, "GET /", 100)` searches raw
memory.

## Renaming / retyping to improve decompilation

```java
f.setName("parse_packet", SourceType.USER_DEFINED);
createLabel(toAddr(0x401500), "g_config", true);
// retype a parameter:
Parameter p = f.getParameter(0);
p.setDataType(new PointerDataType(StructureDataType...), SourceType.USER_DEFINED);
// or via the high function:
HighFunctionDBUtil.updateDBVariable(highSym, "pkt_len", intType, SourceType.USER_DEFINED);
```

Every rename/retype re-propagates through the decompiler on the next
`decompileFunction` call: `undefined8 uVar3` chains become typed fields, and
`*(int *)(param_1 + 0x1c)` becomes `pkt->len` once you define the struct
(`StructureDataType` + `dtm.addDataType(...)`). This is the highest-leverage
manual step when auditing a hot function.

Headless scripts run inside an open transaction already; in standalone
(non-GhidraScript) contexts wrap changes in
`program.startTransaction(...)`/`endTransaction`.

## Reading decompiler output — heuristics

- `char local_48 [64]` + any unbounded write = stack overflow candidate;
  presence of `__stack_chk_fail` in the function tells you a canary is in play.
- `memcpy(dst, src, n)` — chase `n`: if it comes from input
  (`*(ushort *)(buf+2)`) and `dst` is fixed-size, candidate.
- Non-constant first arg to `printf`/`fprintf`/`syslog` = format string bug.
- `CONCAT44`, `SUB168`, `in_RDI` artifacts = missing type info; retype and
  re-decompile before judging.
- `halt_baddata()` / huge single function = analysis failure (wrong processor,
  obfuscation, data-as-code). Fix import options first.

## Stripped + static binaries: Function ID

The **Function ID** analyzer hashes function bodies and matches them against
`.fidb` databases (shipped sets cover common Visual Studio and some libc
builds), restoring `strcpy`/`malloc` names in fully static, stripped binaries.
Headless: it's part of standard auto-analysis when enabled. Build your own fidb
from a matching SDK's `.a` files via the GUI (`Tools → Function ID → Create new
FidDb / Populate from programs`) and ship it with
`-preScript` setting the analyzer's database path. Complements:
"Demangler GNU/MS" (restores C++ names), "Decompiler Parameter ID" (better
signatures), and third-party signature approaches (BSim in recent Ghidra for
similarity search across a corpus).

## Minimal postScript skeletons

Java (`MyScript.java`, class name == file name):
```java
import ghidra.app.script.GhidraScript;
public class MyScript extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        println("program: " + currentProgram.getName());
    }
}
```

Jython (`my_script.py`):
```python
args = getScriptArgs()
print("program: %s" % currentProgram.getName())
```

Run either with:
```
analyzeHeadless /tmp/proj p -import ./bin -scriptPath ./scripts/ghidra \
  -postScript MyScript.java outdir -deleteProject
```
