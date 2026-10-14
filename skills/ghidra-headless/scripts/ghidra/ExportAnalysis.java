// ExportAnalysis.java — Ghidra headless postScript.
// Exports functions (+ full decompilation), strings (+ refs), imports/exports,
// and cross-references to a sink list, as JSON + text, under <outdir>/<program>/.
//
// Usage:
//   analyzeHeadless /tmp/proj p -import ./bin -scriptPath <this dir> \
//       -postScript ExportAnalysis.java <outdir> [extra,sinks,comma,separated] \
//       -deleteProject
//
// @category Export

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportAnalysis extends GhidraScript {

    private static final String[] DEFAULT_SINKS = {
        "system", "popen", "execve", "execl", "execle", "execlp", "execv", "execvp",
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
        "memcpy", "memmove", "strncpy", "strncat", "snprintf",
        "read", "recv", "recvfrom", "fread",
        "printf", "fprintf", "syslog", "dlopen", "LoadLibraryA", "WinExec",
        "CreateProcessA", "ShellExecuteA"
    };

    private static final int DECOMP_TIMEOUT_SECS = 60;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outBase = (args.length > 0) ? args[0] : "ghidra_export";
        Set<String> sinks = new LinkedHashSet<>(Arrays.asList(DEFAULT_SINKS));
        if (args.length > 1) {
            for (String s : args[1].split(",")) {
                s = s.trim();
                if (!s.isEmpty()) sinks.add(s);
            }
        }

        String progName = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File outDir = new File(outBase, progName);
        File decompDir = new File(outDir, "decompiled");
        decompDir.mkdirs();

        exportFunctionsAndDecomp(outDir, decompDir);
        exportStrings(outDir);
        exportImportsExports(outDir);
        exportSinkXrefs(outDir, sinks);

        // meta.json: lets the driver tie exports back to the original path.
        try (PrintWriter w = new PrintWriter(new File(outDir, "meta.json"), "UTF-8")) {
            w.println("{");
            w.println("  \"program\": " + q(currentProgram.getName()) + ",");
            w.println("  \"exec_path\": " + q(currentProgram.getExecutablePath()) + ",");
            w.println("  \"sha256\": " + q(currentProgram.getExecutableSHA256()) + ",");
            w.println("  \"language\": " + q(currentProgram.getLanguageID().toString()) + ",");
            w.println("  \"compiler\": " + q(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + ",");
            w.println("  \"image_base\": " + q(currentProgram.getImageBase().toString()) );
            w.println("}");
        }
        println("[ExportAnalysis] wrote " + outDir.getAbsolutePath());
    }

    private void exportFunctionsAndDecomp(File outDir, File decompDir) throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        List<String> json = new ArrayList<>();
        try (PrintWriter txt = new PrintWriter(new File(outDir, "functions.txt"), "UTF-8");
             PrintWriter allC = new PrintWriter(new File(outDir, "decompiled.c"), "UTF-8")) {

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                String entry = f.getEntryPoint().toString();
                String sig = f.getSignature().getPrototypeString();
                long size = f.getBody().getNumAddresses();

                txt.printf("0x%s  %-40s  %s%n", entry, f.getName(), sig);

                String decompFile = "";
                if (!f.isThunk() && !f.isExternal()) {
                    DecompileResults res = ifc.decompileFunction(f, DECOMP_TIMEOUT_SECS, monitor);
                    if (res != null && res.decompileCompleted()
                            && res.getDecompiledFunction() != null) {
                        String c = res.getDecompiledFunction().getC();
                        String fname = f.getName().replaceAll("[^A-Za-z0-9._-]", "_")
                                       + "_" + entry + ".c";
                        try (PrintWriter cw = new PrintWriter(new File(decompDir, fname), "UTF-8")) {
                            cw.print(c);
                        }
                        allC.println("// ---- " + f.getName() + " @ 0x" + entry + " ----");
                        allC.println(c);
                        decompFile = "decompiled/" + fname;
                    }
                }
                json.add("{\"name\": " + q(f.getName())
                        + ", \"entry\": " + q("0x" + entry)
                        + ", \"signature\": " + q(sig)
                        + ", \"size\": " + size
                        + ", \"is_thunk\": " + f.isThunk()
                        + ", \"is_external\": " + f.isExternal()
                        + ", \"decomp_file\": " + q(decompFile) + "}");
            }
        } finally {
            ifc.dispose();
        }
        writeJsonArray(new File(outDir, "functions.json"), json);
    }

    private void exportStrings(File outDir) throws Exception {
        List<String> json = new ArrayList<>();
        try (PrintWriter txt = new PrintWriter(new File(outDir, "strings.txt"), "UTF-8")) {
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Data d = it.next();
                Object v = d.getValue();
                if (!(v instanceof String)) continue;
                String s = (String) v;
                Address a = d.getAddress();

                List<String> refs = new ArrayList<>();
                for (Reference r : getReferencesTo(a)) {
                    Function from = getFunctionContaining(r.getFromAddress());
                    refs.add("{\"from\": " + q("0x" + r.getFromAddress())
                            + ", \"function\": " + q(from != null ? from.getName() : "") + "}");
                }
                txt.printf("0x%s  [%d refs]  %s%n", a, refs.size(),
                           s.replace("\n", "\\n").replace("\r", "\\r"));
                json.add("{\"vaddr\": " + q("0x" + a) + ", \"string\": " + q(s)
                        + ", \"refs\": [" + String.join(", ", refs) + "]}");
            }
        }
        writeJsonArray(new File(outDir, "strings.json"), json);
    }

    private void exportImportsExports(File outDir) throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();

        List<String> imports = new ArrayList<>();
        SymbolIterator ext = st.getExternalSymbols();
        while (ext.hasNext()) {
            Symbol s = ext.next();
            imports.add("{\"name\": " + q(s.getName())
                    + ", \"library\": " + q(s.getParentNamespace().getName()) + "}");
        }
        writeJsonArray(new File(outDir, "imports.json"), imports);

        List<String> exports = new ArrayList<>();
        AddressIterator epIt = st.getExternalEntryPointIterator();
        while (epIt.hasNext()) {
            Address a = epIt.next();
            Symbol s = st.getPrimarySymbol(a);
            exports.add("{\"name\": " + q(s != null ? s.getName() : "")
                    + ", \"vaddr\": " + q("0x" + a) + "}");
        }
        writeJsonArray(new File(outDir, "exports.json"), exports);
    }

    private void exportSinkXrefs(File outDir, Set<String> sinks) throws Exception {
        List<String> json = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();

        try (PrintWriter txt = new PrintWriter(new File(outDir, "xrefs.txt"), "UTF-8")) {
            for (String sink : sinks) {
                // Collect every address that embodies this sink: external symbols,
                // same-named labels, and functions (incl. PLT thunks, "_name").
                Set<Address> addrs = new LinkedHashSet<>();
                for (String variant : new String[] { sink, "_" + sink }) {
                    SymbolIterator si = st.getSymbols(variant);
                    while (si.hasNext()) addrs.add(si.next().getAddress());
                    Function f = getFunction(variant);
                    if (f != null) addrs.add(f.getEntryPoint());
                }
                for (Address a : addrs) {
                    for (Reference r : getReferencesTo(a)) {
                        Function from = getFunctionContaining(r.getFromAddress());
                        String fn = (from != null) ? from.getName() : "";
                        txt.printf("%-14s <- 0x%s in %s (%s)%n",
                                sink, r.getFromAddress(), fn, r.getReferenceType());
                        json.add("{\"sink\": " + q(sink)
                                + ", \"from\": " + q("0x" + r.getFromAddress())
                                + ", \"function\": " + q(fn)
                                + ", \"type\": " + q(r.getReferenceType().toString())
                                + ", \"is_call\": " + r.getReferenceType().isCall() + "}");
                    }
                }
            }
        }
        writeJsonArray(new File(outDir, "xrefs.json"), json);
    }

    // ---- tiny JSON helpers (no external libs in script scope) ----

    private static void writeJsonArray(File f, List<String> objs) throws Exception {
        try (PrintWriter w = new PrintWriter(f, "UTF-8")) {
            w.println("[");
            for (int i = 0; i < objs.size(); i++) {
                w.println("  " + objs.get(i) + (i < objs.size() - 1 ? "," : ""));
            }
            w.println("]");
        }
    }

    private static String q(String s) {
        if (s == null) return "\"\"";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
