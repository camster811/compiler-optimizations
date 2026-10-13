// Dump the functions Ghidra recovers from a binary, plus decompiler output.
// Uses only what Ghidra discovers; no oracle names, labels, or addresses.
//
// Script args: <output_dir> <tag>
//@category Evaluation
import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class DumpFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args[0]);
        String tag = args[1];
        outDir.mkdirs();

        String base = currentProgram.getName().replace(".elf", "");
        File out = new File(outDir, base + "_" + tag + ".txt");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        try (PrintWriter w = new PrintWriter(out)) {
            w.println("program: " + currentProgram.getName());
            w.println("== functions (entry name min max numAddresses thunk external callRefs) ==");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                AddressSetView body = f.getBody();
                int callRefs = 0;
                for (Reference r : getReferencesTo(f.getEntryPoint())) {
                    if (r.getReferenceType().isCall()) {
                        callRefs++;
                    }
                }
                w.printf("%s %s %s %s %d thunk=%b external=%b callRefs=%d%n",
                    f.getEntryPoint(), f.getName(), body.getMinAddress(), body.getMaxAddress(),
                    body.getNumAddresses(), f.isThunk(), f.isExternal(), callRefs);
            }

            w.println();
            w.println("== decompiled ==");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) {
                    continue;
                }
                w.println("---- " + f.getName() + " @ " + f.getEntryPoint());
                DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                if (res.decompileCompleted()) {
                    w.println(res.getDecompiledFunction().getC());
                } else {
                    w.println("decompile failed: " + res.getErrorMessage());
                }
            }
        }
    }
}
