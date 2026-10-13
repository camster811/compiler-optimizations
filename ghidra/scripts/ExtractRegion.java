// Export one function from the analyzed program as a machine-readable record.
//
// The launcher passes a target address. The script finds the function containing it,
// decompiles it, and exports what Ghidra recovered. It never renames, comments or
// labels anything, and the analyzer-facing record carries no oracle information
// (no optimization level, symbol condition, source name, line, label or region end).
//
// Script args: <config.json> <sample_id> <target_address> <record_out.json> <run_meta_out.json>
//
// run_meta_out is PRIVATE (versions, binary hash, analysis options); never give it to an analyzer.
//@category Evaluation
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;

public class ExtractRegion extends GhidraScript {
    private static final String SCRIPT_VERSION = "1.0.0";
    private static final String SCHEMA_VERSION = "1.0";

    private final Gson gson =
        new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) {
            throw new IllegalArgumentException(
                "usage: <config.json> <sample_id> <target_address> <record_out> <run_meta_out>");
        }
        JsonObject config =
            JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        String sampleId = args[1];
        long targetOffset = Long.decode(args[2]);
        Path recordOut = Path.of(args[3]);
        Path metaOut = Path.of(args[4]);

        requireEqual("script_version", config.get("script_version").getAsString(), SCRIPT_VERSION);
        requireEqual("schema_version", config.get("schema_version").getAsString(), SCHEMA_VERSION);
        requireEqual("ghidra_version", config.get("ghidra_version").getAsString(),
            Application.getApplicationVersion());
        requireEqual("language_id", config.get("language_id").getAsString(),
            currentProgram.getLanguageID().getIdAsString());
        int decompileTimeout = config.getAsJsonObject("decompiler").get("timeout_s").getAsInt();

        Function function = getFunctionContaining(toAddr(targetOffset));

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("schema_version", SCHEMA_VERSION);
        record.put("sample_id", sampleId);
        if (function == null) {
            record.put("status", "function_not_found");
            record.put("function", null);
            record.put("decompilation", decompilation("failed", null, "no function at target"));
            record.put("instructions", new ArrayList<String>());
            record.put("calls", new ArrayList<String>());
            record.put("tail_jumps", new ArrayList<String>());
            record.put("constants", new ArrayList<String>());
            record.put("stack_variables", new ArrayList<Object>());
            record.put("imports", new ArrayList<String>());
        } else {
            record.put("status", "ok");
            fillRecord(record, function, decompileTimeout);
        }
        write(recordOut, record);

        Map<String, String> options = new TreeMap<>(getCurrentAnalysisOptionsAndValues(currentProgram));
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("sample_id", sampleId);
        meta.put("ghidra_version", Application.getApplicationVersion());
        meta.put("script_version", SCRIPT_VERSION);
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("language_id", currentProgram.getLanguageID().getIdAsString());
        meta.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        meta.put("program_sha256", currentProgram.getExecutableSHA256());
        meta.put("target_address", "0x" + Long.toHexString(targetOffset));
        meta.put("resolved_entry", function == null ? null : hex(function.getEntryPoint()));
        meta.put("decompiler_timeout_s", decompileTimeout);
        meta.put("analysis_options_sha256", sha256(options.toString()));
        meta.put("analysis_options", options);
        write(metaOut, meta);
    }

    private void fillRecord(Map<String, Object> record, Function f, int decompileTimeout)
            throws Exception {
        AddressSetView body = f.getBody();

        List<String> instructions = new ArrayList<>();
        List<String> calls = new ArrayList<>();
        List<String> tailJumps = new ArrayList<>();
        LinkedHashSet<String> imports = new LinkedHashSet<>();
        LinkedHashSet<String> constants = new LinkedHashSet<>();

        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            instructions.add(hex(ins.getAddress()) + ": " + ins);

            for (int i = 0; i < ins.getNumOperands(); i++) {
                int type = ins.getOperandType(i);
                if (OperandType.isScalar(type) && !OperandType.isAddress(type)) {
                    Scalar s = ins.getScalar(i);
                    if (s != null) {
                        constants.add(Long.toString(s.getSignedValue()));
                    }
                }
            }

            // Classify by p-code, not by reference type: Ghidra gives a jump to another
            // function a call-type reference, which would hide it among the calls.
            boolean isCall = false;
            boolean isJump = false;
            for (PcodeOp op : ins.getPcode()) {
                int code = op.getOpcode();
                isCall |= code == PcodeOp.CALL || code == PcodeOp.CALLIND;
                isJump |= code == PcodeOp.BRANCH || code == PcodeOp.CBRANCH
                    || code == PcodeOp.BRANCHIND;
            }
            if (isCall) {
                boolean resolved = false;
                for (Reference r : ins.getReferencesFrom()) {
                    if (r.getReferenceType().isCall()) {
                        resolved = true;
                        calls.add(targetName(r));
                        addImport(imports, r);
                    }
                }
                if (!resolved) {
                    calls.add("<indirect>");
                }
            } else if (isJump) {
                for (Reference r : ins.getReferencesFrom()) {
                    boolean leavesBody = r.isExternalReference() || !body.contains(r.getToAddress());
                    if ((r.getReferenceType().isJump() || r.getReferenceType().isCall()) && leavesBody
                            && (r.isExternalReference() || getFunctionAt(r.getToAddress()) != null)) {
                        tailJumps.add(targetName(r));
                        addImport(imports, r);
                    }
                }
            }
        }

        int blocks = 0;
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator bi = model.getCodeBlocksContaining(body, monitor);
        while (bi.hasNext()) {
            bi.next();
            blocks++;
        }

        List<List<String>> ranges = new ArrayList<>();
        for (AddressRange range : body.getAddressRanges()) {
            ranges.add(List.of(hex(range.getMinAddress()), "0x" + Long.toHexString(range.getMaxAddress().getOffset() + 1)));
        }

        Map<String, Object> function = new LinkedHashMap<>();
        function.put("name", f.getName());
        function.put("entry", hex(f.getEntryPoint()));
        function.put("size_bytes", body.getNumAddresses());
        function.put("instruction_count", instructions.size());
        function.put("basic_block_count", blocks);
        function.put("body_ranges", ranges);

        List<Object> stack = new ArrayList<>();
        for (Variable v : f.getStackFrame().getStackVariables()) {
            Map<String, Object> sv = new LinkedHashMap<>();
            sv.put("name", v.getName());
            sv.put("stack_offset", v.getStackOffset());
            sv.put("size_bytes", v.getLength());
            sv.put("data_type", v.getDataType().getName());
            stack.add(sv);
        }

        record.put("function", function);
        record.put("decompilation", decompile(f, decompileTimeout));
        record.put("instructions", instructions);
        record.put("calls", calls);
        record.put("tail_jumps", tailJumps);
        record.put("constants", new ArrayList<>(constants));
        record.put("stack_variables", stack);
        record.put("imports", new ArrayList<>(imports));
    }

    private Map<String, Object> decompile(Function f, int timeoutSeconds) {
        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(currentProgram)) {
                return decompilation("failed", null, "decompiler failed to open program");
            }
            DecompileResults res = decomp.decompileFunction(f, timeoutSeconds, monitor);
            if (res.isTimedOut()) {
                return decompilation("timeout", null, "timed out after " + timeoutSeconds + "s");
            }
            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                return decompilation("ok", res.getDecompiledFunction().getC(), null);
            }
            return decompilation("failed", null, String.valueOf(res.getErrorMessage()));
        } catch (Exception e) {
            return decompilation("failed", null, e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            decomp.dispose();
        }
    }

    private static Map<String, Object> decompilation(String status, String text, String error) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("status", status);
        d.put("text", text);
        d.put("error", error);
        return d;
    }

    private String targetName(Reference r) {
        if (r instanceof ExternalReference) {
            String label = ((ExternalReference) r).getLabel();
            if (label != null) {
                return label;
            }
        }
        Function callee = getFunctionAt(r.getToAddress());
        return callee != null ? callee.getName() : hex(r.getToAddress());
    }

    private void addImport(LinkedHashSet<String> imports, Reference r) {
        if (r.isExternalReference()) {
            imports.add(targetName(r));
            return;
        }
        Function callee = getFunctionAt(r.getToAddress());
        if (callee == null) {
            return;
        }
        Function thunked = callee.isThunk() ? callee.getThunkedFunction(true) : null;
        if (callee.isExternal() || (thunked != null && thunked.isExternal())) {
            imports.add(thunked != null ? thunked.getName() : callee.getName());
        }
    }

    private static String hex(Address a) {
        return "0x" + Long.toHexString(a.getOffset());
    }

    private static void requireEqual(String what, String configured, String actual) {
        if (!configured.equals(actual)) {
            throw new IllegalStateException(
                what + " mismatch: config=" + configured + " actual=" + actual);
        }
    }

    private static String sha256(String s) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void write(Path path, Object obj) throws Exception {
        Files.createDirectories(path.toAbsolutePath().getParent());
        Files.writeString(path, gson.toJson(obj) + "\n", StandardCharsets.UTF_8);
    }
}
