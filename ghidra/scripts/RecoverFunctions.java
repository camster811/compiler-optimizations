// Private recovery evidence, independent of the selected public record.
//@category Evaluation
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.AddressRange;

public class RecoverFunctions extends GhidraScript {
    protected void run() throws Exception {
        List<Map<String,Object>> functions = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal()) continue;
            Map<String,Object> row = new LinkedHashMap<>();
            row.put("entry", "0x" + Long.toHexString(f.getEntryPoint().getOffset()));
            row.put("name", f.getName());
            List<List<String>> ranges = new ArrayList<>();
            for (AddressRange r : f.getBody().getAddressRanges()) {
                ranges.add(List.of("0x" + Long.toHexString(r.getMinAddress().getOffset()),
                                  "0x" + Long.toHexString(r.getMaxAddress().getOffset() + 1)));
            }
            row.put("body_ranges", ranges); functions.add(row);
        }
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(functions));
    }
}
