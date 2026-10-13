#!/usr/bin/env python3
"""Validate evaluation/oracle_mapping.csv against the oracle binaries.

Usage: check_oracle_mapping.py [--freeze]

Table-level checks
  * header names and order match HEADER exactly; every row has that many fields
  * the table is nonempty and (sample_id, optimization) is unique
Per-row checks
  * every field has the right syntax; booleans and enums take allowed values
  * analysis_region and evidence_region: start < end, evidence inside analysis,
    boundaries on instruction boundaries, analysis_region_start == canonical_function_entry
  * canonical_function_entry is a FUNC symbol (any binding) named canonical_function_name,
    and analysis_region_end == entry + symbol size
  * ghidra_stripped_function matches the stripped-binary Ghidra dump (name, inclusive
    bounds, size, contiguous body) and equals the analysis region
  * candidate_ranges (syntax, start < end) equals the non-empty line-table ranges of
    target_source_line, and candidate_addresses are the range starts, in order
  * canonical_address maps (addr2line -i) to target_source_line, is inside the selected
    instance's copy ranges and the evidence region, and is the first explicit
    memory-destination mov (not rip-relative) in those ranges
  * evidence region: stack rows = hull of the selected copy ranges; heap rows start at
    alloc_size_address and end at the hull end; the end is at or after the last store
  * alloc_size_address is `mov edi|rdi, imm` equal to alloc_size_value and the next call
    is malloc@plt (heap rows only; stack rows must leave both empty)
  * strcpy_call_present equals the presence of a call/jmp to strcpy or a strcpy import
  * target_standalone / target_inlined / multiple_instances, canonical_instance_type,
    callsite_addresses and secondary_instances agree with the instances found in the
    line table, and with the addr2line -i inline stack
  * reachable_from_main (selected and secondary) equals reachability from `main` over direct
    call AND direct jump edges (so tail jumps count), the selected instance is reachable, and
    it follows the selection policy in oracle_mapping_schema.md
  * standalone callsites are exactly the direct `call` instructions that target the entry
Freeze
  * with --freeze (and all checks passing) write evaluation/oracle_freeze.sha256
  * otherwise, if that file exists, every listed file must still hash the same

Limits: indirect calls and address-taken functions are not followed; an instance is
"standalone" when its host function is named source_function and "inline-<host>" otherwise;
functions without a .symtab FUNC symbol are rejected rather than sized from DWARF.
"""
import bisect
import csv
import hashlib
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "evaluation" / "oracle_mapping.csv"
FREEZE_PATH = ROOT / "evaluation" / "oracle_freeze.sha256"
ORACLE_DIR = ROOT / "build" / "artifacts" / "oracle"
GHIDRA_DIR = ROOT / "ghidra" / "output" / "recovery_check"

HEADER = [
    "sample_id", "optimization", "source_path", "target_source_line", "source_function",
    "candidate_addresses", "canonical_address", "canonical_function_entry",
    "canonical_function_name", "analysis_region_start", "analysis_region_end",
    "target_standalone", "target_inlined", "multiple_instances", "mapping_method",
    "mapping_verified", "candidate_ranges", "evidence_region_start", "evidence_region_end",
    "canonical_instance_type", "reachable_from_main", "callsite_addresses",
    "secondary_instances", "alloc_size_address", "alloc_size_value", "strcpy_call_present",
    "ghidra_stripped_function", "notes",
]
BOOLS = ["target_standalone", "target_inlined", "multiple_instances", "mapping_verified",
         "reachable_from_main", "strcpy_call_present"]
OPTIMIZATIONS = {"O0", "O1", "O2", "O3", "Os"}
INSTANCE_TYPES = {"standalone", "inlined"}

ID = r"[A-Za-z_]\w*"
HEX = r"0x[0-9a-f]+"
KIND = rf"(?:standalone|inline-{ID})"
RE_RANGE = re.compile(rf"^({KIND}):({HEX})-({HEX})$")
RE_SECONDARY = re.compile(rf"^({KIND})@({HEX})\((reachable|unreachable)\)$")
RE_GHIDRA = re.compile(rf"^(\S+)@({HEX})-({HEX})\((\d+)B\)$")
RE_BRANCH = re.compile(r"^(call|j[a-z]+)\s+([0-9a-f]+)\s+<")
RE_STORE_DST = re.compile(r"^(?:BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD) PTR \[(.*)\]$")


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Elf:
    def __init__(self, path):
        self.path = path
        self.funcs = {}  # entry -> (size, name), from .symtab FUNC symbols, any binding
        self.imports = set()
        section = None
        for line in run("readelf", "-sW", str(path)).splitlines():
            if line.startswith("Symbol table"):
                section = line.split("'")[1]
                continue
            f = line.split()
            if len(f) < 8 or not f[0].endswith(":"):
                continue
            name = f[7].split("@")[0]
            if section == ".dynsym":
                self.imports.add(name)
            elif section == ".symtab" and f[3] == "FUNC" and int(f[1], 16) != 0:
                self.funcs.setdefault(int(f[1], 16), (int(f[2]), name))
        self.entries = sorted(self.funcs)

        self.insns = {}  # addr -> (size, text without comment)
        for line in run("objdump", "-d", "-Mintel", "--insn-width=16", str(path)).splitlines():
            p = line.split("\t")
            if len(p) >= 3 and p[0].strip().endswith(":") and re.fullmatch(r"[0-9a-f]+", p[0].strip()[:-1]):
                self.insns[int(p[0].strip()[:-1], 16)] = (len(p[1].split()), p[2].split("#")[0].strip())
        self.boundaries = set(self.insns) | {a + s for a, (s, _) in self.insns.items()}

        self.rows = []  # (line or None, addr) from .debug_line, in file order
        for line in run("objdump", "--dwarf=decodedline", str(path)).splitlines():
            m = re.match(rf"^\S+\s+(\d+|-)\s+({HEX})(?:\s|$)", line)
            if m:
                self.rows.append((None if m.group(1) == "-" else int(m.group(1)), int(m.group(2), 16)))

    def host(self, addr):
        """Entry of the sized FUNC symbol containing addr, or None."""
        i = bisect.bisect_right(self.entries, addr) - 1
        if i < 0:
            return None
        entry = self.entries[i]
        size = self.funcs[entry][0]
        return entry if not size or addr < entry + size else None

    def line_ranges(self, line):
        """Non-empty [start, end) address ranges the line table assigns to a source line.

        A row lasts until the next row; rows superseded at the same address are empty."""
        out = set()
        for (ln, a), (_, nxt) in zip(self.rows, self.rows[1:]):
            if ln == line and nxt > a:
                out.add((a, nxt))
        return sorted(out)

    def reachable_from_main(self):
        main = next((a for a, (_, n) in self.funcs.items() if n == "main"), None)
        edges = defaultdict(set)
        for addr, (_, text) in self.insns.items():
            m = RE_BRANCH.match(text)
            host = self.host(addr)
            if m and host is not None:
                target = int(m.group(2), 16)
                if target in self.funcs and target != host:
                    edges[host].add(target)
        seen, todo = set(), deque([main] if main is not None else [])
        while todo:
            f = todo.popleft()
            if f not in seen:
                seen.add(f)
                todo.extend(edges[f])
        return seen

    def inline_stack(self, addr):
        out = run("addr2line", "-f", "-i", "-e", str(self.path), hex(addr)).splitlines()
        return [(out[i], out[i + 1].rsplit(":", 1)[-1].split()[0]) for i in range(0, len(out) - 1, 2)]

    def store_addrs(self, ranges):
        """Explicit, non-rip-relative memory-destination moves inside the ranges, in address order."""
        out = []
        for a in sorted(self.insns):
            if not any(lo <= a < hi for lo, hi in ranges):
                continue
            mnemonic, _, operands = self.insns[a][1].partition(" ")
            m = RE_STORE_DST.match(operands.strip().split(",")[0])
            if mnemonic.startswith("mov") and m and "rip" not in m.group(1):
                out.append(a)
        return out

    def call_sites_to(self, target):
        return sorted(a for a, (_, t) in self.insns.items()
                      if (m := RE_BRANCH.match(t)) and m.group(1) == "call" and int(m.group(2), 16) == target)

    def strcpy_call_present(self):
        calls = any(re.match(r"^(call|j[a-z]+)\s+[0-9a-f]+\s+<strcpy[@>+]", t) for _, t in self.insns.values())
        return calls or "strcpy" in self.imports


def ghidra_functions(sid, opt):
    """entry -> (name, min, max, numAddresses) from the stripped-binary Ghidra dump."""
    path = GHIDRA_DIR / f"{sid}_{opt}_stripped.txt"
    out = {}
    for line in path.read_text().splitlines():
        if line.startswith("== decompiled"):
            break
        m = re.match(r"^([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+(\d+)\s+thunk=", line)
        if m:
            out[int(m.group(1), 16)] = (m.group(2), int(m.group(3), 16), int(m.group(4), 16), int(m.group(5)))
    return out


def merge_adjacent(ranges):
    """ranges: (kind, host, start, end). Join ranges of one instance that touch."""
    out = []
    for k, h, a, b in sorted(ranges, key=lambda r: (r[0], r[1], r[2])):
        if out and out[-1][:2] == (k, h) and out[-1][3] == a:
            out[-1] = (k, h, out[-1][2], b)
        else:
            out.append((k, h, a, b))
    return out


def validate_syntax(row):
    errs = []

    def need(field, pattern):
        if not re.fullmatch(pattern, row[field]):
            errs.append(f"{field}={row[field]!r} is not {pattern}")

    def need_list(field, pattern, allow_empty=False):
        items = [i for i in row[field].split(";") if i]
        if not items and not allow_empty:
            errs.append(f"{field} is empty")
        for i in items:
            if not re.fullmatch(pattern, i):
                errs.append(f"{field} item {i!r} is not {pattern}")

    need("sample_id", r"sample_\d{4}")
    if row["optimization"] not in OPTIMIZATIONS:
        errs.append(f"optimization={row['optimization']!r} not in {sorted(OPTIMIZATIONS)}")
    if not (ROOT / row["source_path"]).is_file():
        errs.append(f"source_path {row['source_path']!r} does not exist")
    need("target_source_line", r"[1-9]\d*")
    need("source_function", ID)
    need("canonical_function_name", ID)
    for f in ["canonical_address", "canonical_function_entry", "analysis_region_start",
              "analysis_region_end", "evidence_region_start", "evidence_region_end"]:
        need(f, HEX)
    need_list("candidate_addresses", HEX)
    need_list("candidate_ranges", rf"{KIND}:{HEX}-{HEX}")
    need_list("callsite_addresses", rf"(?:inline@)?{HEX}")
    need_list("secondary_instances", rf"{KIND}@{HEX}\((?:reachable|unreachable)\)", allow_empty=True)
    for f in BOOLS:
        if row[f] not in ("true", "false"):
            errs.append(f"{f}={row[f]!r} is not true/false")
    if row["canonical_instance_type"] not in INSTANCE_TYPES:
        errs.append(f"canonical_instance_type={row['canonical_instance_type']!r} not in {sorted(INSTANCE_TYPES)}")
    need("alloc_size_address", rf"(?:{HEX})?")
    need("alloc_size_value", r"(?:[1-9]\d*)?")
    if bool(row["alloc_size_address"]) != bool(row["alloc_size_value"]):
        errs.append("alloc_size_address and alloc_size_value must both be set or both empty")
    if not RE_GHIDRA.match(row["ghidra_stripped_function"]):
        errs.append(f"ghidra_stripped_function={row['ghidra_stripped_function']!r} does not match {RE_GHIDRA.pattern}")
    for f in ("mapping_method", "notes"):
        if not row[f].strip():
            errs.append(f"{f} is empty")
    return errs


def check_row(row, elf, ghidra):
    errs = validate_syntax(row)
    if errs:
        return errs

    def err(msg):
        errs.append(msg)

    h = lambda f: int(row[f], 16)
    line = int(row["target_source_line"])
    entry, name = h("canonical_function_entry"), row["canonical_function_name"]
    a_start, a_end = h("analysis_region_start"), h("analysis_region_end")
    e_start, e_end = h("evidence_region_start"), h("evidence_region_end")
    addr = h("canonical_address")
    inlined = row["canonical_instance_type"] == "inlined"
    heap = bool(row["alloc_size_address"])

    # --- regions ---------------------------------------------------------------------
    if not a_start < a_end:
        err("analysis_region_start >= analysis_region_end")
    if not e_start < e_end:
        err("evidence_region_start >= evidence_region_end")
    if not (a_start <= e_start and e_end <= a_end):
        err("evidence region is not inside the analysis region")
    if a_start != entry:
        err("analysis_region_start != canonical_function_entry")
    for f in ("analysis_region_start", "evidence_region_start"):
        if h(f) not in elf.insns:
            err(f"{f} is not an instruction address")
    for f in ("analysis_region_end", "evidence_region_end"):
        if h(f) not in elf.boundaries:
            err(f"{f} is not on an instruction boundary")
    if entry not in elf.funcs:
        err("canonical_function_entry is not a FUNC symbol in the oracle")
        return errs
    size, sym_name = elf.funcs[entry]
    if sym_name != name:
        err(f"symbol at entry is {sym_name!r}, canonical_function_name is {name!r}")
    if not size or a_end != entry + size:
        err(f"analysis_region_end != entry + symbol size ({hex(entry + size)})")

    # --- Ghidra recovery -------------------------------------------------------------
    gname, gmin, gmax, gn = RE_GHIDRA.match(row["ghidra_stripped_function"]).groups()
    gmin, gmax, gn = int(gmin, 16), int(gmax, 16), int(gn)
    dump = ghidra.get(gmin)
    if dump is None:
        err("ghidra_stripped_function entry is not in the Ghidra dump")
    elif dump != (gname, gmin, gmax, gn):
        err(f"ghidra_stripped_function differs from the Ghidra dump {dump}")
    if gn != gmax - gmin + 1:
        err("Ghidra body is not one contiguous range (numAddresses != max-min+1)")
    if (gmin, gmax + 1) != (a_start, a_end):
        err("Ghidra bounds (max+1) differ from the analysis region")

    # --- candidate ranges and instances ----------------------------------------------
    declared = []
    for item in row["candidate_ranges"].split(";"):
        kind, lo, hi = RE_RANGE.match(item).groups()
        lo, hi = int(lo, 16), int(hi, 16)
        if not lo < hi:
            err(f"candidate range {item} has start >= end")
        host = elf.host(lo)
        if host is None or elf.host(hi - 1) != host:
            err(f"candidate range {item} is not inside one function")
            return errs
        declared.append((kind, host, lo, hi))
    if [hex(r[2]) for r in declared] != row["candidate_addresses"].split(";"):
        err("candidate_addresses are not the candidate_ranges starts in order")

    derived = []
    for lo, hi in elf.line_ranges(line):
        host = elf.host(lo)
        if host is None:
            err(f"line-table range {hex(lo)}-{hex(hi)} is outside every FUNC symbol")
            return errs
        kind = "standalone" if elf.funcs[host][1] == row["source_function"] else f"inline-{elf.funcs[host][1]}"
        derived.append((kind, host, lo, hi))
    if set(merge_adjacent(declared)) != set(merge_adjacent(derived)):
        err("candidate_ranges differ from the line table: "
            f"declared-only={sorted(set(merge_adjacent(declared)) - set(merge_adjacent(derived)))} "
            f"line-table-only={sorted(set(merge_adjacent(derived)) - set(merge_adjacent(declared)))}")

    keys = {(k, hst) for k, hst, _, _ in derived}
    sel_kind = "standalone" if not inlined else f"inline-{name}"
    sel_key = (sel_kind, entry)
    if sel_key not in keys:
        err("no line-table instance matches canonical_instance_type and canonical_function_entry")
        return errs
    if (name == row["source_function"]) == inlined:
        err("canonical_function_name vs source_function contradicts canonical_instance_type")
    sel_ranges = [(a, b) for k, hst, a, b in derived if (k, hst) == sel_key]

    # --- flags -----------------------------------------------------------------------
    for field, want in (("target_standalone", any(k == "standalone" for k, _ in keys)),
                        ("target_inlined", any(k.startswith("inline-") for k, _ in keys)),
                        ("multiple_instances", len(keys) > 1)):
        if (row[field] == "true") != want:
            err(f"{field}={row[field]} but the line table implies {str(want).lower()}")

    # --- reachability, selection policy, secondary instances -------------------------
    reach = elf.reachable_from_main()
    if (row["reachable_from_main"] == "true") != (entry in reach):
        err(f"reachable_from_main={row['reachable_from_main']} but main reaches it: {entry in reach}")
    if entry not in reach:
        err("selected instance is not reachable from main (policy rules 5-6)")
    best = min((k for k in keys if k[1] in reach), key=lambda k: (elf.funcs[k[1]][0], k[1]), default=None)
    if best != sel_key:
        err(f"selection policy picks {best}, row selects {sel_key}")
    secondary = {}
    for item in filter(None, row["secondary_instances"].split(";")):
        kind, a, state = RE_SECONDARY.match(item).groups()
        secondary[(kind, int(a, 16))] = state == "reachable"
    if set(secondary) != keys - {sel_key}:
        err(f"secondary_instances {sorted(secondary)} != other line-table instances {sorted(keys - {sel_key})}")
    for key, declared_reach in secondary.items():
        if declared_reach != (key[1] in reach):
            err(f"secondary {key} reachability is {key[1] in reach}, row says {declared_reach}")

    # --- callsites -------------------------------------------------------------------
    sites = row["callsite_addresses"].split(";")
    if inlined:
        if sites != [f"inline@{hex(entry)}"]:
            err(f"inlined instance needs callsite_addresses == inline@{hex(entry)}")
    else:
        if any(s.startswith("inline@") for s in sites):
            err("standalone instance has an inline@ callsite")
        elif sorted(int(s, 16) for s in sites) != elf.call_sites_to(entry):
            err(f"callsites {sites} != direct calls to {hex(entry)}: {[hex(c) for c in elf.call_sites_to(entry)]}")

    # --- canonical address -----------------------------------------------------------
    if addr not in elf.insns:
        err("canonical_address is not an instruction address")
    if not any(a <= addr < b for a, b in sel_ranges):
        err("canonical_address is outside the selected instance's copy ranges")
    if not e_start <= addr < e_end:
        err("canonical_address is outside the evidence region")
    stack = elf.inline_stack(addr)
    if not stack or stack[0] != (row["source_function"], row["target_source_line"]):
        err(f"addr2line -i innermost frame is {stack[:1]}, expected {(row['source_function'], row['target_source_line'])}")
    if inlined and (len(stack) < 2 or stack[-1][0] != name):
        err(f"inlined instance but outermost addr2line frame is {stack[-1:]}, expected {name}")
    if not inlined and len(stack) != 1:
        err(f"standalone instance but addr2line -i has {len(stack)} frames")
    stores = elf.store_addrs(sel_ranges)
    if not stores or stores[0] != addr:
        err(f"canonical_address is not the first memory-destination store in the copy ranges ({[hex(s) for s in stores[:2]]}...)")
    elif e_end < stores[-1] + elf.insns[stores[-1]][0]:
        err("evidence_region_end is before the end of the last destination store")

    # --- evidence region definition and allocation -----------------------------------
    hull_start, hull_end = min(a for a, _ in sel_ranges), max(b for _, b in sel_ranges)
    if e_end != hull_end:
        err(f"evidence_region_end {hex(e_end)} != copy-range hull end {hex(hull_end)}")
    if heap:
        alloc = h("alloc_size_address")
        if e_start != alloc:
            err("heap row: evidence_region_start != alloc_size_address")
        m = re.match(r"^mov\s+[er]di,(0x[0-9a-f]+)$", elf.insns.get(alloc, (0, ""))[1])
        if not m:
            err("alloc_size_address is not `mov edi|rdi, imm`")
        elif int(m.group(1), 16) != int(row["alloc_size_value"]):
            err(f"alloc immediate {int(m.group(1), 16)} != alloc_size_value {row['alloc_size_value']}")
        nxt = next((t for a, (_, t) in sorted(elf.insns.items()) if a > alloc and t.startswith("call")), "")
        if "<malloc@plt>" not in nxt:
            err(f"first call after alloc_size_address is {nxt!r}, not malloc@plt")
        if not alloc < addr:
            err("alloc_size_address is not before canonical_address")
    elif e_start != hull_start:
        err(f"stack row: evidence_region_start {hex(e_start)} != copy-range hull start {hex(hull_start)}")

    if (row["strcpy_call_present"] == "true") != elf.strcpy_call_present():
        err(f"strcpy_call_present={row['strcpy_call_present']} but binary says {elf.strcpy_call_present()}")
    return errs


def freeze_entries(rows):
    paths = [CSV_PATH]
    for r in rows:
        paths.append(ORACLE_DIR / f"{r['sample_id']}_{r['optimization']}.elf")
        paths.append(GHIDRA_DIR / f"{r['sample_id']}_{r['optimization']}_stripped.txt")
    return paths


def main():
    freeze = "--freeze" in sys.argv[1:]
    table_errs = []
    raw = list(csv.reader(CSV_PATH.open(newline="")))
    if not raw or raw[0] != HEADER:
        table_errs.append(f"header mismatch: got {raw[0] if raw else None}")
    rows = []
    for i, fields in enumerate(raw[1:], start=2):
        if len(fields) != len(HEADER):
            table_errs.append(f"line {i}: {len(fields)} fields, expected {len(HEADER)}")
        else:
            rows.append(dict(zip(HEADER, fields)))
    if not rows:
        table_errs.append("no data rows")
    keys = [(r["sample_id"], r["optimization"]) for r in rows]
    for k in {k for k in keys if keys.count(k) > 1}:
        table_errs.append(f"duplicate row {k}")

    failures = 0
    if table_errs:
        print("[FAIL] table")
        for e in table_errs:
            print("       -", e)
        sys.exit(1)

    cache = {}
    for row in rows:
        tag = f"{row['sample_id']}/{row['optimization']}"
        errs = []
        elf_path = ORACLE_DIR / f"{row['sample_id']}_{row['optimization']}.elf"
        try:
            if elf_path not in cache:
                cache[elf_path] = Elf(elf_path)
            errs = check_row(row, cache[elf_path], ghidra_functions(row["sample_id"], row["optimization"]))
        except (OSError, subprocess.CalledProcessError, AttributeError, KeyError, ValueError) as e:
            errs.append(f"checker error: {type(e).__name__}: {e}")
        print(f"[{'OK  ' if not errs else 'FAIL'}] {tag} ({len(HEADER)} columns)")
        for e in errs:
            print("       -", e)
        failures += bool(errs)

    if not failures:
        if freeze:
            lines = [f"{sha256(p)}  {p.relative_to(ROOT).as_posix()}" for p in freeze_entries(rows)]
            FREEZE_PATH.write_text("\n".join(lines) + "\n")
            print(f"[FROZEN] wrote {FREEZE_PATH.relative_to(ROOT)} ({len(lines)} files)")
        elif FREEZE_PATH.exists():
            bad = []
            for line in FREEZE_PATH.read_text().splitlines():
                digest, rel = line.split("  ", 1)
                if not (ROOT / rel).is_file() or sha256(ROOT / rel) != digest:
                    bad.append(rel)
            print(f"[{'FAIL' if bad else 'OK  '}] freeze {FREEZE_PATH.name}" + (f": changed {bad}" if bad else ""))
            failures += bool(bad)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
