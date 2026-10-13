#!/usr/bin/env python3
"""Rule-based static baseline over analyzer-facing Ghidra records.

Usage: analyze.py INPUT [INPUT ...] [-o OUTPUT]

INPUT is a record JSON file or a directory of them. The program reads nothing else: no
oracle mapping, no run metadata, no source, no file naming. File names and directories
are only used to find the files. Each prediction carries the SHA-256 of its record's raw
bytes as a content identifier, so predictions for the several records that share a
sample_id stay distinct without the analyzer knowing which variant a record is.
Byte-identical records get one prediction; the private evaluator maps a hash to the one
or more experimental observations that produced it.

The rules are described in rules.md.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

RECORD_KEYS = {"schema_version", "sample_id", "status", "function", "decompilation",
               "instructions", "calls", "tail_jumps", "constants", "stack_variables", "imports"}
SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16, "ymmword": 32}
STORE_MNEMONICS = {"MOV", "MOVABS", "MOVUPS", "MOVAPS", "MOVDQU", "MOVDQA", "MOVQ", "MOVD", "MOVSS", "MOVSD"}
CALLER_SAVED = ("RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11")
COPY_FUNCTIONS = {"strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf", "gets",
                  "memcpy", "memmove", "scanf", "sscanf"}
# Frozen pilot parameter (a heuristic, not derived from the data). A merged stack write of
# at least this many bytes that stays inside the frame is treated as buffer-like and recorded
# as "capacity unknown". Shorter writes (scalar spills and initializations) are ignored so that
# every ordinary local variable does not force an uncertain result.
MIN_BUFFER_LIKE_WRITE = 8
RE_MEM = re.compile(r"^(?:(\w+) ptr )?\[(.*)\]$")
RE_INS = re.compile(r"^0x([0-9a-f]+): (\S+)(?: (.*))?$")


def canon(reg):
    """Map a register name to its 64-bit general-purpose name, or None."""
    r = reg.upper()
    if m := re.fullmatch(r"(?:R|E)?([ABCD])X|([ABCD])[LH]", r):
        return f"R{m.group(1) or m.group(2)}X"
    if m := re.fullmatch(r"(?:R|E)?(SI|DI|BP|SP)|(SI|DI|BP|SP)L", r):
        return f"R{m.group(1) or m.group(2)}"
    if m := re.fullmatch(r"R(8|9|1[0-5])[DWB]?", r):
        return f"R{m.group(1)}"
    return None


def number(text):
    try:
        return int(text, 0)
    except ValueError:
        return None


def parse_mem(op):
    """'qword ptr [RAX + 0x7]' -> (size or None, base register or None, displacement); None if unsupported."""
    m = RE_MEM.match(op.strip())
    if not m:
        return None
    base, disp = None, 0
    for term in re.split(r"\s*\+\s*", m.group(2).strip()):
        if reg := canon(term):
            if base is not None:
                return None
            base = reg
        elif (n := number(term)) is not None:
            disp += n
        else:
            return None
    return (SIZES.get(m.group(1).lower()) if m.group(1) else None), base, disp


def merge(intervals):
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [tuple(i) for i in out]


def offset(n):
    return f"-0x{-n:x}" if n < 0 else f"+0x{n:x}"


class Trace:
    """Single straight-line pass over the listing. It follows which registers and spill
    slots hold a frame address or a malloc result, and records the stores made through
    them. It does not follow branches, so it is only meaningful for simple functions."""

    def __init__(self, instructions, calls):
        self.allocs = []         # {"size": int|None, "call": addr, "stores": [(lo, hi, addr)]}
        self.stack_stores = []   # (base, lo, hi, addr, bound or None)
        self.copy_calls = []     # (addr, callee)
        self.notes = []
        self._rbp_frame = False
        self._rsp_frame = None   # bytes taken by SUB RSP while RSP has not moved since
        self._walk(self._parse(instructions), list(calls))

    @staticmethod
    def _parse(instructions):
        out = []
        for line in instructions:
            m = RE_INS.match(line)
            if m:
                ops = [o.strip() for o in m.group(3).split(",")] if m.group(3) else []
                out.append((int(m.group(1), 16), m.group(2).upper(), ops))
        return out

    def _walk(self, parsed, calls):
        if sum(mn == "CALL" for _, mn, _ in parsed) != len(calls):
            self.notes.append("the call list does not match the CALL instructions")
            calls = None
        if len(parsed) >= 2 and parsed[0][1:] == ("PUSH", ["RBP"]) and parsed[1][1:] == ("MOV", ["RBP", "RSP"]):
            self._rbp_frame = True

        tags, slots, consts, call_index = {}, {}, {}, 0
        for addr, mn, ops in parsed:
            if mn == "CALL":
                name = calls[call_index] if calls else None
                call_index += 1
                if name in COPY_FUNCTIONS:
                    self.copy_calls.append((addr, name))
                size = consts.get("RDI")
                for r in CALLER_SAVED:
                    tags.pop(r, None)
                    consts.pop(r, None)
                if name == "malloc":
                    self.allocs.append({"size": size, "call": addr, "stores": []})
                    tags["RAX"] = ("heap", len(self.allocs) - 1, 0)
                continue
            if mn in ("PUSH", "POP", "LEAVE", "RET") or (mn in ("ADD", "SUB") and ops and canon(ops[0]) == "RSP"):
                if mn == "SUB" and self._rsp_frame is None and len(ops) == 2 and number(ops[1]):
                    self._rsp_frame = number(ops[1])
                elif self._rsp_frame is not None:
                    self._rsp_frame = -1
                if mn == "POP" and ops and (r := canon(ops[0])):
                    tags.pop(r, None)
                    consts.pop(r, None)
                continue
            if len(ops) < 1:
                continue

            if "[" in ops[0] and mn in STORE_MNEMONICS and (dst := parse_mem(ops[0])):
                size, base, disp = dst
                src = canon(ops[1]) if len(ops) > 1 else None
                if src in tags:
                    # Spilling a tracked pointer is bookkeeping, not a write into a buffer.
                    if base in ("RBP", "RSP"):
                        slots[(base, disp)] = tags[src]
                else:
                    self._store(addr, base, disp, size or 8, tags)
                    slots.pop((base, disp), None)
                continue

            dst = canon(ops[0])
            if dst is None:
                continue
            if mn == "LEA" and len(ops) == 2 and (mem := parse_mem(ops[1])):
                _, base, disp = mem
                consts.pop(dst, None)
                if base in ("RBP", "RSP"):
                    tags[dst] = ("stack", base, disp)
                elif base in tags:
                    kind, ident, off = tags[base]
                    tags[dst] = (kind, ident, off + disp)
                else:
                    tags.pop(dst, None)
            elif mn in STORE_MNEMONICS and len(ops) == 2:
                tags.pop(dst, None)
                consts.pop(dst, None)
                if src := canon(ops[1]):
                    if src in tags:
                        tags[dst] = tags[src]
                    if src in consts:
                        consts[dst] = consts[src]
                elif "[" in ops[1] and (mem := parse_mem(ops[1])) and (mem[1], mem[2]) in slots:
                    tags[dst] = slots[(mem[1], mem[2])]
                elif (n := number(ops[1])) is not None:
                    consts[dst] = n
            elif mn not in ("CMP", "TEST", "NOP"):
                tags.pop(dst, None)
                consts.pop(dst, None)

    def _store(self, addr, base, disp, size, tags):
        if base in ("RBP", "RSP"):
            self._stack_store(base, disp, size, addr)
        elif base in tags:
            kind, ident, off = tags[base]
            if kind == "heap":
                self.allocs[ident]["stores"].append((off + disp, off + disp + size, addr))
            else:
                self._stack_store(ident, off + disp, size, addr)

    def _stack_store(self, base, disp, size, addr):
        if base == "RBP":
            bound = 0 if self._rbp_frame else None
        else:
            bound = self._rsp_frame if self._rsp_frame and self._rsp_frame > 0 else None
        self.stack_stores.append((base, disp, disp + size, addr, bound))


def analyze(record):
    pred = {"sample_id": record["sample_id"], "classification": "uncertain", "predicted_cwe": None,
            "evidence": [], "triggered_rules": []}
    if record["status"] != "ok" or not record["instructions"]:
        pred["evidence"] = ["no function was recovered for this record"]
        pred["triggered_rules"] = ["no_function_recovered"]
        return pred

    trace = Trace(record["instructions"], record["calls"])
    findings, safe, unknown, underwrites = [], [], list(trace.notes), []

    for alloc in trace.allocs:
        size, at = alloc["size"], f"0x{alloc['call']:x}"
        groups = merge([(lo, hi) for lo, hi, _ in alloc["stores"]])
        if size is None:
            unknown.append(f"malloc at {at} has a size that is not a visible constant")
        elif not groups:
            unknown.append(f"malloc({size}) at {at} has no visible write through its pointer")
        for lo, hi in groups if size is not None else []:
            text = f"malloc({size}) is followed by a write of {hi - lo} bytes over [ptr{lo:+d}, ptr{hi:+d})"
            # Only a write past the end is CWE-122. A write before the start is an underwrite,
            # which is outside the project's CWE-121/122 scope and is never classified.
            if hi > size:
                findings.append((alloc["call"], "heap_write_exceeds_allocation", "CWE-122",
                                 f"{text} that ends {hi - size} byte(s) past the allocation"))
            if lo < 0:
                underwrites.append((alloc["call"], f"{text} that starts {-lo} byte(s) before the allocation; "
                                    "heap underwrites are outside the CWE-121/122 scope and are not classified"))
            if hi <= size and lo >= 0:
                safe.append((alloc["call"], f"{text} that lies inside the allocation"))

    for base, bound in sorted({(s[0], s[4]) for s in trace.stack_stores if s[4] is not None}):
        stores = [s for s in trace.stack_stores if s[0] == base and s[4] == bound and s[1] < bound]
        for lo, hi in merge([(s[1], s[2]) for s in stores]):
            first = min(s[3] for s in stores if lo <= s[1] < hi)
            r = base.lower()
            what = f"{hi - lo}-byte write over [{r}{offset(lo)}, {r}{offset(hi)})"
            if hi > bound:
                n = hi - bound
                if base == "RBP":
                    # The local area ends at rbp+0; the saved frame pointer occupies [rbp, rbp+8).
                    into = ("into the saved frame pointer" if n <= 8
                            else "through the saved frame pointer")
                    tail = f"beyond the local area {into}"
                else:
                    tail = f"beyond the {bound}-byte local area"
                findings.append((first, "stack_write_exceeds_frame_locals", "CWE-121",
                                 f"{what} extends {n} byte(s) {tail}"))
            elif hi - lo >= MIN_BUFFER_LIKE_WRITE:
                unknown.append(f"{what} stays inside the frame, but the destination buffer size is not recoverable")

    if findings:
        findings.sort()
        pred["classification"] = "vulnerable"
        pred["predicted_cwe"] = findings[0][2]
        pred["triggered_rules"] = sorted({f[1] for f in findings} | ({"unsupported_heap_underwrite"} if underwrites else set()))
        pred["evidence"] = [f[3] for f in findings] + [t for _, t in sorted(underwrites)]
    elif underwrites:
        pred["triggered_rules"] = ["unsupported_heap_underwrite"]
        pred["evidence"] = [t for _, t in sorted(underwrites)]
    elif trace.copy_calls:
        pred["triggered_rules"] = ["unresolved_copy_call"]
        pred["evidence"] = [f"call to {n} at 0x{a:x} whose destination capacity is not provable"
                            for a, n in trace.copy_calls]
    elif safe and not unknown:
        pred["classification"] = "not_vulnerable"
        pred["triggered_rules"] = ["heap_write_within_allocation"]
        pred["evidence"] = [t for _, t in sorted(safe)]
    else:
        pred["triggered_rules"] = ["insufficient_evidence"]
        pred["evidence"] = [t for _, t in sorted(safe)] + unknown or ["no recognized allocation or buffer write"]
    return pred


def load(path):
    raw = path.read_bytes()
    record = json.loads(raw)
    if set(record) != RECORD_KEYS:
        raise ValueError(f"{path.name}: record keys differ from the analyzer schema: {sorted(set(record) ^ RECORD_KEYS)}")
    return hashlib.sha256(raw).hexdigest(), record


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=Path(__file__).parent / "output" / "predictions.json")
    args = ap.parse_args()

    files = []
    for p in args.inputs:
        files.extend(p.glob("*.json") if p.is_dir() else [p])
    # record_sha256 identifies content, not an observation: byte-identical records get one
    # prediction, and the private evaluator maps each hash to its observation(s).
    by_hash = {}
    for f in files:
        digest, record = load(f)
        if digest not in by_hash:
            by_hash[digest] = {
                "record_sha256": digest,
                **analyze(record),
            }
    predictions = sorted(by_hash.values(), key=lambda p: (p["sample_id"], p["record_sha256"]))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(predictions, indent=2) + "\n")
    print(f"wrote {len(predictions)} predictions for {len(files)} input records to {args.output}")


if __name__ == "__main__":
    main()
