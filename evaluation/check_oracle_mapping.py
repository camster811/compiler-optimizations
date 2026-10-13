#!/usr/bin/env python3
"""Sanity-check evaluation/oracle_mapping.csv against the oracle binaries.

Checks, per row:
  * field count matches the header
  * canonical_address resolves (addr2line) to target_source_line
  * canonical_address lies in [canonical_target_start, canonical_target_end)
  * canonical_function_entry <= canonical_address < entry + symbol/DWARF-sized body
  * every callsite address is a call to canonical_function_entry
"""
import csv
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "evaluation" / "oracle_mapping.csv"


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def hexint(s):
    return int(s, 16)


def main():
    rows = list(csv.DictReader(CSV_PATH.open(newline="")))
    n_fields = len(rows[0])
    failures = 0
    for row in rows:
        sid, opt = row["sample_id"], row["optimization"]
        tag = f"{sid}/{opt}"
        elf = ROOT / "build" / "artifacts" / "oracle" / f"{sid}_{opt}.elf"
        errs = []

        if None in row or any(v is None for v in row.values()):
            errs.append("wrong field count")

        addr = hexint(row["canonical_address"])
        line = run("addr2line", "-e", str(elf), hex(addr)).strip().rsplit(":", 1)[1]
        if line.split()[0] != row["target_source_line"]:
            errs.append(f"addr2line gives line {line}, expected {row['target_source_line']}")

        start, end = hexint(row["canonical_target_start"]), hexint(row["canonical_target_end"])
        if not start <= addr < end:
            errs.append("canonical_address outside canonical_target range")

        entry = hexint(row["canonical_function_entry"])
        if not entry <= start:
            errs.append("target range starts before function entry")

        syms = run("readelf", "-sW", str(elf))
        sizes = {
            hexint(m.group(1)): int(m.group(2))
            for m in re.finditer(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+GLOBAL", syms, re.M)
            if hexint(m.group(1)) != 0
        }
        if entry not in sizes:
            errs.append("canonical_function_entry is not a FUNC symbol in the oracle")
        elif end > entry + sizes[entry]:
            errs.append("target range extends past function end")

        for cs in filter(None, row["callsite_addresses"].split(";")):
            if cs.startswith("inline@"):
                continue
            dis = run("objdump", "-d", "-Mintel", "--no-show-raw-insn",
                      f"--start-address={cs}", f"--stop-address={hex(hexint(cs) + 8)}", str(elf))
            m = re.search(rf"^\s*{cs[2:]}:\s+call\s+([0-9a-f]+)", dis, re.M)
            if not m or hexint(m.group(1)) != entry:
                errs.append(f"callsite {cs} is not a call to {row['canonical_function_entry']}")

        status = "OK  " if not errs else "FAIL"
        print(f"[{status}] {tag} ({n_fields} columns)")
        for e in errs:
            print("       -", e)
        failures += bool(errs)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
