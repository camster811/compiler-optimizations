#!/usr/bin/env python3
"""Acceptance check for the Ghidra extraction (PRIVATE: reads the oracle mapping).

Run after ghidra/run_headless.sh. Checks:
  * exactly 16 JSON records (8 retained + 8 stripped), each expected sample/optimization once
  * every record validates against ghidra/record_schema.json
  * every record resolved its target (status ok); decompilation failures must be structured
    (schema) and are reported as warnings
  * the recovered function equals the oracle analysis region (entry == analysis_region_start,
    one contiguous body ending at analysis_region_end) and retained/stripped agree on it
  * retained records keep the symbol name, stripped records use a generated FUN_ name and
    never contain the oracle function/source function name
  * no record contains CWE, ground-truth, source-path, Juliet, good/bad, optimization or
    symbol-condition text
  * the private run metadata matches ghidra/config.json, hashes the artifact on disk, used the
    mapped target address, and shows identical analysis options for all 16 runs
"""
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
GHIDRA = ROOT / "ghidra"
CONDITIONS = ("retained", "stripped")

LEAK_PATTERNS = {
    "CWE": r"cwe",
    "Juliet": r"juliet",
    "ground truth": r"ground[ _-]?truth",
    "good/bad": r"\b(?:good|bad)\b",
    "vulnerable/fixed": r"\b(?:vulnerable|fixed)\b",
    "source path": r"source/|/experiment|case_[sh]\d+|\.c\b|\.elf\b|sample_\d{4}_",
    "optimization level": r"\bO[0-3s]\b|-O[0-3s]\b",
    "symbol condition": r"\b(?:retained|stripped)\b",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    config = json.loads((GHIDRA / "config.json").read_text())
    validator = Draft202012Validator(json.loads((GHIDRA / "record_schema.json").read_text()))
    rows = list(csv.DictReader((ROOT / "evaluation" / "oracle_mapping.csv").open(newline="")))
    expected = {f"{r['sample_id']}_{r['optimization']}": r for r in rows}

    errors, warnings = [], []
    records = {}

    # --- file set --------------------------------------------------------------------
    for cond in CONDITIONS:
        found = sorted(p.stem for p in (GHIDRA / "output" / cond).glob("*.json"))
        if len(found) != len(set(found)):
            errors.append(f"{cond}: duplicate files")
        missing, extra = set(expected) - set(found), set(found) - set(expected)
        if missing:
            errors.append(f"{cond}: missing {sorted(missing)}")
        if extra:
            errors.append(f"{cond}: unexpected {sorted(extra)}")
    total = sum(len(list((GHIDRA / "output" / c).glob("*.json"))) for c in CONDITIONS)
    if total != 2 * len(expected) or total != 16:
        errors.append(f"expected exactly 16 JSON records, found {total}")

    # --- per record ------------------------------------------------------------------
    for cond in CONDITIONS:
        for tag, row in expected.items():
            where = f"{cond}/{tag}"
            path = GHIDRA / "output" / cond / f"{tag}.json"
            if not path.is_file():
                continue
            text = path.read_text()
            try:
                rec = json.loads(text)
            except json.JSONDecodeError as e:
                errors.append(f"{where}: invalid JSON: {e}")
                continue
            schema_errs = sorted(validator.iter_errors(rec), key=lambda e: list(e.path))
            for e in schema_errs:
                errors.append(f"{where}: schema: {'/'.join(map(str, e.path)) or '<root>'}: {e.message[:120]}")
            if schema_errs:
                continue
            records[(cond, tag)] = rec

            if rec["sample_id"] != row["sample_id"]:
                errors.append(f"{where}: sample_id {rec['sample_id']} != {row['sample_id']}")
            if rec["status"] != "ok":
                errors.append(f"{where}: status {rec['status']}")
                continue
            if rec["decompilation"]["status"] != "ok":
                warnings.append(f"{where}: decompilation {rec['decompilation']['status']}: {rec['decompilation']['error']}")

            fn = rec["function"]
            start, end = int(row["analysis_region_start"], 16), int(row["analysis_region_end"], 16)
            ranges = [(int(a, 16), int(b, 16)) for a, b in fn["body_ranges"]]
            if int(fn["entry"], 16) != start:
                errors.append(f"{where}: entry {fn['entry']} != analysis_region_start {row['analysis_region_start']}")
            if ranges != [(start, end)]:
                errors.append(f"{where}: body_ranges {fn['body_ranges']} != [{row['analysis_region_start']}, {row['analysis_region_end']}]")
            if fn["size_bytes"] != sum(b - a for a, b in ranges):
                errors.append(f"{where}: size_bytes does not equal the body ranges")
            if fn["instruction_count"] != len(rec["instructions"]):
                errors.append(f"{where}: instruction_count != len(instructions)")

            oracle_names = {row["canonical_function_name"], row["source_function"]}
            if cond == "retained":
                if fn["name"] != row["canonical_function_name"]:
                    errors.append(f"{where}: retained name {fn['name']!r} != {row['canonical_function_name']!r}")
            else:
                if not re.fullmatch(r"FUN_[0-9a-f]+", fn["name"]):
                    errors.append(f"{where}: stripped name {fn['name']!r} is not Ghidra-generated")
                for name in oracle_names:
                    if re.search(rf"\b{re.escape(name)}\b", text):
                        errors.append(f"{where}: stripped record contains {name!r}")

            for label, pattern in LEAK_PATTERNS.items():
                m = re.search(pattern, text, re.I if label not in ("optimization level",) else 0)
                if m:
                    errors.append(f"{where}: leak ({label}): {m.group(0)!r}")

    # --- retained vs stripped agreement ----------------------------------------------
    for tag in expected:
        r, s = records.get(("retained", tag)), records.get(("stripped", tag))
        if not (r and s and r["function"] and s["function"]):
            continue
        for key in ("entry", "size_bytes", "instruction_count", "body_ranges"):
            if r["function"][key] != s["function"][key]:
                errors.append(f"{tag}: retained/stripped differ in function.{key}: {r['function'][key]} vs {s['function'][key]}")

    # --- private run metadata --------------------------------------------------------
    option_hashes = set()
    for cond in CONDITIONS:
        for tag, row in expected.items():
            where = f"{cond}/{tag}"
            meta_path = GHIDRA / "logs" / cond / f"{tag}.run.json"
            if not meta_path.is_file():
                errors.append(f"{where}: missing run metadata")
                continue
            meta = json.loads(meta_path.read_text())
            artifact = ROOT / "build" / "artifacts" / cond / f"{tag}.elf"
            checks = {
                "ghidra_version": config["ghidra_version"],
                "script_version": config["script_version"],
                "schema_version": config["schema_version"],
                "language_id": config["language_id"],
                "decompiler_timeout_s": config["decompiler"]["timeout_s"],
                "target_address": hex(int(row["analysis_region_start"], 16)),
                "program_sha256": sha256(artifact),
            }
            for key, want in checks.items():
                if meta.get(key) != want:
                    errors.append(f"{where}: run metadata {key}={meta.get(key)!r}, expected {want!r}")
            rec = records.get((cond, tag))
            if rec and rec["function"] and meta.get("resolved_entry") != rec["function"]["entry"]:
                errors.append(f"{where}: resolved_entry {meta.get('resolved_entry')} != record entry")
            option_hashes.add(meta.get("analysis_options_sha256"))
    if len(option_hashes) != 1:
        errors.append(f"analysis options differ across runs: {len(option_hashes)} distinct hashes")

    for w in warnings:
        print("[WARN]", w)
    for e in errors:
        print("[FAIL]", e)
    print(f"{'FAIL' if errors else 'OK'}: {total} records, {len(errors)} errors, {len(warnings)} warnings")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
