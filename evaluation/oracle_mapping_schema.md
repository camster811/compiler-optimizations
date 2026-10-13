# oracle_mapping.csv schema

Private ground truth. Never copy this file, or anything derived from it, into
static-analysis or LLM-facing inputs. All addresses come from
`build/artifacts/oracle/<sample_id>_<opt>.elf`. The retained and stripped
artifacts have the same `.text` hash (see `build/artifacts/private/build_manifest.tsv`).

Multi-valued fields use `;` as the separator. Ranges are `start-end` with `end`
exclusive, except Ghidra function bounds, which are inclusive as Ghidra reports them.

## Canonical selection policy (reachability first)

1. Enumerate every emitted binary instance of the target source operation
   (standalone function bodies and inlined copies).
2. Keep the instances reachable from `main`.
3. If exactly one is reachable, select it.
4. If several are reachable, select the smallest enclosing function; break ties
   by lowest address.
5. A standalone instance is selected only if it is reachable.
6. Unreachable emitted copies are recorded in `secondary_instances`, never selected.

This replaces the earlier standalone-first rule. It only changes `sample_0002` O2,
where the executed copy is inlined into `main` and the standalone
`copy_message` is dead code.

Duplication and inlining are recorded separately: `multiple_instances` (more than
one emitted instance), `target_inlined` (an inlined instance exists),
`target_standalone` (a standalone function body exists).

## Fields added in phase 2b

| Field | Meaning |
|---|---|
| `candidate_ranges` | Line-table ranges for the copy line, per instance, as `standalone:` or `inline-<function>:` prefixed ranges |
| `canonical_address` | First instruction that stores into the destination object, in the selected instance |
| `analysis_region_start` / `analysis_region_end` | The function body handed to the tools: the Ghidra-recovered body of the stripped binary, `end` exclusive (Ghidra max + 1). It equals the oracle `.symtab` `FUNC` extent (`entry + size`), and `analysis_region_start == canonical_function_entry`. For an inlined instance this is the host function (`main`), not the inlined callee |
| `evidence_region_start` / `evidence_region_end` | The smallest contiguous evidence region containing the facts needed to classify the selected instance. For stack cases this covers the copy-line ranges; for heap cases it begins at allocation-size setup and ends after the final destination write. It lies inside the analysis region. (Renamed from `canonical_target_start` / `canonical_target_end`, whose old definition, the hull of the target line ranges, disagreed with the heap rule) |

| `canonical_instance_type` | `standalone` or `inlined` |
| `reachable_from_main` | Whether the selected instance executes from `main` |
| `callsite_addresses` | Call instruction address, or `inline@<entry>` for an inlined instance |
| `secondary_instances` | Other emitted instances, with reachability |
| `alloc_size_address` / `alloc_size_value` | Heap only: instruction that sets the `malloc` size argument and its immediate value |
| `strcpy_call_present` | Whether a `strcpy` call survives in the binary |
| `ghidra_stripped_function` | What Ghidra headless recovers from the stripped artifact: generated name, inclusive bounds and size |

`canonical_function_entry` and `canonical_function_name` are the enclosing region
that is handed to the tools. `canonical_address` is evidence inside that region,
not the region itself.

Ghidra dumps are in `ghidra/output/recovery_check/` and are produced by

`ghidra/scripts/DumpFunctions.java`.


## Interpretation limits


Keep this wording in the report.


- `strcpy_call_present=false` appears at both O0 and O2. It is compiler builtin

  lowering or constant-copy expansion observed across optimization levels, not an
  effect of O2 alone.

- The stack labels are source-vulnerable: the copy exceeds the source-language
  object bounds. The `sample_0001` O2 binary is not shown to overwrite the return
  address and is not claimed to be exploitable. At O0 the NUL lands on the low byte
  of the saved `rbp`; that is a layout observation, not an exploit claim.

- The heap overflow may be silent at runtime because allocators can provide more
  usable space than requested. That is allocator-dependent and was not tested.

- Ghidra recovering the dead standalone `copy_message` in `sample_0002` O2 is
  unexplained. The `.eh_frame` explanation is a hypothesis until a diagnostic copy
  with `.eh_frame` and `.eh_frame_hdr` removed is tested.


## Checker and freeze


`evaluation/check_oracle_mapping.py` validates the table (see its docstring for the

full list) and exits nonzero on any failure. `--freeze` writes
`evaluation/oracle_freeze.sha256` (SHA-256 of the CSV, the eight oracle ELFs and the
stripped-binary Ghidra dumps). Later runs fail if any listed file changes.


Not verified: that `canonical_address` stores into the intended source object (the

check is the first explicit memory-destination `mov` in the copy ranges), indirect

calls, and Ghidra bodies made of several ranges (the dump only records min, max and

count, so the checker requires a contiguous body).
