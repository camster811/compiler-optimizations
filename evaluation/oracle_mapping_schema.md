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
| `canonical_target_start` / `canonical_target_end` | Hull of the target line ranges in the selected instance. Heap rows start at the `malloc` size argument so allocation size and write extent are both inside the region |
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
