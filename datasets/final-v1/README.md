# final-v1 corpus and frozen-input handoff

This is a source-selected, held-out corpus for the frozen v1.1 local LLM and the unchanged static baseline. It contains 20 vulnerable/fixed pairs (10 CWE-121 and 10 CWE-122), 40 neutral standalone C sources, four optimization levels, and two symbol conditions. No final LLM completion requests or accuracy scores have been produced.

| Matrix or workload | Count |
|---|---:|
| Planned observations | 320 |
| Eligible function observations | 216 |
| Proven-eliminated observations, not inferred | 104 |
| Distinct eligible raw records | 176 |
| Later LLM generations, three per distinct record | 528 |
| Complete rendered prompt tokens | 1,265–3,409 |
| Length exclusions / technical pair replacements | 0 / 4 |

The four-level scope was fixed after the four-pair batch passed build, oracle, Ghidra, static-contract and exact token checks. Final evidence-completeness review later rejected four wide-string pairs; whole-pair replacements and an accepted four-pair revalidation preserved the original optimization scope. The provisional checkpoint is retained as history, not as an accepted final dataset. At the source/optimization level, 100 targets are present, eight are transformed and 52 are eliminated. Symbol stripping duplicates these counts; it does not change the underlying executable write effect because all three derived artifacts share their `.text` bytes.

## Selection and scope

The source-only inventory considered 360 local Juliet files using flow variants 01 and 31. It qualified 141 pairs and selected 20 using the recorded diversity priority and path tie-breaker. After final evidence checks, four otherwise-qualified pairs were rejected for unavailable readonly source constants, and four replacements were taken in the frozen reserve order. There are 117 remaining qualified reserves and 219 source-level rejections. No classifier outputs or scores determined these replacements. Rejected records, their token counts and the provisional input chain are retained privately in the release. `private/selection_policy.json`, `private/candidates.json`, and `private/source_selection.json` preserve the rules, decisions and reserve order. `private/accepted_pairs.json` lists the final members, repairs, source proofs and sanitized diffs.

Original bodies and capacities are preserved; benchmark wrappers are replaced by an equivalent common standalone harness, neutral names and standard printing calls. Exact upstream bytes, including original line endings and attribution, are retained privately. These are curated standalone adaptations, not the original full Juliet harness executions. Fixed programs passed native execution at every optimization and separate O0 AddressSanitizer checks. Vulnerable programs may exit normally or crash; neither outcome determines truth. Instrumented ELFs never enter Ghidra extraction.

The final scope is local target setup and a numerically established write extent inside a complete function record fitting the frozen model context without truncation. The explicit exception is unrecoverable stack-object capacity, retained as the central research difficulty. Interprocedural allocation/write reconstruction and required source contents omitted from the public record are outside this corpus. The readonly-input check found four optimized wide-string pairs with this missing-evidence problem; each whole pair was replaced without changing optimization scope or source bodies. Local stack cases remain eligible when exact object capacity is absent from the public record; `capacity_visibility` distinguishes this recovery difficulty from missing function context. The deterministic selection chose alloca-based stack cases. The common one-helper harness, selected template families and related mechanisms limit population generalization. Conditions and generations are repeated measurements, not independent programs.

Every otherwise valid length exclusion would be recorded with its tokens and failed conditions and would reject the whole pair. There were none. This remains a context-compatible corpus by design. Token counts use the frozen prompt, chat template, tokenizer and special-token options; prompt + 4096 generation allowance + 128 reserve fits 8192. The tokenizer server was stopped after checks. Only `/props`, `/apply-template` and `/tokenize` were used.

## Truth and oracle semantics

`source_ground_truth` describes the source-defined object bounds. `binary_manifestation` separately records present, transformed, relocated, eliminated or unresolved effects. The private JSONL oracle records provenance, reachable instances, selected context, instruction-aligned disjoint evidence ranges and kind-specific canonical addresses. Heap request sizes and constant copy-length arguments are checked against machine code; lowered store intervals are independently merged. Library semantics and certified initialized inputs establish string-copy extents. Loop counter bounds or pointer limits, initial values, strides, write widths and backedges are checked against the disassembly and retained for review.

Elimination requires a positive absence proof over reachable corresponding contexts; a missing call or missing DWARF line is insufficient. Secondary emitted instances and their reachability remain recorded. Eliminated targets have no selected analysis context or canonical address and produce no fake `main` record. Unresolved mappings are technical failures. Valid retained/stripped recovery differences are allowed when the same target and required local evidence remain covered.

Later primary scoring uses eligible surviving source-defined target effects and `target_effect_ground_truth`. Source-defined object/requested-allocation bounds supply the bounds labels; surviving instruction sequences supply the write effects. It addresses target-object bounds, not whole-program safety or exploitability. The secondary source-origin view retains the complete 320-row matrix and reports the 104 non-analyzable eliminated rows separately. They are never ordinary false negatives, true negatives or model abstentions. The v2 private experiment binds the full matrix; its blinded input manifest exports only eligible records.

`private/input_equivalence.json` records eight identical projected-input groups with conflicting source-defined target labels, all within the explicitly retained latent-stack-capacity stratum. Compiler lowering has erased the distinguishing source bounds from those records. They remain in the dataset without filtering. Correct uncertainty is meaningful here; these labels must not be presented as distinguishing pure executable-safety facts encoded in the record. This is an input-information limitation, not evidence of an analyzer reasoning error.

## Reproduce and audit

Run from the repository root. The existing no-argument pilot commands retain their original behavior. Fresh dataset construction uses:

```bash
python3 -m evaluation.corpus_selection
bash build.sh --root datasets/final-v1
python3 -m evaluation.oracle_v2 draft --root datasets/final-v1
bash ghidra/run_headless.sh --root datasets/final-v1
python3 evaluation/check_oracle_mapping.py --dataset-root datasets/final-v1 --records
python3 evaluation/check_ghidra_extraction.py --dataset-root datasets/final-v1
```

The committed dataset is immutable. Rebuilding its ELFs may change build-identification bytes; use the release to recover the exact frozen artifacts. Selection inventory is idempotent and verifies existing sources instead of silently reselecting them. For a new dataset, use a separate root and identity, and reproduce the source-selection and four-pair scope checkpoint before full processing.

Private static-contract results under `private/validation/` were validated without computing accuracy. The final blinded records and method contracts can be checked offline:

```bash
python3 -m unittest discover -s llm_analysis/tests -v
python3 -m unittest discover -s evaluation/tests -v
python3 -m evaluation.freeze_corpus --check
```

`private/corpus-freeze.json` binds sources, candidate history, artifacts, oracle, extraction evidence and pipeline versions. `private/inputs-freeze.json` additionally binds `evaluation/experiments/final.json` and its hash-named blinded records. `release.json` identifies `datasets/releases/final-v1.tar.gz` and its checksum. The compressed release restores ignored binaries, reserve bodies, recovery dumps and process logs into repository-relative locations. Restore it with `tar -xzf datasets/releases/final-v1.tar.gz -C <repository-root>`, then run the offline checks. Restore into a clean checkout or scratch copy; do not overwrite modified files.

## Later inference

The selected method ID remains `6a18617e0ef4b1985060a76db93755018bc1e99190f0d652ca6d51dff78c1c1d`. No prompt, schema, parser, model, seed, sampling parameter, voting rule or static classification rule changed. The final private manifest is `evaluation/experiments/final.json`; the existing runner accepts only the corresponding blinded manifest and verifies the selected method.

```bash
python3 -m llm_analysis.runtime serve
LLM_CAMPAIGN=$(python3 -m llm_analysis.run_llm prepare --input-manifest evaluation/experiments/final.inputs/manifest.json)
python3 -m llm_analysis.run_llm run --campaign "$LLM_CAMPAIGN"
python3 evaluation/check_llm_predictions.py --campaign "$LLM_CAMPAIGN" --experiment evaluation/experiments/final.json
```

Those inference commands are a handoff, not work performed in this release. Later analysis must distinguish structural eligibility, model abstentions, operational failures and compiler elimination, and use source-pair clustering for uncertainty estimates.
