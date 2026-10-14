# Phase B/C v1.1 development-pilot result

Campaign `d5982d9920179520c42798c707708a54205300024fa8d653e64fb179c9491d73` completed on 2026-10-14. The frozen receipt is [method.json](../../frozen/d5982d9920179520c42798c707708a54205300024fa8d653e64fb179c9491d73/method.json), and [current.json](../../frozen/current.json) selects this method for the independently frozen final corpus. The complete scored observation table and comparisons are in [report.json](report.json); exact parsed responses and run IDs are in [run_results.json](run_results.json).

v1.1 corrects the interface with llama.cpp JSON Schema enforcement and three shared repetition seeds. The strict parser, prompt, model, quantization, context, sampling parameters, and vote rule remain fixed. The v1.0 campaign, original report, receipt, and raw evidence remain unchanged. The interface correction was completed before final-corpus evaluation. Prediction accuracy did not determine method selection.

## Acceptance and preservation

All 48 scheduled requests completed with one attempt each and schema-valid final content. There were no transport, parsing, schema, context, or generation-limit failures. All 16 prompts fit: 958–1263 rendered tokens plus 4096 generated tokens and a 128-token reserve within context 8192. The 98% schema-adherence gate passed at 100%. Ten of 16 records had unanimous classifications; complete formatting compliance does not imply stable or correct reasoning.

The dedicated server's recorded PID 473223 was absent before freezing. Its saved log, GPU telemetry, and process metadata were captured with the release; the log and telemetry span multiple development sessions. Offline replay, archive restoration and checksum verification passed. Resuming the completed campaign generated zero new inference requests. All 27 implementation/evaluation tests passed, including malformed-pair rejection before publication, ground-truth metric reconciliation, and shared-seed pairing with failures and shared records. Existing oracle, Ghidra-extraction and static-baseline acceptance checks also passed. No saved generations were changed.

The versioned receipt records the archive and result hashes. The [206,157-byte compressed archive](../../output/releases/d5982d9920179520c42798c707708a54205300024fa8d653e64fb179c9491d73.tar.gz) has SHA-256 `fd7d0498df6a8bd31121e3592199c37d8608cb774305b8e6120a4d63e58b4a0d`. It and the exact method/evaluator source snapshot under the versioned frozen directory are committed alongside the reports. The private pilot manifest and its original hash were preserved.

## Aggregate results

| Metric | v1.1 LLM |
|---|---:|
| Correct / incorrect / abstain | 9 / 6 / 1 |
| Coverage | 93.75% |
| Selective accuracy | 60% |
| Binary TP / TN / FP / FN | 6 / 4 / 4 / 2 |
| Binary accuracy | 62.5% |
| Precision / recall | 60% / 75% |
| False-positive / false-negative rate | 50% / 25% |
| TN / FN from abstention | 1 / 0 |
| TN / FN from explicit `not_vulnerable` | 3 / 2 |

The forced binary view treats uncertainty as no alert. The fixed-case binary accuracy includes one abstention-derived true negative, whereas the three-way view counts it as an abstention. The ground-truth breakdown exposes four false positives among eight fixed observations.

| Factor | Observations | Binary accuracy |
|---|---:|---:|
| O0 | 8 | 62.5% |
| O2 | 8 | 62.5% |
| Retained symbols | 8 | 75% |
| Stripped symbols | 8 | 50% |
| CWE-121 | 8 | 50% |
| CWE-122 | 8 | 75% |
| Vulnerable ground truth | 8 | 75% |
| Fixed ground truth (`not_vulnerable`) | 8 | 50% |

The 24 retained/stripped run pairs all had matching repetition seeds and valid responses: 12 agreed on classification and CWE, and 12 disagreed. No pair reused a byte-identical record and none was unavailable. These are repeated measurements of two source pairs, not 24 independent cases. Common seeds improve pairing but do not guarantee identical token trajectories across prompts or reproducibility of GPU sampling.

The v1.0 O0/O2 disparity disappeared after interface and seed correction. It should not be reported as an optimization finding. The retained/stripped difference is a pilot observation with eight observations per condition, not evidence of a general stripping effect. The LLM receives decompilation and inferred locals in addition to instructions; the static baseline ignores those fields, so the two analyzers use different evidence.

## Qualitative mechanisms

For stripped vulnerable stack `sample_0001` at O2, runs `dcf063f899f8f768f1ead4d5e6d17edd1b52afaacc882976c9d63cc2253a3941-r1`, `-r2`, and `-r3` all returned `not_vulnerable`. Their explanations used either Ghidra's inferred 18-byte `local_12` or the 24-byte frame allocated at `0x401140` as destination capacity. The source object is 10 bytes. The stores at `0x401153` and `0x401158` have merged extent 11 bytes, so they overflow that source object by one byte. Several responses also miscounted overlapping store widths, but the decisive error was substituting a frame or inferred local for the true source-object boundary.

For stripped fixed stack `sample_0002` at O2, runs `39b90320b436ad044ab60695fddbda8a11922bc40a42b6f93c50fccba7d7fd52-r1`, `-r2`, and `-r3` all returned vulnerable CWE-121. They treated the inferred seven-byte `local_13` as authoritative, especially for the eight-byte store at `0x401050`. The true source object is 11 bytes and the merged stores fit. The prompt's warning about inferred locals did not prevent this false positive. Together, these cases support the source-object-boundary mechanism hypothesis.

For fixed heap `sample_0004` at O0, the retained runs `c39286c3e4b66b6dc53ae383012990de194ed5e8e51392fcaa42db25fbf7d6c9-r1`, `-r2`, and `-r3` all reported vulnerabilities. Allocation at `0x401153` is 11 bytes. Stores at `0x401167` and `0x401170` cover `[ptr+0, ptr+8)` and `[ptr+7, ptr+11)`: the merged extent is 11 bytes. The retained explanations added eight and four to claim 12 bytes. Run 1 also mislabeled this heap allocation CWE-121. The corresponding stripped runs `a4a439216b2cd257f9f60b7e6fecd0e90b4fd42f46c0bd6135b93b0e21ef9e4d-r1`, `-r2`, and `-r3` correctly reported no overflow and an 11-byte extent. The instructions express the same write intervals, while their public representations differ. This is qualitative evidence of representation-sensitive reasoning under shared seeds; it does not identify symbol names alone as the cause.

The O2 stripped fixed-heap labels were also all correct, but some explanations inconsistently claimed 12 bytes within an 11-byte allocation. Correct classification alone is not evidence of correct interval reasoning. O0 provides the clearer overlap comparison.

Heap cases had higher pilot binary accuracy than stack cases, consistent with the hypothesis that explicit allocation/write relationships are easier than source stack-object recovery. This small development set cannot establish general effects or calibrated confidence. Final-corpus inference must use the selected method without tuning it to final outcomes.
