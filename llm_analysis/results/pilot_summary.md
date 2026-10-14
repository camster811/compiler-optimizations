# Phase B/C development-pilot result

Completed on 2026-10-14. The analyzer method is frozen in `../frozen/method.json`; campaign `bc11e2466eab2b3d2dfc658f52fd4e340d564d8b59de4aa4cabb59ec2603a345` preserves the original evidence. The full private observation table and breakdowns are in `../../evaluation/llm_pilot_report.json`.

## Execution and acceptance

- All 48 scheduled repetitions completed, with one HTTP attempt each. No transport failures, timeouts, context overflows, or generation-limit failures occurred.
- All sixteen prompts fit the 8192-token context: 958–1263 rendered tokens, plus the fixed 4096-token generation budget and 128-token reserve.
- Twenty responses were schema-valid (41.7%). Twenty-seven failed JSON parsing: 26 were markdown-fenced and one had another non-JSON shape. One response omitted the required `uncertainty_reason` key. None were repaired or regenerated.
- Offline replay and the private sixteen-observation join passed. With the server stopped, a completed-campaign resume reported zero requests for inference.
- Nineteen implementation/evaluation tests passed. Existing oracle, Ghidra extraction, and static-prediction acceptance gates also passed.
- Method files, runtime artifacts, model weights, requests, raw responses, and exports are hashed. The compressed release contains raw campaign evidence, exact method code, the private checker, server logs, and GPU telemetry snapshots. Its hash is recorded in the freeze receipt.

## Development-set comparison

| Metric | Static baseline | LLM aggregate |
|---|---:|---:|
| Correct decisions | 10 | 4 |
| Incorrect decisions | 0 | 2 |
| Abstentions | 6 | 10 |
| Coverage | 62.5% | 37.5% |
| Selective accuracy | 100% | 66.7% |
| Binary TP / TN / FP / FN | 6 / 8 / 0 / 2 | 2 / 7 / 1 / 6 |
| Binary-alert accuracy | 87.5% | 56.25% |

Binary metrics treat every uncertain aggregate as no alert. The ten LLM abstentions were caused by insufficient matching valid votes; they must not be interpreted as ten successful model abstentions. Thirteen observations had at least one failed repetition. No record had three valid matching classifications. Eight valid individual runs made incorrect predictions with confidence at least 0.8; this threshold is descriptive and does not affect voting.

The aggregate false negative was the retained optimized vulnerable-stack observation. The aggregate false positive was the stripped optimized fixed-stack observation. These cases and the formatting failures are preserved for qualitative inspection. Sampling instability and invalid-output rates prevent attributing retained/stripped prediction differences solely to symbol names.

The LLM receives decompilation and inferred variables in addition to instructions and names, while the static baseline ignores those fields. These are development measurements from two source pairs under repeated conditions, not independent observations or held-out estimates.

## Measured resources

The dedicated RTX 5070 Ti server confirmed 49/49 layers offloaded, a 9505.88 MiB CUDA model buffer, a 1536 MiB FP16 KV buffer, and a 32.25 MiB CUDA compute buffer. During the pilot, 151 five-second GPU samples showed peak total usage of 12958 MiB and minimum reported free memory of 3038 MiB; those measurements include desktop GPU usage.

The 48 HTTP attempts took 761.48 seconds in total (approximately 12.7 minutes), with a median of 12.69 seconds. The server was stopped after completion. Exact model content was verified against a pinned published GGUF artifact in `../frozen/model_provenance.json`; no weights or inference settings changed during the pilot.

The implementation meets the Phase B/C acceptance contract. The frozen method's poor JSON adherence and modest decision coverage remain substantive limitations for the research comparison. Any subsequent method revision requires a separately identified development campaign and must occur before evaluating the final corpus.
