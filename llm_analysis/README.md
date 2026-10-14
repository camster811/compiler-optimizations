# Local LLM analyzer

Phase B/C adds a local DeepSeek-R1-Distill-Qwen-14B Q5_K_M analyzer to the existing pre-LLM pilot. The analyzer sees public Ghidra evidence only. The evaluator reads private ground truth separately. This is a development experiment, not held-out performance evidence.

The completed 48-run pilot and acceptance results are documented in [results/pilot_summary.md](results/pilot_summary.md). Its raw evidence archive and exact method are identified by [frozen/method.json](frozen/method.json).

## Frozen contract

`config.json`, `prompt.md`, `chat_template.jinja`, `output_schema.json`, and the Python modules identify the method. Their hashes, the Ghidra input-schema hash, dependency specification, backend artifacts, and input hashes identify each campaign. Executable/model locations can be configured before preparing a campaign. Changing a method file creates a different campaign; execution refuses drift within an existing campaign.

Inputs include instructions, function boundaries and names, calls, tail jumps, imports, constants, inferred stack variables, and decompilation. `sample_id` is removed from the prompt. Filenames, condition labels, source, oracle evidence, and static predictions are excluded. The complete input is rendered deterministically and never truncated. Unlike the static baseline, this analyzer uses names and decompilation; interpretation of their effects must account for that difference.

One fresh user message is sent per request, with no previous messages, tools, or system prompt. The bundled Distill-Qwen chat template is versioned locally to support llama.cpp's automatic reasoning parser. Reasoning is retained in the exact raw HTTP response but is never parsed as prediction JSON. An explicit model end-token stop prevents the terminator from being included in final content. The strict parser rejects fenced or repaired JSON. Structural validation and instruction-address membership do not establish that an observation is factually correct.

The default configuration is 8192 context tokens, 4096 total generated tokens, temperature 0.6, top-p 0.95, only the top-p/temperature samplers, full GPU offload, FP16 KV cache, Flash Attention, and one server slot. CPU and prompt-processing threads are fixed at 12. Reasoning has no separate cap. Three repetition seeds are derived from SHA-256 of `generation:<master seed>:<record hash>:<repetition>`, using the first 32 bits masked to 31 bits. The master seed is 20261014; the same seed shuffles the sorted record/repetition schedule. Seeded requests support auditing, not guaranteed bit-for-bit GPU reproduction.

Two matching valid classifications decide the aggregate. A vulnerable result additionally requires two agreeing CWE votes. Otherwise the aggregate is uncertain. Model abstentions, CWE disagreements, operational failures, and insufficient votes remain distinct. Median confidence across valid runs is descriptive; it never controls classification. Unanimity requires three valid matching classifications. CWE disagreement is checked separately.

## Execution

Run from the repository root. Python 3 with `jsonschema==4.19.2` is required. The existing WSL CUDA backend and GGUF are reused; no modification to the llama.cpp installation is needed.

```bash
python3 -m unittest discover -s llm_analysis/tests -v
python3 -m llm_analysis.runtime inventory
```

Start the dedicated server in another terminal:

```bash
python3 -m llm_analysis.runtime serve
```

Prepare and execute the blinded pilot:

```bash
LLM_CAMPAIGN=$(python3 -m llm_analysis.run_llm prepare ghidra/output/retained ghidra/output/stripped)
python3 -m llm_analysis.run_llm preflight --campaign "$LLM_CAMPAIGN"
python3 -m llm_analysis.run_llm run --campaign "$LLM_CAMPAIGN"
python3 evaluation/check_llm_predictions.py --campaign "$LLM_CAMPAIGN" --report evaluation/llm_pilot_report.json
```

Preflight verifies the server's context, slot count, model, and effective template. It tokenizes the rendered prompts with special-token handling and requires prompt + 4096 generated tokens + 128 reserve to fit. The startup log confirms allocation/offload details; GPU memory samples are written every five seconds to `output/gpu_memory.jsonl`. Synthetic smoke campaigns should be executed before the project pilot and remain excluded from its scores.

The runner has a 10-second connection timeout and a 600-second overall request deadline. Only transport failure, timeout, interrupted attempts, HTTP 429, and HTTP 500/502/503/504 can consume the one retry, after a five-second delay. Both attempts are preserved and use the same seed/payload. The single slot must become idle before another request starts; if the server is unavailable or still working, execution stops and can be resumed. A file lock excludes concurrent writers.

Reissue `run` to resume. Terminal results, including failures, are never regenerated or overwritten. If an attempt was interrupted before its complete response metadata was committed, any saved bytes remain preserved and the attempt is marked interrupted. A completed campaign needs no server connection when resumed and issues zero new generation requests. All expected runs are then validated and the deterministic exports reconstructed. An interrupted campaign must retain its original method files to resume.

Offline validation and freezing:

```bash
python3 -m llm_analysis.run_llm replay --campaign "$LLM_CAMPAIGN"
python3 evaluation/check_llm_predictions.py --campaign "$LLM_CAMPAIGN" --freeze
```

`replay` uses saved responses only. The private checker verifies every raw-response/request hash, exact request construction, seed, repetition, retry eligibility, parse, aggregate, and join to sixteen pilot observations. It reports per-run reliability and condition-level three-way/binary metrics, by CWE, optimization, and symbol condition. A vulnerable alert with the wrong CWE is incorrect in the three-way view; the binary-alert view assesses alert presence. Operational failures remain visible and produce no alert if they prevent a majority.

## Evidence and release

Every campaign contains a manifest, hash-named original public records, preflight receipt, immutable request/attempt/result artifacts, per-run exports, aggregate predictions, and a SHA-256 manifest covering the evidence. Exact HTTP response bodies retain reasoning and final content. Campaign and server artifacts under `output/` are excluded from Git, but are preserved locally. The release archive also includes the exact method files and private checker used at freeze time, plus snapshots of available server logs and GPU telemetry. Stop the dedicated server after inference and before freezing to capture final diagnostics.

Freezing writes small reviewable exports to `results/`, the private scored report to `evaluation/llm_pilot_report.json`, and the complete method receipt to `frozen/method.json`. It also creates a deterministic compressed evidence archive in `output/releases/` and records its hash. Include that archive in the reproducibility release; small Git exports alone cannot reproduce the evidence audit. Freezing refuses to replace a different frozen method.

The original model download route was unknown when the campaign configuration was captured. Subsequent verification established that the local model's SHA-256 and size match [bartowski's pinned GGUF artifact](https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-14B-GGUF/commit/f311014f9aac74f301f01b822a772b9b6cbe1920). `frozen/model_provenance.json` supplies its immutable download URL. The inference configuration remains unchanged.

Existing oracle, extraction, and static-baseline acceptance checks remain required. No model, prompt, or parameter tuning on the final expanded corpus is permitted. A superseded interface-development campaign must be retained rather than repaired in place.
