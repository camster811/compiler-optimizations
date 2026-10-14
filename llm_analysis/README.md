# Local LLM analyzer

The local DeepSeek-R1-Distill-Qwen-14B Q5_K_M analyzer consumes public Ghidra evidence. Private experiment construction and scoring stay in `evaluation/`. Corpus expansion is separate from the two-pair development pilot.

## Methods and preservation

v1.0 used prompt-only JSON and record-dependent seeds. Its 48 raw responses, original exports, original receipt, and evidence archive remain unchanged. Campaign `bc11e2466eab2b3d2dfc658f52fd4e340d564d8b59de4aa4cabb59ec2603a345` has versioned copies under `frozen/<campaign_id>/` and `results/<campaign_id>/`, including the exact archived implementation used for historical replay. The original unversioned v1.0 files remain compatibility artifacts.

v1.1 adds llama.cpp `response_format` JSON Schema enforcement and shared repetition seeds. The generation schema expresses the existing classification/CWE/uncertainty rules as three object alternatives compatible with llama.cpp's grammar converter. Evidence address choices come only from the public instruction listing. The unchanged strict parser still checks final content, including duplicate keys, exact fields, confidence, and address membership. No client code strips fences or repairs responses.

The pinned backend's schema-aware chat parser permits reasoning before the constrained final JSON, and separates `reasoning_content` from `content`. Any chat-format wrappers handled by the backend are part of the recorded v1.1 interface. Exact HTTP responses are retained. Historical responses are audited with their historical implementation, not reinterpreted by v1.1.

The prompt, model, quantization, context (8192), generated-token budget (4096), temperature (0.6), top-p (0.95), full layer offload, FP16 KV cache, Flash Attention, and single-slot execution remain unchanged. Only top-p and temperature samplers are active. The same three seeds apply to every record: 1406227738, 1995257104, and 1887179923. They are derived from SHA-256 of `generation:<master seed>:<repetition>` with master seed 20261014, using the first 32 bits masked to 31 bits. Execution-order randomization still uses the master seed. Common seeds improve experimental pairing; they do not guarantee identical GPU results or identical token trajectories across different prompts.

Two matching valid classifications decide the aggregate. A vulnerable result also needs two matching CWE votes. Otherwise the result is uncertain. Failures, model abstentions, and disagreements remain distinct; confidence is descriptive and does not determine the vote. The static baseline ignores names and decompilation; the LLM uses all public evidence, so that difference must be documented in comparisons.

## Private experiment manifests and blinded inputs

Freeze the expected observation matrix before inference. The private manifest contains dataset identity, development/final status, expected cases and conditions, source-pair IDs, truth/CWE labels, record paths, and record hashes. A separate SHA-256 file detects manifest drift. Each pair must contain exactly two unique source cases with the same CWE: one vulnerable and one fixed (normalized to `not_vulnerable`). Optimization and symbol variants do not count as additional pair members. Validation runs before publishing the manifest, hash, or blinded inputs, and again whenever the manifest is loaded. The checker rejects duplicate or missing observations, inconsistent labels, and record-content drift. It has no fixed observation count or build-manifest location.

For the pilot, the checked-in frozen matrix is `evaluation/experiments/pilot.json`. To create another experiment, supply the exact build manifest and every condition directory:

```bash
python3 evaluation/prepare_llm_experiment.py --build-manifest build/artifacts/private/build_manifest.tsv --condition retained=ghidra/output/retained --condition stripped=ghidra/output/stripped --output evaluation/experiments/new-development.json --dataset-id new-development --data-split development
```

Use `--data-split final` when freezing the final corpus. The private exporter writes a separate `<name>.inputs/manifest.json` and hash-named copies of public records. Only that blinded manifest is passed to the runner. It contains record paths, an opaque experiment hash, and the data-split flag; no truth labels or condition matrix. Neither metadata nor filenames are sent to the model. Each request contains one fresh user message with `sample_id` removed.

Development/final status is campaign metadata, not a method property. Campaign identity binds method hash, input-set hash, and metadata, so changing the split or experiment binding cannot silently reuse an old campaign. Byte-identical records share predictions within a campaign; evaluation maps them back to all expected observations.

## Run, resume, and audit

Run from the repository root with Python and `jsonschema==4.19.2`. Configure local paths before preparing the development method; preserve the selected method unchanged for final inference.

```bash
python3 -m unittest discover -s llm_analysis/tests -v
python3 -m llm_analysis.runtime inventory
```

Start the dedicated server in another terminal:

```bash
python3 -m llm_analysis.runtime serve
```

Prepare and run the 48-request pilot:

```bash
LLM_CAMPAIGN=$(python3 -m llm_analysis.run_llm prepare --input-manifest evaluation/experiments/pilot.inputs/manifest.json)
python3 -m llm_analysis.run_llm run --campaign "$LLM_CAMPAIGN"
python3 evaluation/check_llm_predictions.py --campaign "$LLM_CAMPAIGN" --experiment evaluation/experiments/pilot.json
```

Preflight verifies the model, context, slot count, and effective template. Fully rendered prompt tokens + 4096 generated tokens + 128 reserve must fit; records are never truncated. Startup logs show actual offload and buffer allocations; GPU usage is sampled every five seconds.

The connection timeout is 10 seconds and the total request deadline 600 seconds. Only transport failure, timeout, interrupted attempts, HTTP 429, and HTTP 500/502/503/504 can consume the single retry, after five seconds. The payload and seed are unchanged. Each attempt is saved atomically before parsing. Output failures are never retried. Interrupted bytes remain preserved. The server must be idle before another request begins; a file lock excludes concurrent writers.

Reissue `run` to resume. Completed runs, including failures, are reused; a fully completed campaign needs no server and generates zero new requests. Replaying raw responses and recomputing exports requires no inference. For current code:

```bash
python3 -m llm_analysis.run_llm replay --campaign "$LLM_CAMPAIGN"
```

The private checker automatically uses the exact frozen implementation when auditing an older method. For v1.0, supply its campaign path and the pilot private manifest. The new audit report includes abstention-derived TN/FN counts without modifying the original report. The v1.0 counts are five TNs and five FNs from abstention.

## Versioned freeze and final-method gate

Stop the dedicated server after inference, then freeze the development campaign and select it only if the interface gate passes:

```bash
python3 evaluation/check_llm_predictions.py --campaign "$LLM_CAMPAIGN" --experiment evaluation/experiments/pilot.json --freeze --select-final
```

A freeze always preserves a campaign under `frozen/<campaign_id>/method.json` and `results/<campaign_id>/{predictions.json,run_results.json,report.json}`. It never overwrites a different campaign. The final-method pointer `frozen/current.json` is updated only by explicit selection of a constrained-output development method with at least 98% schema-valid responses and zero JSON/schema failures. For 48 runs this requires 48 valid responses. Prediction accuracy is not a selection criterion. If the gate fails, the development evidence remains frozen but is not selected for final-corpus evaluation.

Final-data preparation requires an unchanged selected method and a frozen experiment binding. Private evaluation checks that the campaign's split, record set, and experiment digest match. The report retains three-way metrics, forced binary alerts, failure rates, CWE/optimization/condition/ground-truth breakdowns, aggregate symbol comparisons, and source-pair identifiers. Binary metrics explicitly separate `TN_from_abstention`, `FN_from_abstention`, `TN_from_not_vulnerable`, and `FN_from_not_vulnerable`. Repeated conditions and generations are related measurements, not independent samples.

`paired_run_symbol_comparisons` matches retained/stripped outcomes by source case, optimization, repetition, and equal seed. It preserves both run IDs, record hashes, statuses, classifications, CWEs, confidence values, agreement, and confidence differences. A valid `uncertain` prediction is a model abstention; a failed run is unavailable, with null prediction/agreement fields. The summary counts valid agreements/disagreements and unavailable pairs. Byte-identical records are explicitly marked as shared evidence. Missing or duplicate repetitions and unequal seeds are rejected; conditions without a counterpart are skipped. Historical methods with record-dependent seeds have no paired run comparisons.

The selected v1.1 development campaign and qualitative findings are documented in [its pilot summary](results/d5982d9920179520c42798c707708a54205300024fa8d653e64fb179c9491d73/pilot_summary.md). All 48 responses passed the interface gate. Its 62.5% binary accuracy and 50% false-positive rate remain pilot measurements from two source pairs.

## Durable evidence

Each campaign has exact requests/responses, attempt metadata, parsed results, aggregate predictions, and a checksum manifest. A compressed release archive also preserves method code, private evaluation tools, the private experiment snapshot, scored report, server logs, and GPU telemetry. Named `.tar.gz` files under `output/releases/` are committed through a narrow ignore exception; transient campaigns, process logs, and model weights stay excluded. The frozen receipt records archive and result hashes.

After cloning, restore a committed archive into a scratch directory with `tar -xzf <archive> -C <scratch-directory>`. The campaign is the `<scratch-directory>/<campaign_id>` directory. Pass that path and the original checked-in private experiment manifest to `check_llm_predictions.py` for an offline evidence audit; neither a model server nor the model weights are needed. The `method/`, `runtime/`, and `evaluation/` archive directories preserve supporting snapshots. The exact frozen method source also remains in the repository under `frozen/<campaign_id>/method_source/`.

The existing model matches [bartowski's pinned GGUF artifact](https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-14B-GGUF/commit/f311014f9aac74f301f01b822a772b9b6cbe1920); `frozen/model_provenance.json` records its immutable download URL. The original download route remains unknown. Before final-corpus analysis, freeze the corpus independently and do not tune this method using final outcomes.
