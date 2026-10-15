# Phase H analysis plan (final-v1)

The original analysis plan was committed as `7856cce` before aggregate metrics were computed.
This version also contains pre-analysis amendments documented before aggregate metrics were computed;
those amendments are committed with the implementation and results, not as part of the original
preregistration. `evaluation/run_final_analysis.py` implements this version. Anything changed after results
are visible must appear as a labelled deviation in the generated report, never silently.

## Pre-analysis amendments

Pre-analysis amendments documented before aggregate metrics were computed:

1. Use R/lme4 rather than a custom Python GLMM, retaining maximum likelihood and 30 adaptive quadrature
   points. Pin the runtime/package environment. Use a fixed BOBYQA optimizer (`maxfun=200000`,
   `rhoend=1e-9`) with no result-driven tuning. The gradient diagnostic is maximum absolute Hessian-scaled
   gradient, threshold 1e-3; at a variance boundary use the fixed-effect block for this diagnostic.
2. Remove Firth fitting. The fixed ladder is full GLMM, main-effects GLMM, then descriptive pair-cluster
   contrasts with confidence intervals and no model of record. Both GLMM specifications are evaluated.

The runner records this plan's hash, the original preregistration, and these amendments. Missing dependencies,
failed separation checks, or broken execution stop the pipeline; they are not statistical fallbacks.
Operational response summaries use 528 distinct requests at the overall level only; factor subgroups use
648 observation-weighted rows and are labelled separately. Confidence/correctness summaries retain observation weighting because one response
may map to different truths. Distinct-record stability (176 records) is separate from observation stability
(216 observations). All intervals continue to resample the 20 whole source pairs.

## Post-analysis reporting correction

Review found that distinct-request factor subgroups inherited a representative observation's factor values
even when a request was shared across levels (notably O2/O3). Those subgroups are removed; distinct-request
status summaries are overall only, and observation-weighted subgroup summaries are retained. This is a
reporting correction after results were visible, not a change to scoring, intervals, or model selection.
F3 also now verifies the preserved campaign server-log slice rather than an ignored live server log;
its refreshed acceptance receipt and Phase G manifest bind the same frozen prediction tables.

## What had been seen before this plan

Operational facts only: LLM run statuses (524 valid, 4 `schema_invalid`, no timeouts or transport errors), the
static prediction mix by rule (158 of 176 distinct records `uncertain`) and two example rows. No accuracy,
alert, error-rate or per-factor correctness figure had been computed. The frozen analyzers, experiment matrix
and Phase G tables are not modified in Phase H.

## Data and unit of analysis

* Inputs: `results/final-v1/private/condition_comparison.jsonl` (432 rows = 216 eligible observations x
  {static, llm_majority}) and `llm_runs.jsonl` (648 rows = 216 x 3 repetitions). The analysis verifies their
  SHA-256 against `tables_manifest.json`, then re-derives every classification/CWE from the frozen
  `static/predictions.json` and the campaign `predictions.json` / `run_results.json` by record hash. Any
  mismatch aborts the run.
* The 104 proven-eliminated observations are not scored and are never TN, FN or abstentions.
* Truth is `target_effect_ground_truth`; it equals `source_ground_truth` on all eligible rows, so the
  source-origin view is numerically identical and is not tabulated separately.
* **Clustering unit: `pair_id`** (20 source-program pairs, 10 CWE-121 and 10 CWE-122). Observations are
  optimization x symbol variants of two source cases; 40 records are shared by two observations; repetitions are
  three measurements of one observation. None of these are independent samples.

## Metric definitions

**Three-way view (H1).** `correct` = truth vulnerable and predicted `vulnerable` with the exact CWE, or truth
fixed and predicted `not_vulnerable`. `incorrect` = any other `vulnerable`/`not_vulnerable` prediction (a wrong
CWE on a vulnerable case is incorrect and counted separately as `wrong_cwe`). `abstain` = valid `uncertain`.
`unavailable` = no valid response (LLM runs only). coverage = (correct+incorrect)/N; abstention rate =
abstain/N; selective accuracy = correct/(correct+incorrect), undefined if nothing is decided. Selective accuracy
is always printed with N, correct, incorrect, abstain, unavailable, coverage and abstention rate (one function
builds all of them).

**Forced binary alert (H2).** alert = `vulnerable`; `not_vulnerable`, `uncertain` and `unavailable` = no alert.
TP/FP/TN/FN as usual; TN and FN are split into `from_not_vulnerable`, `from_abstention`, `from_failure`.
accuracy = (TP+TN)/N; recall = TP/(TP+FN); precision = TP/(TP+FP); F1 = 2TP/(2TP+FP+FN); FPR = FP/(FP+TN);
FNR = FN/(FN+TP); balanced accuracy = (recall + TN/(TN+FP))/2. The CWE is not checked here; the share of
true-positive alerts with the exact CWE is reported separately. An abstention is not a confident safe decision.

**Primary model outcome `Correct` (fixed now).** 1 iff `vulnerable` on a vulnerable observation or
`not_vulnerable` on a fixed one. 0 for an incorrect alert/no-alert, an abstention or an unavailable result. CWE
not required. Abstention on a fixed case therefore scores 0 (unlike the forced binary view). Coverage is always
reported beside it. **Sensitivity outcome `Correct_forced`**: 1 iff the forced alert equals truth (abstention on
a fixed case scores 1). It never replaces the primary result.

**Additional strata (pre-existing in the experiment, descriptive only):** `capacity_visibility`,
`binary_manifestation`, `input_label_conflict_group`. Required factors: method, optimization, symbol condition,
CWE, ground truth.

## Intervals (H5)

Percentile cluster bootstrap, 95%: resample the 20 pairs with replacement, 10,000 replicates, one fixed weight
matrix from `numpy.random.default_rng(20261014)` reused for every metric and subgroup (metrics are recomputed
from weighted per-pair counts). A replicate with a zero denominator is dropped for that ratio; if more than 5%
are dropped the interval is "not estimable". Method comparison = paired difference (llm_majority - static) on
the same observations with the same weights. With 20 clusters percentile intervals are approximate and can be too
narrow near 0 or 1. A zero-event outcome (e.g. timeouts) is reported with a one-sided 95% Clopper-Pearson upper
bound on the proportion of *pairs* that could contain an event. Differences whose interval contains 0, or whose
cells contain few pairs, are not interpreted as differences. No multiplicity correction; nothing is
confirmatory.

## Primary model and fixed fallback ladder (H4)

Data: the 432 condition rows. `Correct ~ Optimization + Stripped + Method + CWE + GroundTruthLabel +
Optimization:Method + Optimization:Stripped + Method:Stripped + (1 | pair_id)`, logit link. Treatment coding:
Optimization reference O0; Stripped 1 = stripped; Method reference static; CWE reference CWE-121; GroundTruth
reference fixed. No continuous covariates.

Rung 1 (**primary**): random-intercept logistic GLMM, maximum likelihood with 30-node adaptive Gauss-Hermite
quadrature using R/lme4. A rung is **rejected** if any of these holds: the fixed-effect design is rank deficient,
completely or
quasi-completely separated (linear-programming check on the design with the outcome); the optimizer does not
report convergence or the maximum absolute scaled gradient exceeds 1e-3; the Hessian is not positive definite; any |coefficient| >
10 or any standard error is non-finite or > 10. A random-intercept variance at the boundary (< 1e-3) is
**not** a failure; it is reported as such.

If rung 1 is rejected, the **model of record** is the first accepted of, in this fixed order and decided only by
the rejection rules above, never by estimates or p-values:

* Rung 2: the same GLMM with main effects only (the three interactions dropped).
* Rung 3: no model; only the descriptive pair-cluster contrasts below.

Both GLMM rungs are evaluated and shown (rejected ones with their reason, labelled "diagnostic, not of record").
Wald tests use the fitted covariance; with 20 clusters they are anti-conservative and are reported as
approximate. Joint Wald tests are given for each interaction. The same ladder is run on `Correct_forced` as a
sensitivity analysis. **Always shown, whatever the model does:** descriptive pair-bootstrap contrasts of the
primary `Correct` rate (LLM - static; each factor level vs reference), labelled descriptive.
Factor contrasts are unadjusted marginal eligible-case rate differences; eligible-case composition can vary
across levels, and CWE is a between-pair factor. They are not causal or adjusted model effects.

## LLM-specific reporting (H3)

Response validity and each failure status with counts and pair-level one-sided bounds; latency and token
summaries; agreement across repetitions (all-three-valid-and-identical rate, mean pairwise agreement on
classification, the distribution of the number of correct runs out of 3); vote patterns as sorted vote triples,
overall and by truth; confidence (valid runs; and median confidence for the majority result) summarised by run
outcome `correct`/`incorrect`/`abstain` with n, mean, median, quartiles and range. **High confidence = 0.8 or
more** (the repo's earlier threshold, fixed now). High-confidence false positive = `vulnerable` on a fixed case;
high-confidence false negative = `not_vulnerable` on a vulnerable case (abstentions are listed separately, not
as FNs of this kind). Retained-vs-stripped agreement of the prediction is reported for both methods.

## Outputs

`results/final-v1/analysis/`: `tables/*.csv`, `figures/*.png`, `report.md`, `analysis.json` with input hashes and
the deviations list. `python evaluation/run_final_analysis.py` regenerates all of it and exits nonzero if the
inputs do not match the frozen files. Every table and figure states its exact N (rows) and number of pairs.
`--check` regenerates into a temporary directory and compares every output byte. Undefined ratios are null
with a reason; confidence intervals record the number of usable bootstrap replicates. No timestamps or
temporary paths enter generated artifacts. Near-zero/one bootstrap intervals are explicitly labelled as
potentially too narrow. No population-representativeness or confirmatory significance claims are made.

Backend documentation: https://lme4.github.io/lme4/reference/glmer.html and
https://lme4.github.io/lme4/reference/convergence.html.
