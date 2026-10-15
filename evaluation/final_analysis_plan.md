# Phase H analysis plan (final-v1)

Written and committed **before** any correctness aggregate was computed. `evaluation/run_final_analysis.py`
implements this plan. Anything changed after results are visible must appear as a labelled deviation in the
generated report, never silently.

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

Rung 1 (**primary**): random-intercept logistic GLMM, maximum likelihood with 30-node Gauss-Hermite quadrature
(own implementation, `evaluation/glmm.py`, validated by simulation in `evaluation/tests/test_glmm.py`; no R/lme4
is available). A rung is **rejected** if any of these holds: the fixed-effect design is completely or
quasi-completely separated (linear-programming check on the design with the outcome); the optimizer does not
report convergence or the gradient norm exceeds 1e-3; the Hessian is not positive definite; any |coefficient| >
10 or any standard error is non-finite or > 10. A random-intercept variance at the boundary (< 1e-3) is
**not** a failure; it is reported as such.

If rung 1 is rejected, the **model of record** is the first accepted of, in this fixed order and decided only by
the rejection rules above, never by estimates or p-values:

* Rung 2: the same GLMM with main effects only (the three interactions dropped).
* Rung 3: Firth-penalised logistic regression with the full formula (handles separation, ignores the random
  intercept) with percentile CIs from a 2,000-replicate pair-cluster bootstrap; accepted if at least 95% of
  replicates fit.
* Rung 4: no model; only the descriptive pair-stratified contrasts below.

All of rungs 1-3 are fitted and shown (rejected ones with their reason, labelled "diagnostic, not of record").
Wald tests use the fitted covariance; with 20 clusters they are anti-conservative and are reported as
approximate. Joint Wald tests are given for each interaction. The same ladder is run on `Correct_forced` as a
sensitivity analysis. **Always shown, whatever the model does:** descriptive pair-bootstrap contrasts of the
primary `Correct` rate (LLM - static; each factor level vs reference), labelled descriptive.

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
