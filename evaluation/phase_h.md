# Reproducing Phase H

The frozen campaign, static output and Phase G tables are the only prediction inputs.
This pipeline makes no inference requests and does not change those inputs.
Definitions and the pre-result amendments are in [final_analysis_plan.md](final_analysis_plan.md).
These are pre-analysis amendments documented before aggregate metrics were computed. They are committed
with the implementation and results, separately from the original preregistration (`7856cce`).

## Environment

In a fresh checkout, restore only the campaign directory from the committed release archive;
the refreshed acceptance receipt and Phase G manifest in `results/` must remain in place:

```sh
sha256sum --check results/final-v1/archive.sha256
mkdir -p llm_analysis/output/campaigns
tar -xzf llm_analysis/output/releases/final-v1-ad3bd1652d6a.tar.gz -C llm_analysis/output/campaigns ad3bd1652d6a18461914be5cb0f12b8786f76e72807d1ae725b5fe4e60f2f478
```

F3 reads the committed `results/final-v1/llm/server_final_run.log` slice directly. It does not
read the ignored live server log or use the pre-campaign offsets.

The recorded environment targets Ubuntu 26.04 amd64 and Python 3.14.4. The package lock pins
59 Debian archives, including R/lme4 and scientific Python dependencies, with SHA-256 hashes.
The installer verifies each archive and extracts into ignored `.analysis-env/`; it needs no sudo.
Existing base OS libraries remain host dependencies; exact runtime versions and platform are
recorded in the analysis receipt. Installation needs network access unless archives are cached.

```sh
python3 -m evaluation.analysis_environment --install
python3 evaluation/run_final_analysis.py
python3 evaluation/run_final_analysis.py --check
```

The runner activates the local environment automatically, verifies exact runtime versions and the
backend reference example, checks the frozen corpus and receipts, replays saved raw responses, and
rebuilds all six Phase G tables in a temporary directory. All six must match before metrics run.
This rebuild does not rewrite the original timestamped Phase G manifest.

`--campaign PATH` selects the campaign directory (it must match the frozen receipt).
`--output PATH` selects an analysis directory. Existing output is accepted only when every artifact
is byte-identical; `--check` compares a temporary regeneration without rewriting output. To review
an intentional implementation change, generate into a new directory and compare it before replacing
the previously generated analysis. A normal run never silently replaces differing results.

## Outputs and interpretation

The default output is `results/final-v1/analysis/`: `report.md`, CSV tables, PNG figures,
`models.json`, and `analysis.json`. The latter binds inputs, amended plan, source, package lock,
bootstrap weights, runtime versions, backend validation and generated artifact hashes. It excludes
its own hash to avoid a circular digest. Tables record exact denominators, contributing pairs, and
usable bootstrap replicates; null ratios include the reason.

Selective accuracy must be read with coverage and abstention counts. Strict three-way correctness
requires the correct CWE on a vulnerable call; the primary model uses correct decided classifications
without checking CWE. Abstentions and failures score zero in that model. The separate forced-alert
view maps them to no alert and preserves TN/FN provenance. Repetitions and shared predictions are
measurements of the same source pair, not extra independent programs.

The full GLMM and main-effects GLMM are screened in fixed order; selection never uses significance.
If neither passes, the report retains descriptive pair-cluster intervals with no model of record.
The same ladder runs independently for the forced-alert sensitivity outcome. Runtime/setup errors
abort instead of becoming statistical fallbacks. With only 20 pairs, intervals are approximate and
Wald inference can be anti-conservative; no comparisons are confirmatory.

## Validation

```sh
python3 -m evaluation.analysis_environment --run python3 -m unittest discover -s evaluation/tests -v
python3 -m unittest discover -s llm_analysis/tests -v
python3 -m evaluation.freeze_corpus --check
```

The LLM transport test requires permission to bind a temporary loopback socket. Phase H tests use
hand-calculated cases and synthetic clustered observations, plus lme4's published `cbpp` example;
they do not inspect final predictions. Regeneration additionally checks all input and output hashes.
The separate F3 regression restores the archived final campaign, hides the live server log and its old
offsets, and requires all 39 acceptance checks to pass using the preserved campaign log slice.

Distinct-request status summaries are overall only. Requests shared across optimization levels cannot be
assigned to one representative level; optimization, symbol, CWE and other subgroup summaries therefore
use observation-weighted rows. The report records this post-analysis reporting correction explicitly.

Backend references: [GLMM fitting](https://lme4.github.io/lme4/reference/glmer.html) and
[convergence diagnostics](https://lme4.github.io/lme4/reference/convergence.html).
