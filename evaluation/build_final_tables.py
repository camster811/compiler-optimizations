#!/usr/bin/env python3
"""PRIVATE Phase G: build the final-v1 evaluation tables. No metric is computed here.

Tables (results/final-v1/private/, JSONL and CSV with identical flat columns):
  llm_runs               one row per eligible observation x LLM repetition (648)
  condition_comparison   one row per eligible observation x method {static, llm_majority} (432)
  non_analyzable         proven-eliminated observations; never predicted, never scored (104)
Join cardinality is validated before anything is written. A hash shared by several
observations yields one row per observation, so repeated rows are not independent evidence.
"""
import argparse
import csv
import io
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from evaluation.prepare_llm_experiment import load_experiment
from llm_analysis.build_prompt import project
from llm_analysis.common import decode, digest, encode, file_hash, load, now, save
from llm_analysis.history import replay_campaign
from llm_analysis.run_llm import terminal_from_attempt

OUT = ROOT / "results" / "final-v1" / "private"
OPERATIONAL = {"timeout", "transport_error", "interrupted", "http_error", "context_overflow"}
METHODS = ("static", "llm_majority")


def failure_kind(status):
    return "none" if status == "valid" else "operational" if status in OPERATIONAL else "output_contract"


def decision(classification, cwe, positive, truth_cwe):
    """Three-way view: abstain, or correct/incorrect (a vulnerable call needs the exact CWE)."""
    if classification is None:
        return "unavailable"
    if classification == "uncertain":
        return "abstain"
    ok = (classification == "vulnerable" and cwe == truth_cwe) if positive else classification == "not_vulnerable"
    return "correct" if ok else "incorrect"


def views(o, classification, cwe):
    """Correctness under each declared view: target-effect (primary) and source-origin (secondary)."""
    alert = classification == "vulnerable"
    out = {"binary_alert": alert, "abstained": classification == "uncertain"}
    for name, key in (("primary_target_effect", "target_effect_ground_truth"), ("secondary_source_origin", "source_ground_truth")):
        positive = o[key] == "vulnerable"
        out[f"{name}_positive"] = positive
        out[f"{name}_decision"] = decision(classification, cwe, positive, o["cwe"])
        out[f"{name}_binary_correct"] = None if classification is None else alert == positive
        out[f"{name}_cwe_match"] = (cwe == o["cwe"]) if classification == "vulnerable" else None
    return out


def observation_fields(o, conflicted, shared):
    return {"observation_id": o["observation_id"], "pair_id": o["pair_id"], "source_case_id": o["sample_id"],
            "truth_cwe": o["cwe"], "condition": o["condition"], "optimization": o["optimization"],
            "source_ground_truth": o["source_ground_truth"], "target_effect_ground_truth": o["target_effect_ground_truth"],
            "binary_manifestation": o["binary_manifestation"], "capacity_visibility": o["capacity_visibility"],
            "evidence_locality": o["evidence_locality"], "input_label_conflict_group": o["record_sha256"] in conflicted,
            "observations_sharing_record": shared[o["record_sha256"]]}


def write_table(name, rows, written):
    if not rows or any(list(r) != list(rows[0]) for r in rows):
        raise ValueError(f"{name}: inconsistent columns")
    jsonl = "".join(json.dumps(r, sort_keys=False, ensure_ascii=False, allow_nan=False) + "\n" for r in rows).encode()
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows({k: ("" if v is None else v) for k, v in r.items()} for r in rows)
    for suffix, raw in (("jsonl", jsonl), ("csv", buffer.getvalue().encode())):
        path = OUT / f"{name}.{suffix}"
        if path.exists() and path.read_bytes() != raw:
            raise ValueError(f"{path} exists with different content")
        path.write_bytes(raw)
        written[f"{name}.{suffix}"] = {"sha256": digest(raw), "rows": len(rows), "columns": list(rows[0])}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--campaign", required=True, type=Path)
    ap.add_argument("--experiment", default=ROOT / "evaluation/experiments/final.json", type=Path)
    args = ap.parse_args()
    campaign = args.campaign.resolve()

    acceptance = load(ROOT / "results/final-v1/acceptance.json")
    if acceptance["failed"] or acceptance["campaign_id"] != campaign.name:
        raise SystemExit("F3 acceptance has not passed for this campaign; no tables built")
    experiment, experiment_hash = load_experiment(args.experiment)
    if acceptance["experiment_sha256"] != experiment_hash:
        raise SystemExit("acceptance was computed for a different experiment")
    manifest, runs, aggregates = replay_campaign(campaign)
    config = manifest["method"]["config"]
    static_execution = load(ROOT / "results/final-v1/static/execution.json")
    static = {p["record_sha256"]: p for p in load(ROOT / "results/final-v1/static/predictions.json")}
    preflight = load(campaign / "preflight.json")["records"]
    conflicted = {r["record_sha256"] for g in load(ROOT / "datasets/final-v1/private/input_equivalence.json")["conflicting_groups"].values() for r in g}
    model_sha256 = manifest["method"]["runtime"]["artifacts"][config["model_path"]]
    config_sha256 = digest(encode(config))

    eligible = sorted((o for o in experiment["observations"] if o["inference_eligible"]), key=lambda o: o["observation_id"])
    eliminated = sorted((o for o in experiment["observations"] if not o["inference_eligible"]), key=lambda o: o["observation_id"])
    shared = Counter(o["record_sha256"] for o in eligible)
    runs_by_hash, agg_by_hash = {}, {}
    for r in runs:
        runs_by_hash.setdefault(r["record_sha256"], {})[r["repetition"]] = r
    for a in aggregates:
        if a["record_sha256"] in agg_by_hash:
            raise SystemExit("duplicate LLM aggregate")
        agg_by_hash[a["record_sha256"]] = a

    # ---- join cardinality, before any row is built ----
    problems = []
    if len(eligible) + len(eliminated) != 320 or len({o["observation_id"] for o in experiment["observations"]}) != 320:
        problems.append("observation count differs from the 320-row frozen matrix")
    for h in shared:
        if h not in static or h not in agg_by_hash or set(runs_by_hash.get(h, {})) != {1, 2, 3}:
            problems.append(f"record {h[:12]} lacks a static prediction, aggregate or three runs")
    if set(static) != set(shared) or set(agg_by_hash) != set(shared) or set(runs_by_hash) != set(shared):
        problems.append("a prediction or run has no private observation")
    if any(o["record_sha256"] is not None for o in eliminated):
        problems.append("an eliminated observation carries a record")
    if problems:
        raise SystemExit("join validation failed:\n" + "\n".join(problems))

    # ---- raw LLM-run table ----
    attempt_history = {}
    for r in runs:
        run_dir = campaign / "runs" / r["run_id"]
        raw = (campaign / "records" / f"{r['record_sha256']}.json").read_bytes()
        history = []
        for k in range(1, r["attempts"] + 1):
            meta = load(run_dir / f"attempt-{k}" / "response.json")
            body = (run_dir / f"attempt-{k}" / "response.body").read_bytes()
            outcome, retry = terminal_from_attempt(meta, body, project(raw), config)
            history.append({"attempt": k, "status": outcome["status"], "retried": retry and k < r["attempts"],
                            "http_status": meta["http_status"], "latency_seconds": meta["latency_seconds"],
                            "started_at": meta["started_at"], "response_sha256": meta["response_sha256"]})
        attempt_history[r["run_id"]] = history

    raw_rows = []
    for o in eligible:
        for repetition in (1, 2, 3):
            r = runs_by_hash[o["record_sha256"]][repetition]
            p = r["prediction"]
            cls, cwe = (p["classification"], p["predicted_cwe"]) if p else (None, None)
            usage, history = r.get("usage") or {}, attempt_history[r["run_id"]]
            raw_rows.append({
                **observation_fields(o, conflicted, shared), "method": "llm_run", "repetition": repetition, "run_id": r["run_id"],
                "seed": r["seed"], "run_status": r["status"], "failure_kind": failure_kind(r["status"]),
                "prediction_available": p is not None, "classification": cls, "predicted_cwe": cwe,
                "confidence": p["confidence"] if p else None, **views(o, cls, cwe),
                "parser_detail": r["detail"], "finish_reason": r.get("finish_reason"), "attempts": r["attempts"],
                "retry_history": json.dumps(history, sort_keys=True),
                "terminal_latency_seconds": r.get("latency_seconds"),
                "total_attempt_latency_seconds": sum(h["latency_seconds"] or 0 for h in history),
                "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                "total_tokens": usage.get("total_tokens"),
                "record_sha256": o["record_sha256"], "request_sha256": r["request_sha256"],
                "rendered_prompt_sha256": preflight[o["record_sha256"]]["rendered_prompt_sha256"],
                "response_sha256": history[-1]["response_sha256"] if history else None,
                "result_sha256": file_hash(campaign / "runs" / r["run_id"] / "result.json"),
                "raw_response_path": f"runs/{r['run_id']}/attempt-{r['attempts']}/response.body" if history else None,
                "method_id": manifest["method_id"], "config_sha256": config_sha256, "model_sha256": model_sha256,
                "campaign_id": manifest["campaign_id"]})

    # ---- condition-level table ----
    condition_rows = []
    for o in eligible:
        h = o["record_sha256"]
        s, a = static[h], agg_by_hash[h]
        base = observation_fields(o, conflicted, shared)
        s_cls = s["classification"]
        condition_rows.append({
            **base, "method": "static", "classification": s_cls, "predicted_cwe": s["predicted_cwe"], "confidence": None,
            **views(o, s_cls, s["predicted_cwe"]),
            "operational_failure_status": "none", "valid_runs": None, "failed_runs": None, "unanimous": None,
            "votes": None, "uncertain_reason": ";".join(s["triggered_rules"]) if s_cls == "uncertain" else None,
            "rule_names": ";".join(s["triggered_rules"]), "evidence": json.dumps(s["evidence"], ensure_ascii=False),
            "record_sha256": h, "result_sha256": digest(encode(s)), "run_ids": None,
            "method_id": static_execution["analyzer"]["analyzer_sha256"], "config_sha256": static_execution["analyzer"]["rules_sha256"]})
        l_cls = a["classification"]
        condition_rows.append({
            **base, "method": "llm_majority", "classification": l_cls, "predicted_cwe": a["predicted_cwe"],
            "confidence": a["median_confidence"], **views(o, l_cls, a["predicted_cwe"]),
            "operational_failure_status": "none" if a["failure_count"] == 0 else "all_failed" if a["failure_count"] == 3 else "partial",
            "valid_runs": a["valid_run_count"], "failed_runs": a["failure_count"], "unanimous": a["unanimous"],
            "votes": json.dumps(a["votes"], sort_keys=True), "uncertain_reason": a["aggregation_reason"],
            "rule_names": None, "evidence": None,
            "record_sha256": h, "result_sha256": digest(encode(a)), "run_ids": ";".join(a["run_references"]),
            "method_id": manifest["method_id"], "config_sha256": config_sha256})

    # ---- non-analyzable rows ----
    skipped = [{**{k: o[k] for k in ("observation_id", "pair_id", "sample_id", "cwe", "condition", "optimization",
                                      "source_ground_truth", "binary_manifestation", "inference_disposition")},
                "scored": False, "note": "proven eliminated; no record, prediction, TN, FN or abstention"} for o in eliminated]

    # ---- cardinality validation of the built tables ----
    ids = [o["observation_id"] for o in eligible]
    raw_keys = Counter((r["observation_id"], r["repetition"]) for r in raw_rows)
    cond_keys = Counter((r["observation_id"], r["method"]) for r in condition_rows)
    problems = []
    if len(raw_rows) != 3 * len(ids) or set(raw_keys.values()) != {1} or {k[0] for k in raw_keys} != set(ids):
        problems.append("raw LLM-run table is not one row per observation and repetition")
    if len(condition_rows) != 2 * len(ids) or set(cond_keys.values()) != {1} or {k[1] for k in cond_keys} != set(METHODS):
        problems.append("condition table is not one row per observation and method")
    for h, n in shared.items():
        if sum(r["record_sha256"] == h for r in raw_rows) != 3 * n or sum(r["record_sha256"] == h for r in condition_rows) != 2 * n:
            problems.append(f"record {h[:12]} lost or duplicated rows")
    if {r["observation_id"] for r in skipped} & set(ids) or len(skipped) + len(ids) != 320:
        problems.append("eliminated and eligible observations do not partition the 320-row matrix")
    if problems:
        raise SystemExit("table cardinality failed:\n" + "\n".join(problems))

    OUT.mkdir(parents=True, exist_ok=True)
    written = {}
    write_table("llm_runs", raw_rows, written)
    write_table("condition_comparison", condition_rows, written)
    write_table("non_analyzable", skipped, written)
    receipt = {"phase": "G", "built_at": now(), "campaign_id": manifest["campaign_id"], "method_id": manifest["method_id"],
               "experiment_sha256": experiment_hash, "acceptance_sha256": file_hash(ROOT / "results/final-v1/acceptance.json"),
               "static_predictions_sha256": static_execution["output"]["sha256"],
               "campaign_checksums_sha256": file_hash(campaign / "checksums.sha256"),
               "cardinality": {"planned_observations": 320, "eligible_observations": len(ids),
                               "distinct_records": len(shared), "records_shared_by_two_observations": sum(n == 2 for n in shared.values()),
                               "llm_runs_rows": len(raw_rows), "condition_rows": len(condition_rows),
                               "non_analyzable_rows": len(skipped)},
               "tables": written, "metrics_computed": False,
               "conventions": [
                   "binary_alert = classification == 'vulnerable'; uncertain and failed runs raise no alert.",
                   "Failed LLM runs have decision 'unavailable' (not 'abstain') and binary_correct = null, so a failure is never silently scored as a correct negative; binary_alert is false for them, and any forced-alert analysis must apply that policy explicitly.",
                   "Decisions: abstain = valid 'uncertain'; a vulnerable call is correct only with the exact CWE; not_vulnerable is correct only for negatives.",
                   "primary_target_effect uses target_effect_ground_truth; secondary_source_origin uses source_ground_truth. They coincide on all eligible rows; the views differ only in the 104 non-analyzable rows, which are not in the scored tables.",
                   "failure_kind: operational = timeout/transport/interrupted/http/context; output_contract = parser-level failures.",
                   "In condition_comparison, method_id/config_sha256 hold the analyzer and rules SHA-256 for static rows and the frozen LLM method ID and config hash for llm_majority rows.",
                   "llm_majority is the frozen two-of-three vote; failures reduce valid votes and can yield uncertain.",
                   "Repeated rows for byte-identical records (observations_sharing_record = 2) and rows for the same source pair are related measurements; cluster by pair_id."]}
    save(OUT / "tables_manifest.json", receipt)
    print(json.dumps(receipt["cardinality"], indent=1))


if __name__ == "__main__":
    main()
