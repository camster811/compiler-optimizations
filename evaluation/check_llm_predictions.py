#!/usr/bin/env python3
"""PRIVATE: verify persisted inference evidence and join it to ground truth."""
import argparse
import gzip
import os
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from llm_analysis.common import digest, file_hash, load, now, save, write
from llm_analysis.history import replay_campaign
from llm_analysis.run_llm import verify
from evaluation.prepare_llm_experiment import load_experiment


def ratio(a, b):
    return a / b if b else None


def metrics(rows):
    decisions = Counter(r["decision"] for r in rows)
    decided = decisions["correct"] + decisions["incorrect"]
    tp = sum(r["positive"] and r["classification"] == "vulnerable" for r in rows)
    tn = sum(not r["positive"] and r["classification"] != "vulnerable" for r in rows)
    fp = sum(not r["positive"] and r["classification"] == "vulnerable" for r in rows)
    fn = sum(r["positive"] and r["classification"] != "vulnerable" for r in rows)
    sensitivity, specificity = ratio(tp, tp + fn), ratio(tn, tn + fp)
    return {"observations": len(rows), "correct": decisions["correct"], "incorrect": decisions["incorrect"],
            "abstentions": decisions["abstain"], "coverage": ratio(decided, len(rows)),
            "selective_accuracy": ratio(decisions["correct"], decided),
            "failure_affected_observations": sum(r["failure_count"] > 0 for r in rows),
            "binary_alert": {"TP": tp, "TN": tn, "FP": fp, "FN": fn,
                             "TN_from_abstention": sum(not r["positive"] and r["classification"] == "uncertain" for r in rows),
                             "FN_from_abstention": sum(r["positive"] and r["classification"] == "uncertain" for r in rows),
                             "TN_from_not_vulnerable": sum(not r["positive"] and r["classification"] == "not_vulnerable" for r in rows),
                             "FN_from_not_vulnerable": sum(r["positive"] and r["classification"] == "not_vulnerable" for r in rows),
                             "accuracy": ratio(tp + tn, len(rows)),
                             "balanced_accuracy": (sensitivity + specificity) / 2 if sensitivity is not None and specificity is not None else None,
                             "precision": ratio(tp, tp + fp), "recall": sensitivity,
                             "F1": ratio(2 * tp, 2 * tp + fp + fn), "FPR": ratio(fp, fp + tn), "FNR": ratio(fn, fn + tp)}}


def paired_symbol_runs(observations, runs, shared_seeds):
    """Match shared-seed runs; failed responses are unavailable, not model abstentions."""
    if not shared_seeds:
        return []
    by_record = {}
    for run in runs:
        key = (run["record_sha256"], run["repetition"])
        if key in by_record:
            raise ValueError("duplicate repetition in paired symbol analysis")
        by_record[key] = run
    by_case = {}
    for observation in observations:
        key = (observation["sample_id"], observation["optimization"])
        by_case.setdefault(key, {})[observation["condition"]] = observation

    def outcome(observation, run):
        prediction = run["prediction"] if run["status"] == "valid" else None
        return {"record_sha256": observation["record_sha256"], "run_id": run["run_id"],
                "status": run["status"], "classification": prediction["classification"] if prediction else None,
                "predicted_cwe": prediction["predicted_cwe"] if prediction else None,
                "confidence": prediction["confidence"] if prediction else None}

    comparisons = []
    for (sid, opt), conditions in sorted(by_case.items()):
        if not {"retained", "stripped"} <= set(conditions):
            continue
        retained, stripped = conditions["retained"], conditions["stripped"]
        for repetition in (1, 2, 3):
            try:
                a = by_record[(retained["record_sha256"], repetition)]
                b = by_record[(stripped["record_sha256"], repetition)]
            except KeyError as e:
                raise ValueError("missing repetition in paired symbol analysis") from e
            if a["seed"] != b["seed"]:
                raise ValueError(f"symbol comparison seed mismatch for {sid}/{opt}/r{repetition}")
            valid = a["status"] == b["status"] == "valid"
            agree = ((a["prediction"]["classification"], a["prediction"]["predicted_cwe"])
                     == (b["prediction"]["classification"], b["prediction"]["predicted_cwe"])) if valid else None
            comparisons.append({"sample_id": sid, "pair_id": retained["pair_id"], "optimization": opt,
                                "repetition": repetition, "seed": a["seed"],
                                "shared_record": retained["record_sha256"] == stripped["record_sha256"],
                                "retained": outcome(retained, a), "stripped": outcome(stripped, b),
                                "both_valid": valid, "same_classification_and_cwe": agree,
                                "confidence_difference_retained_minus_stripped":
                                    a["prediction"]["confidence"] - b["prediction"]["confidence"] if valid else None})
    return comparisons


def check(campaign, experiment_path):
    m, runs, predictions = replay_campaign(campaign)
    experiment, experiment_hash = load_experiment(experiment_path)
    if m["development_data"] != experiment["development_data"]:
        raise ValueError("experiment and campaign data splits differ")
    if m["method"]["version"] != "1.0.0" and m["metadata"]["experiment_sha256"] != experiment_hash:
        raise ValueError("campaign is not bound to this frozen private experiment")
    if load(campaign / "run_results.json") != runs or load(campaign / "predictions.json") != predictions:
        raise ValueError("exported predictions differ from offline replay")
    listed = {}
    for line in (campaign / "checksums.sha256").read_text().splitlines():
        h, name = line.split("  ", 1)
        p = Path(name)
        if p.is_absolute() or ".." in p.parts or name in listed:
            raise ValueError("invalid checksum entry")
        listed[name] = h
        if file_hash(campaign / p) != h:
            raise ValueError(f"archive checksum mismatch: {name}")
    expected_files = {str(p.relative_to(campaign)) for p in campaign.rglob("*")
                      if p.is_file() and p.name not in {"checksums.sha256", ".lock"}}
    if set(listed) != expected_files:
        raise ValueError("checksum manifest does not cover every campaign artifact")
    observations = experiment["observations"]
    if set(m["record_hashes"]) != {o["record_sha256"] for o in observations}:
        raise ValueError("campaign record set differs from the private experiment")
    by_hash = {p["record_sha256"]: p for p in predictions}
    rows, run_rows = [], []
    for o in observations:
        condition, sid, optimization, h = o["condition"], o["sample_id"], o["optimization"], o["record_sha256"]
        t = o
        def scored(pred, failures):
            cls, cwe = pred["classification"], pred["predicted_cwe"]
            positive = t["ground_truth"] == "vulnerable"
            decision = "abstain" if cls == "uncertain" else (
                "correct" if (positive and cls == "vulnerable" and cwe == t["cwe"])
                or (not positive and cls == "not_vulnerable") else "incorrect")
            return {"observation_id": o["observation_id"], "pair_id": o["pair_id"],
                    "sample_id": sid, "optimization": optimization, "condition": condition,
                    "cwe": t["cwe"], "ground_truth": t["ground_truth"], "record_sha256": h, "positive": positive,
                    "classification": cls, "predicted_cwe": cwe, "decision": decision, "failure_count": failures}
        p = by_hash[h]
        rows.append({**scored(p, p["failure_count"]), "median_confidence": p["median_confidence"],
                     "aggregation_reason": p["aggregation_reason"]})
        for r in runs:
            if r["record_sha256"] == h:
                prediction = r["prediction"] or {"classification": "uncertain", "predicted_cwe": None}
                run_rows.append({**scored(prediction, int(r["status"] != "valid")), "run_id": r["run_id"],
                                 "status": r["status"], "confidence": prediction.get("confidence")})
    statuses = Counter(r["status"] for r in runs)
    token_counts = [v["prompt_tokens"] for v in load(campaign / "preflight.json")["records"].values()]
    latencies = [r["latency_seconds"] for r in runs if r.get("latency_seconds") is not None]
    total_latency = 0
    attempt_count = 0
    for p in (campaign / "runs").glob("*/attempt-*/response.json"):
        response = load(p)
        attempt_count += 1
        total_latency += response["latency_seconds"] or 0
    comparisons = []
    for sid, opt in sorted({(r["sample_id"], r["optimization"]) for r in rows}):
        pair = {r["condition"]: r for r in rows if r["sample_id"] == sid and r["optimization"] == opt}
        if not {"retained", "stripped"} <= set(pair):
            continue
        a, b = pair["retained"], pair["stripped"]
        comparisons.append({"sample_id": sid, "optimization": opt,
                            "same_classification_and_cwe": (a["classification"], a["predicted_cwe"]) == (b["classification"], b["predicted_cwe"]),
                            "confidence_difference_retained_minus_stripped": a["median_confidence"] - b["median_confidence"]
                            if a["median_confidence"] is not None and b["median_confidence"] is not None else None})
    # Confidence is descriptive; this threshold does not change predictions.
    high_confidence = [r for r in run_rows if r["decision"] == "incorrect" and (r["confidence"] or 0) >= 0.8]
    paired_runs = paired_symbol_runs(observations, runs, m["method"]["config"].get("seed_policy") == "shared_repetition")
    report = {"development_data": m["development_data"], "campaign_id": m["campaign_id"], "method_id": m["method_id"],
              "experiment_sha256": experiment_hash, "dataset_id": experiment["dataset_id"],
              "distinct_records": len(predictions), "scheduled_runs": len(runs), "http_attempts": attempt_count,
              "run_statuses": dict(sorted(statuses.items())), "schema_valid_response_rate": ratio(statuses["valid"], len(runs)),
              "operational_failure_rate": ratio(sum(statuses[s] for s in ("timeout", "transport_error", "interrupted", "http_error")), len(runs)),
              "valid_run_classifications": dict(sorted(Counter(r["prediction"]["classification"] for r in runs if r["status"] == "valid").items())),
              "aggregate_abstention_reasons": dict(sorted(Counter(p["aggregation_reason"] for p in predictions if p["classification"] == "uncertain").items())),
              "unanimous_record_rate": ratio(sum(p["unanimous"] for p in predictions), len(predictions)),
              "all_valid_record_count": sum(p["valid_run_count"] == 3 for p in predictions),
              "prompt_tokens": {"minimum": min(token_counts), "maximum": max(token_counts)},
              "latency_seconds": {"total_attempt_time": total_latency, "median_terminal_attempt": median(latencies) if latencies else None},
              "overall": metrics(rows), "breakdowns": {}, "observations": rows,
              "per_run_observation_metrics": metrics(run_rows), "high_confidence_incorrect_runs": high_confidence,
              "symbol_comparisons": comparisons,
              "paired_run_symbol_comparisons": paired_runs,
              "paired_run_symbol_summary": {
                  "matched_pairs": len(paired_runs), "both_valid_pairs": sum(p["both_valid"] for p in paired_runs),
                  "unavailable_pairs": sum(not p["both_valid"] for p in paired_runs),
                  "agreeing_pairs": sum(p["same_classification_and_cwe"] is True for p in paired_runs),
                  "disagreeing_pairs": sum(p["same_classification_and_cwe"] is False for p in paired_runs),
                  "shared_record_pairs": sum(p["shared_record"] for p in paired_runs)},
              "notes": ["Repeated conditions and generations are related measurements, not independent samples.",
                        "Forced binary alert: vulnerable=alert; uncertain, including failure-driven uncertainty, produces no alert.",
                        "A schema-valid answer can still be factually incorrect. Evidence checks validate address membership only.",
                        "Run-level symbol comparisons require shared seeds. Legacy differing-seed runs are not paired.",
                        "Failed runs remain unavailable in paired comparisons; valid uncertain predictions remain model abstentions."]}
    for factor in ("cwe", "optimization", "condition", "ground_truth"):
        report["breakdowns"][factor] = {value: metrics([r for r in rows if r[factor] == value])
                                           for value in sorted({r[factor] for r in rows})}
    return report


def preserve(path, raw):
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError(f"immutable frozen artifact differs: {path}")
    else:
        write(path, raw, immutable=True)


def select_final(receipt, report):
    from llm_analysis.common import encode
    if (report["campaign_id"] != receipt["campaign_id"] or report["method_id"] != receipt["method_id"]
            or digest(encode(report)) != receipt["report_sha256"]):
        raise ValueError("selection report differs from frozen evidence")
    c = receipt["method"]["config"]
    threshold = c.get("minimum_schema_valid_rate", 0.98)
    if not receipt["development_data"] or c.get("structured_output") != "json_schema":
        raise ValueError("select a constrained-output development campaign before final evaluation")
    if (report["schema_valid_response_rate"] < threshold
            or report["run_statuses"].get("invalid_json", 0)
            or report["run_statuses"].get("schema_invalid", 0)):
        raise ValueError(f"final-method gate failed: schema adherence must be >= {threshold:.1%} without formatting/schema failures")
    receipt_path = ROOT / "llm_analysis" / "frozen" / receipt["campaign_id"] / "method.json"
    save(ROOT / "llm_analysis" / "frozen" / "current.json", {
        "campaign_id": receipt["campaign_id"], "method_id": receipt["method_id"],
        "receipt_path": str(receipt_path.relative_to(ROOT)), "receipt_sha256": file_hash(receipt_path),
        "selection_criterion": "schema adherence only; prediction accuracy is not a selection criterion",
        "minimum_schema_valid_rate": threshold, "schema_valid_response_rate": report["schema_valid_response_rate"]})


def freeze(campaign, report, experiment_path):
    """PRIVATE: preserve a campaign-specific method, results, and evidence archive."""
    m, _, _ = replay_campaign(campaign)
    experiment, experiment_hash = load_experiment(experiment_path)
    cid = m["campaign_id"]
    frozen_dir = ROOT / "llm_analysis" / "frozen" / cid
    frozen = frozen_dir / "method.json"
    results = ROOT / "llm_analysis" / "results" / cid
    if frozen.exists():
        existing = load(frozen)
        if existing["method"] != m["method"]:
            raise ValueError("frozen method differs from campaign")
        if file_hash(ROOT / existing["archive_path"]) != existing["archive_sha256"]:
            raise ValueError("existing frozen archive is corrupted")
        report_path = ROOT / existing.get("report_path", str((results / "report.json").relative_to(ROOT)))
        if file_hash(report_path) != existing["report_sha256"]:
            raise ValueError("frozen report is corrupted")
        for name, h in existing["results"].items():
            if file_hash(results / name) != h:
                raise ValueError("frozen prediction export is corrupted")
        return existing
    verify(campaign, check_runtime=True)
    for name, h in m["method"]["files"].items():
        source = Path(__file__).resolve().parent.parent / name
        if file_hash(source) != h:
            raise ValueError("method source changed before freeze")
        preserve(frozen_dir / "method_source" / name, source.read_bytes())
    for name in ("check_llm_predictions.py", "prepare_llm_experiment.py", "experiment_schema.json"):
        source = Path(__file__).with_name(name)
        preserve(frozen_dir / "method_source" / "evaluation" / name, source.read_bytes())
    for name in ("predictions.json", "run_results.json"):
        preserve(results / name, (campaign / name).read_bytes())
    from llm_analysis.common import encode
    preserve(results / "report.json", encode(report))
    diagnostics = ROOT / "llm_analysis" / "output" / "runtime_evidence" / cid
    diagnostic_files = []
    for name in ("server.log", "gpu_memory.jsonl", "server_process.json"):
        source = ROOT / "llm_analysis" / "output" / name
        if source.exists():
            target = diagnostics / name
            if not target.exists():
                preserve(target, source.read_bytes())
            diagnostic_files.append(target)
    archive = ROOT / "llm_analysis" / "output" / "releases" / f"{cid}.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        raise ValueError("unreceipted archive already exists; preserve it and investigate")
    fd, temporary = tempfile.mkstemp(prefix=".archive-", dir=archive.parent)
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w") as tar:
                    entries = [(p, f"{cid}/{p.relative_to(campaign)}")
                               for p in sorted(p for p in campaign.rglob("*") if p.is_file() and p.name != ".lock")]
                    entries += [(p, f"method/{p.relative_to(frozen_dir / 'method_source')}")
                                for p in sorted((frozen_dir / "method_source").rglob("*")) if p.is_file()]
                    entries += [(p, f"runtime/{p.name}") for p in diagnostic_files]
                    entries.append((Path(experiment_path), "evaluation/experiment.json"))
                    entries.append((results / "report.json", "evaluation/report.json"))
                    for path, name in entries:
                        info = tar.gettarinfo(str(path), arcname=name)
                        info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
                        info.mode = 0o644
                        with path.open("rb") as f:
                            tar.addfile(info, f)
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, archive)
    finally:
        Path(temporary).unlink(missing_ok=True)
    supplements = {str(p.relative_to(ROOT)): file_hash(p) for p in diagnostic_files}
    provenance = ROOT / "llm_analysis" / "frozen" / "model_provenance.json"
    if provenance.exists():
        source = load(provenance)
        actual = m["method"]["runtime"]["artifacts"][m["method"]["config"]["model_path"]]
        if source["sha256"] != actual:
            raise ValueError("provenance addendum does not identify the model used")
        supplements[str(provenance.relative_to(ROOT))] = file_hash(provenance)
    receipt = {"version": "1.1.0", "frozen_at": now(), "development_data": m["development_data"],
               "campaign_id": cid, "method_id": m["method_id"], "method": m["method"],
               "input_set_sha256": m["input_set_sha256"], "archive_path": str(archive.relative_to(ROOT)),
               "archive_sha256": file_hash(archive), "campaign_checksums_sha256": file_hash(campaign / "checksums.sha256"),
               "checker_sha256": file_hash(Path(__file__)), "report_path": str((results / "report.json").relative_to(ROOT)),
               "report_sha256": file_hash(results / "report.json"), "experiment_sha256": experiment_hash,
               "experiment_path": str(Path(experiment_path).resolve().relative_to(ROOT)),
               "supplements": supplements,
               "results": {name: file_hash(results / name) for name in ("predictions.json", "run_results.json")}}
    save(frozen, receipt, immutable=True)
    return receipt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--campaign", required=True, type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--experiment", required=True, type=Path, help="frozen private experiment manifest")
    ap.add_argument("--freeze", action="store_true", help="archive verified pilot evidence and freeze the method")
    ap.add_argument("--select-final", action="store_true", help="select a frozen method only after schema-adherence gate passes")
    args = ap.parse_args()
    try:
        report = check(args.campaign.resolve(), args.experiment.resolve())
    except (ValueError, OSError, KeyError) as e:
        print(f"FAIL: {e}")
        raise SystemExit(1)
    if args.report:
        if args.campaign.resolve() in args.report.resolve().parents:
            raise ValueError("private report must be outside the blinded campaign")
        save(args.report, report)
    if args.freeze:
        receipt = freeze(args.campaign.resolve(), report, args.experiment.resolve())
        print(f"Frozen method {receipt['method_id']}; archive {receipt['archive_path']}")
    if args.select_final:
        receipt = freeze(args.campaign.resolve(), report, args.experiment.resolve())
        select_final(receipt, report)
        print("Selected final method after schema-adherence gate passed")
    print(f"OK: {report['scheduled_runs']} terminal runs, {report['distinct_records']} distinct records, {report['overall']['observations']} observations")
    print("Run statuses:", report["run_statuses"])
    print("Three-way:", {k: v for k, v in report["overall"].items() if k != "binary_alert"})
    print("Binary alert:", report["overall"]["binary_alert"])
    print(f"{'Development' if report['development_data'] else 'Final-corpus'} results; confidence is descriptive and observations are related.")


if __name__ == "__main__":
    main()
