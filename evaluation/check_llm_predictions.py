#!/usr/bin/env python3
"""PRIVATE: verify persisted inference evidence and join it to ground truth."""
import argparse
import csv
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
from llm_analysis.run_llm import replay, verify


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
                             "accuracy": ratio(tp + tn, len(rows)),
                             "balanced_accuracy": (sensitivity + specificity) / 2 if sensitivity is not None and specificity is not None else None,
                             "precision": ratio(tp, tp + fp), "recall": sensitivity,
                             "F1": ratio(2 * tp, 2 * tp + fp + fn), "FPR": ratio(fp, fp + tn), "FNR": ratio(fn, fn + tp)}}


def check(campaign):
    m = verify(campaign)
    runs, predictions = replay(campaign)
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
    observations = []
    for condition in ("retained", "stripped"):
        for p in sorted((ROOT / "ghidra" / "output" / condition).glob("*.json")):
            sid, optimization = p.stem.rsplit("_", 1)
            observations.append((condition, sid, optimization, digest(p.read_bytes())))
    if len(observations) != 16 or set(m["record_hashes"]) != {o[3] for o in observations}:
        raise ValueError("pilot observation join differs from the expected sixteen records")
    with (ROOT / "build" / "artifacts" / "private" / "build_manifest.tsv").open(newline="") as f:
        truth = {(r["sample_id"], r["optimization"]): r for r in csv.DictReader(f, delimiter="\t")}
    by_hash = {p["record_sha256"]: p for p in predictions}
    rows, run_rows = [], []
    for condition, sid, optimization, h in observations:
        t = truth[(sid, optimization)]
        def scored(pred, failures):
            cls, cwe = pred["classification"], pred["predicted_cwe"]
            positive = t["ground_truth"] == "vulnerable"
            decision = "abstain" if cls == "uncertain" else (
                "correct" if (positive and cls == "vulnerable" and cwe == t["cwe"])
                or (not positive and cls == "not_vulnerable") else "incorrect")
            return {"sample_id": sid, "optimization": optimization, "condition": condition,
                    "cwe": t["cwe"], "record_sha256": h, "positive": positive,
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
        a, b = pair["retained"], pair["stripped"]
        comparisons.append({"sample_id": sid, "optimization": opt,
                            "same_classification_and_cwe": (a["classification"], a["predicted_cwe"]) == (b["classification"], b["predicted_cwe"]),
                            "confidence_difference_retained_minus_stripped": a["median_confidence"] - b["median_confidence"]
                            if a["median_confidence"] is not None and b["median_confidence"] is not None else None})
    # Confidence is descriptive; this threshold does not change predictions.
    high_confidence = [r for r in run_rows if r["decision"] == "incorrect" and (r["confidence"] or 0) >= 0.8]
    report = {"development_data": True, "campaign_id": m["campaign_id"], "method_id": m["method_id"],
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
              "notes": ["Repeated conditions and generations are related measurements, not independent samples.",
                        "Forced binary alert: vulnerable=alert; uncertain, including failure-driven uncertainty, produces no alert.",
                        "A schema-valid answer can still be factually incorrect. Evidence checks validate address membership only."]}
    for factor in ("cwe", "optimization", "condition"):
        report["breakdowns"][factor] = {value: metrics([r for r in rows if r[factor] == value])
                                           for value in sorted({r[factor] for r in rows})}
    return report


def freeze(campaign, report):
    """PRIVATE: archive verified evidence and publish the development method receipt."""
    m = verify(campaign, check_runtime=True)
    frozen = ROOT / "llm_analysis" / "frozen" / "method.json"
    if frozen.exists():
        existing = load(frozen)
        if existing["campaign_id"] != m["campaign_id"] or existing["method"] != m["method"]:
            raise ValueError("a different method is already frozen; no automatic replacement")
        if file_hash(ROOT / existing["archive_path"]) != existing["archive_sha256"]:
            raise ValueError("existing frozen archive is corrupted")
        if file_hash(ROOT / "evaluation" / "llm_pilot_report.json") != existing["report_sha256"]:
            raise ValueError("frozen scored report is corrupted")
        for name, h in existing["results"].items():
            if file_hash(ROOT / "llm_analysis" / "results" / name) != h:
                raise ValueError("frozen prediction export is corrupted")
        for name, h in existing.get("supplements", {}).items():
            if file_hash(ROOT / name) != h:
                raise ValueError("frozen reproducibility supplement is corrupted")
        return existing
    diagnostics = ROOT / "llm_analysis" / "output" / "runtime_evidence" / m["campaign_id"]
    diagnostic_files = []
    for name in ("server.log", "gpu_memory.jsonl", "server_process.json"):
        source = ROOT / "llm_analysis" / "output" / name
        if source.exists():
            target = diagnostics / name
            if not target.exists():
                write(target, source.read_bytes(), immutable=True)
            diagnostic_files.append(target)
    archive = ROOT / "llm_analysis" / "output" / "releases" / f"{m['campaign_id']}.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".archive-", dir=archive.parent)
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w") as tar:
                    entries = [(p, f"{campaign.name}/{p.relative_to(campaign)}")
                               for p in sorted(p for p in campaign.rglob("*") if p.is_file() and p.name != ".lock")]
                    # Preserve the exact method code as well as its hashes for future replay.
                    method_root = Path(__file__).resolve().parent.parent
                    entries += [(method_root / name, f"method/{name}") for name in m["method"]["files"]]
                    entries.append((Path(__file__), "method/evaluation/check_llm_predictions.py"))
                    entries += [(p, f"runtime/{p.name}") for p in diagnostic_files]
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
    results = ROOT / "llm_analysis" / "results"
    results.mkdir(parents=True, exist_ok=True)
    for name in ("predictions.json", "run_results.json"):
        write(results / name, (campaign / name).read_bytes())
    save(ROOT / "evaluation" / "llm_pilot_report.json", report)
    supplements = {}
    supplements.update({str(p.relative_to(ROOT)): file_hash(p) for p in diagnostic_files})
    provenance = ROOT / "llm_analysis" / "frozen" / "model_provenance.json"
    if provenance.exists():
        source = load(provenance)
        actual = m["method"]["runtime"]["artifacts"][m["method"]["config"]["model_path"]]
        if source["sha256"] != actual:
            raise ValueError("provenance addendum does not identify the model used")
        supplements[str(provenance.relative_to(ROOT))] = file_hash(provenance)
    receipt = {"version": "1.0.0", "frozen_at": now(), "development_data": True,
               "campaign_id": m["campaign_id"], "method_id": m["method_id"], "method": m["method"],
               "input_set_sha256": m["input_set_sha256"], "archive_path": str(archive.relative_to(ROOT)),
               "archive_sha256": file_hash(archive), "campaign_checksums_sha256": file_hash(campaign / "checksums.sha256"),
               "checker_sha256": file_hash(Path(__file__)),
               "report_sha256": file_hash(ROOT / "evaluation" / "llm_pilot_report.json"),
               "supplements": supplements,
               "results": {name: file_hash(results / name) for name in ("predictions.json", "run_results.json")}}
    save(frozen, receipt, immutable=True)
    return receipt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--campaign", required=True, type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--freeze", action="store_true", help="archive verified pilot evidence and freeze the method")
    args = ap.parse_args()
    try:
        report = check(args.campaign.resolve())
    except (ValueError, OSError, KeyError) as e:
        print(f"FAIL: {e}")
        raise SystemExit(1)
    if args.report:
        if args.campaign.resolve() in args.report.resolve().parents:
            raise ValueError("private report must be outside the blinded campaign")
        save(args.report, report)
    if args.freeze:
        receipt = freeze(args.campaign.resolve(), report)
        print(f"Frozen method {receipt['method_id']}; archive {receipt['archive_path']}")
    print(f"OK: {report['scheduled_runs']} terminal runs, {report['distinct_records']} distinct records, 16 observations")
    print("Run statuses:", report["run_statuses"])
    print("Three-way:", {k: v for k, v in report["overall"].items() if k != "binary_alert"})
    print("Binary alert:", report["overall"]["binary_alert"])
    print("Development-set results; confidence is descriptive and observations are related.")


if __name__ == "__main__":
    main()
