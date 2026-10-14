"""Synthetic end-to-end tests for the private join, scores, and release receipt."""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import json
import llm_analysis.run_llm as runner
from evaluation import check_llm_predictions as evaluator
from evaluation.prepare_llm_experiment import load_experiment, prepare_experiment
from llm_analysis.common import config, encode, load, save, write
from llm_analysis.run_llm import execute_run, export, prepare, verify
from llm_analysis.tests.test_pipeline import record, prediction, response


class PrivateEvaluationTests(unittest.TestCase):
    def test_join_scoring_archive_and_freeze_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            for condition in ("retained", "stripped"):
                for sid in range(1, 5):
                    for opt in ("O0", "O2"):
                        r = record()
                        r["sample_id"] = f"sample_{sid:04d}"
                        r["function"]["name"] = f"function_{condition[0]}{sid}{opt[-1]}"
                        r["decompilation"]["text"] = f"void {r['function']['name']}(void) {{}}"
                        p = root / "ghidra" / "output" / condition / f"sample_{sid:04d}_{opt}.json"
                        write(p, encode(r))
                        records.append(p)
            private = root / "build" / "artifacts" / "private" / "build_manifest.tsv"
            private.parent.mkdir(parents=True)
            with private.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["sample_id", "pair_id", "optimization", "ground_truth", "cwe"], delimiter="\t")
                writer.writeheader()
                for sid in range(1, 5):
                    for opt in ("O0", "O2"):
                        writer.writerow({"sample_id": f"sample_{sid:04d}", "pair_id": f"pair_{(sid+1)//2:04d}", "optimization": opt,
                                         "ground_truth": "vulnerable" if sid in (1, 3) else "not_vulnerable",
                                         "cwe": "CWE-121" if sid <= 2 else "CWE-122"})
            save(root / "runtime.json", {"artifacts": {}})
            experiment, blind = prepare_experiment(private, {c: root / "ghidra" / "output" / c for c in ("retained", "stripped")},
                                                    root / "experiment.json", "synthetic")
            _, experiment_hash = load_experiment(experiment)
            campaign = prepare(records, root / "runtime.json", root / "campaigns", config(), experiment_sha256=experiment_hash)
            manifest = verify(campaign)
            flight = {"records": {h: {"prompt_tokens": 100, "fits_context": True} for h in manifest["record_hashes"]}}
            save(campaign / "preflight.json", flight)
            def transport(c, route, payload):
                return {"http_status": 200, "headers": [], "body": response(prediction("not_vulnerable")),
                        "error": None, "latency_seconds": 0.5}
            for job in manifest["schedule"]:
                execute_run(campaign, job, manifest, flight, exchange_fn=transport, idle_fn=lambda c: None)
            export(campaign)
            with patch.object(evaluator, "ROOT", root):
                report = evaluator.check(campaign, experiment)
                self.assertEqual(report["scheduled_runs"], 48)
                self.assertEqual(report["overall"]["coverage"], 1)
                self.assertEqual(report["overall"]["selective_accuracy"], 0.5)
                self.assertEqual(report["overall"]["binary_alert"]["FN"], 8)
                self.assertIsNone(report["overall"]["binary_alert"]["precision"])
                self.assertEqual(report["breakdowns"]["ground_truth"]["vulnerable"]["binary_alert"]["FN"], 8)
                self.assertEqual(report["breakdowns"]["ground_truth"]["not_vulnerable"]["binary_alert"]["TN"], 8)
                for component in ("TP", "TN", "FP", "FN"):
                    self.assertEqual(report["overall"]["binary_alert"][component], sum(
                        group["binary_alert"][component] for group in report["breakdowns"]["ground_truth"].values()))
                self.assertEqual(report["paired_run_symbol_summary"]["matched_pairs"], 24)
                self.assertEqual(report["paired_run_symbol_summary"]["agreeing_pairs"], 24)
                self.assertEqual(report["paired_run_symbol_summary"]["unavailable_pairs"], 0)
                receipt = evaluator.freeze(campaign, report, experiment)
                self.assertTrue((root / receipt["archive_path"]).is_file())
                self.assertEqual(evaluator.freeze(campaign, report, experiment), receipt)
                evaluator.select_final(receipt, report)
                self.assertEqual(load(root / "llm_analysis" / "frozen" / "current.json")["campaign_id"], campaign.name)
                low_adherence = dict(report, schema_valid_response_rate=0.97)
                with self.assertRaises(ValueError):
                    evaluator.select_final(receipt, low_adherence)
                # A second frozen experiment can reuse the selected method with a final-data tag.
                final_experiment, _ = prepare_experiment(private, {"retained": root / "ghidra" / "output" / "retained"},
                                                          root / "final.json", "synthetic-final", False)
                _, final_hash = load_experiment(final_experiment)
                final_records = [p for p in records if p.parent.name == "retained"]
                with patch.object(runner, "HERE", root / "llm_analysis"):
                    final_campaign = prepare(final_records, root / "runtime.json", root / "campaigns", config(),
                                             development_data=False, experiment_sha256=final_hash)
                final_manifest = verify(final_campaign)
                final_flight = {"records": {h: {"prompt_tokens": 100, "fits_context": True} for h in final_manifest["record_hashes"]}}
                save(final_campaign / "preflight.json", final_flight)
                for job in final_manifest["schedule"]:
                    execute_run(final_campaign, job, final_manifest, final_flight, exchange_fn=transport, idle_fn=lambda c: None)
                export(final_campaign)
                final_report = evaluator.check(final_campaign, final_experiment)
                self.assertFalse(final_report["development_data"])
                self.assertEqual(final_report["overall"]["observations"], 8)
                self.assertEqual(final_report["symbol_comparisons"], [])
                self.assertEqual(final_report["paired_run_symbol_comparisons"], [])
                final_receipt = evaluator.freeze(final_campaign, final_report, final_experiment)
                self.assertNotEqual(receipt["campaign_id"], final_receipt["campaign_id"])
                self.assertEqual(receipt["method_id"], final_receipt["method_id"])
                self.assertEqual(evaluator.freeze(campaign, report, experiment), receipt)
                with self.assertRaises(ValueError):
                    evaluator.check(final_campaign, experiment)
                # A matrix tamper must fail even when its new bytes have a matching hash file.
                wrong = load(final_experiment); wrong["observations"].pop(); save(final_experiment, wrong)
                from llm_analysis.common import file_hash
                write(final_experiment.with_suffix('.json.sha256'), (file_hash(final_experiment)+'\n').encode())
                with self.assertRaises(ValueError):
                    load_experiment(final_experiment)
                write(root / "llm_analysis" / "results" / campaign.name / "predictions.json", b"[]")
                with self.assertRaises(ValueError):
                    evaluator.freeze(campaign, report, experiment)
            raw = next(campaign.glob("runs/*/attempt-1/response.body"))
            write(raw, b"corrupt")
            with self.assertRaises(ValueError):
                evaluator.check(campaign, experiment)

    def test_abstention_components(self):
        rows = []
        for positive in (True, False):
            for classification in ("vulnerable", "not_vulnerable", "uncertain"):
                rows.append({"positive": positive, "classification": classification, "failure_count": 0,
                             "decision": "abstain" if classification == "uncertain" else "correct"})
        binary = evaluator.metrics(rows)["binary_alert"]
        self.assertEqual(binary["TN_from_abstention"], 1)
        self.assertEqual(binary["FN_from_abstention"], 1)
        self.assertEqual(binary["TN_from_not_vulnerable"], 1)
        self.assertEqual(binary["FN_from_not_vulnerable"], 1)
        self.assertEqual(binary["TN"], binary["TN_from_abstention"] + binary["TN_from_not_vulnerable"])
        self.assertEqual(binary["FN"], binary["FN_from_abstention"] + binary["FN_from_not_vulnerable"])
