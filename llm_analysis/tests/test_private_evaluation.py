"""Synthetic end-to-end tests for the private join, scores, and release receipt."""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from evaluation import check_llm_predictions as evaluator
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
                writer = csv.DictWriter(f, fieldnames=["sample_id", "optimization", "ground_truth", "cwe"], delimiter="\t")
                writer.writeheader()
                for sid in range(1, 5):
                    for opt in ("O0", "O2"):
                        writer.writerow({"sample_id": f"sample_{sid:04d}", "optimization": opt,
                                         "ground_truth": "vulnerable" if sid in (1, 3) else "not_vulnerable",
                                         "cwe": "CWE-121" if sid <= 2 else "CWE-122"})
            save(root / "runtime.json", {"artifacts": {}})
            campaign = prepare(records, root / "runtime.json", root / "campaigns", config())
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
                report = evaluator.check(campaign)
                self.assertEqual(report["scheduled_runs"], 48)
                self.assertEqual(report["overall"]["coverage"], 1)
                self.assertEqual(report["overall"]["selective_accuracy"], 0.5)
                self.assertEqual(report["overall"]["binary_alert"]["FN"], 8)
                self.assertIsNone(report["overall"]["binary_alert"]["precision"])
                receipt = evaluator.freeze(campaign, report)
                self.assertTrue((root / receipt["archive_path"]).is_file())
                self.assertEqual(evaluator.freeze(campaign, report), receipt)
                write(root / "llm_analysis" / "results" / "predictions.json", b"[]")
                with self.assertRaises(ValueError):
                    evaluator.freeze(campaign, report)
            raw = next(campaign.glob("runs/*/attempt-1/response.body"))
            write(raw, b"corrupt")
            with self.assertRaises(ValueError):
                evaluator.check(campaign)
