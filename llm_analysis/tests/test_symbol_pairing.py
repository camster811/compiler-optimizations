"""Shared-seed symbol comparisons preserve valid abstentions and failed runs."""
import copy
import unittest

from evaluation.check_llm_predictions import paired_symbol_runs
from llm_analysis.tests.test_pipeline import prediction


class SymbolPairingTests(unittest.TestCase):
    def fixture(self):
        observations = [dict(sample_id="sample_0001", pair_id="pair_0001", optimization="O0",
                             condition=condition, record_sha256=condition) for condition in ("retained", "stripped")]
        runs = [dict(record_sha256=condition, repetition=repetition, seed=100 + repetition,
                     run_id=f"{condition}-{repetition}", status="valid", prediction=prediction("not_vulnerable"))
                for condition in ("retained", "stripped") for repetition in (1, 2, 3)]
        return observations, runs

    def test_agreement_disagreement_abstention_and_unavailable(self):
        observations, runs = self.fixture()
        runs[3]["prediction"] = prediction("vulnerable", "CWE-121")
        runs[4]["prediction"] = prediction("uncertain")
        runs[5].update(status="invalid_json", prediction=None)
        pairs = paired_symbol_runs(observations, runs, True)
        self.assertEqual(len(pairs), 3)
        self.assertFalse(pairs[0]["same_classification_and_cwe"])
        self.assertEqual(pairs[1]["stripped"]["classification"], "uncertain")
        self.assertTrue(pairs[1]["both_valid"])
        self.assertFalse(pairs[2]["both_valid"])
        self.assertIsNone(pairs[2]["same_classification_and_cwe"])
        self.assertIsNone(pairs[2]["stripped"]["classification"])
        self.assertIsNone(pairs[2]["confidence_difference_retained_minus_stripped"])
        self.assertEqual(pairs[0]["retained"]["run_id"], "retained-1")
        self.assertEqual(paired_symbol_runs(observations[:1], runs, True), [])
        self.assertEqual(paired_symbol_runs(observations, runs, False), [])

    def test_seed_mismatch_missing_and_duplicate_repetitions(self):
        observations, runs = self.fixture()
        mismatch = copy.deepcopy(runs)
        mismatch[3]["seed"] += 1
        for invalid, message in ((mismatch, "seed mismatch"), (runs[:-1], "missing repetition"),
                                 (runs + [runs[0]], "duplicate repetition")):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                paired_symbol_runs(observations, invalid, True)

    def test_byte_identical_conditions_reuse_one_run(self):
        observations, runs = self.fixture()
        observations[1]["record_sha256"] = "retained"
        pairs = paired_symbol_runs(observations, runs[:3], True)
        self.assertTrue(all(pair["shared_record"] and pair["same_classification_and_cwe"] for pair in pairs))
        self.assertTrue(all(pair["retained"]["run_id"] == pair["stripped"]["run_id"] for pair in pairs))
        self.assertTrue(all(pair["confidence_difference_retained_minus_stripped"] == 0 for pair in pairs))
