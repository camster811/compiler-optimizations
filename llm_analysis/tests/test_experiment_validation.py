"""Private source-pair contracts must hold before publishing a manifest."""
import csv
import tempfile
import unittest
from pathlib import Path

from evaluation.prepare_llm_experiment import load_experiment, prepare_experiment
from llm_analysis.common import encode, file_hash, save, write
from llm_analysis.tests.test_pipeline import record


class ExperimentValidationTests(unittest.TestCase):
    def fixture(self, root, truths):
        build = root / "build.tsv"
        conditions = {name: root / name for name in ("retained", "stripped")}
        with build.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["sample_id", "pair_id", "optimization", "ground_truth", "cwe"], delimiter="\t")
            writer.writeheader()
            for index, truth in enumerate(truths, 1):
                for optimization in ("O0", "O2"):
                    sid = f"sample_{index:04d}"
                    writer.writerow(dict(sample_id=sid, pair_id="pair_0001", optimization=optimization,
                                         ground_truth=truth, cwe="CWE-121"))
                    for directory in conditions.values():
                        public = record()
                        public["sample_id"] = sid
                        write(directory / f"{sid}_{optimization}.json", encode(public))
        return build, conditions

    def test_rejects_malformed_pairs_before_publication(self):
        for truths in (("vulnerable",), ("vulnerable", "fixed", "fixed"),
                       ("vulnerable", "vulnerable"), ("fixed", "not_vulnerable")):
            with self.subTest(truths=truths), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build, conditions = self.fixture(root, truths)
                destination = root / "experiment.json"
                with self.assertRaisesRegex(ValueError, "pair .* requires"):
                    prepare_experiment(build, conditions, destination, "synthetic")
                self.assertFalse(destination.exists())
                self.assertFalse(destination.with_suffix(".json.sha256").exists())
                self.assertFalse((root / "experiment.inputs").exists())

    def test_unique_source_members_across_variants_and_rehashed_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build, conditions = self.fixture(root, ("vulnerable", "fixed"))
            destination, _ = prepare_experiment(build, conditions, root / "experiment.json", "synthetic")
            original = destination.read_bytes()
            experiment, _ = load_experiment(destination)
            self.assertEqual(len(experiment["observations"]), 8)
            self.assertEqual(destination.read_bytes(), original)
            for observation in experiment["observations"]:
                observation["ground_truth"] = "vulnerable"
            save(destination, experiment)
            write(destination.with_suffix(".json.sha256"), (file_hash(destination) + "\n").encode())
            with self.assertRaisesRegex(ValueError, "one vulnerable and one fixed"):
                load_experiment(destination)
