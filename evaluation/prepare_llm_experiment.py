#!/usr/bin/env python3
"""PRIVATE: freeze an expected observation matrix and export blinded record inputs."""
import argparse
import csv
import os
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = Path(__file__).with_name("experiment_schema.json")
sys.path.insert(0, str(ROOT))
from llm_analysis.build_prompt import project
from llm_analysis.common import decode, digest, encode, file_hash, load, save, write


def load_experiment(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    frozen_hash = (path.with_suffix(path.suffix + ".sha256")).read_text().strip()
    if digest(raw) != frozen_hash:
        raise ValueError("private experiment manifest drift")
    experiment = decode(raw)
    validate_experiment(experiment, path.parent)
    return experiment, frozen_hash


def validate_experiment(experiment, record_directory):
    """Validate the matrix and source pairs without publishing any artifacts."""
    version = experiment.get("schema_version")
    schema = SCHEMA if version == "1.0" else SCHEMA.with_name("experiment_schema_v2.json")
    Draft202012Validator(load(schema)).validate(experiment)
    cases = [(r["sample_id"], r["optimization"]) for r in experiment["expected_matrix"]["cases"]]
    if len(cases) != len(set(cases)):
        raise ValueError("duplicate cases in expected matrix")
    expected = {(condition, sid, opt) for condition in experiment["expected_matrix"]["conditions"] for sid, opt in cases}
    observations = experiment["observations"]
    actual = {(o["condition"], o["sample_id"], o["optimization"]) for o in observations}
    if len(observations) != len(actual) or actual != expected:
        raise ValueError("observations do not equal the frozen expected matrix")
    if len({o["observation_id"] for o in observations}) != len(observations):
        raise ValueError("duplicate observation identifiers")
    facts = {}
    pair_cwes = {}
    manifestations = {}
    for o in observations:
        source_truth = o["ground_truth"] if version == "1.0" else o["source_ground_truth"]
        case_facts = (o["pair_id"], o["cwe"], source_truth)
        if o["sample_id"] in facts and facts[o["sample_id"]] != case_facts:
            raise ValueError("inconsistent truth or pair assignment across conditions")
        facts[o["sample_id"]] = case_facts
        if o["pair_id"] in pair_cwes and pair_cwes[o["pair_id"]] != o["cwe"]:
            raise ValueError("pair spans multiple CWE labels")
        pair_cwes[o["pair_id"]] = o["cwe"]
        if version == "2.0":
            key = (o["sample_id"], o["optimization"])
            manifestation = (o["binary_manifestation"], o["target_effect_ground_truth"])
            if key in manifestations and manifestations[key] != manifestation:
                raise ValueError("compiler manifestation differs across symbol conditions")
            manifestations[key] = manifestation
            if not o["inference_eligible"]:
                if (o["binary_manifestation"] != "eliminated" or o["inference_disposition"] != "proven_eliminated"
                        or o["evidence_locality"] != "not_applicable" or o["capacity_visibility"] != "not_applicable"
                        or any(o[k] is not None for k in ("record_path", "record_sha256", "target_effect_ground_truth", "prompt_tokens", "context_eligible", "rendered_prompt_sha256", "context_rejection_reason"))):
                    raise ValueError("non-inference row requires proven elimination without fabricated evidence")
                continue
            if (o["binary_manifestation"] == "eliminated" or o["target_effect_ground_truth"] is None
                    or o["inference_disposition"] != "eligible" or o["evidence_locality"] != "local"
                    or o["capacity_visibility"] not in ("explicit", "not_explicit")
                    or o["context_eligible"] is not True or o["context_rejection_reason"] is not None
                    or o["prompt_tokens"] is None or o["prompt_tokens"] + 4096 + 128 > 8192
                    or o["record_path"] is None or o["record_sha256"] is None or o["rendered_prompt_sha256"] is None):
                raise ValueError("inference row lacks qualifying local, complete-context evidence")
        record_path = (record_directory / o["record_path"]).resolve()
        raw = record_path.read_bytes()
        if digest(raw) != o["record_sha256"]:
            raise ValueError("experiment record content drift")
        project(raw)
        if decode(raw)["sample_id"] != o["sample_id"]:
            raise ValueError("record sample ID differs from private observation")
    pairs = {}
    for sample_id, (pair_id, _, ground_truth) in facts.items():
        pairs.setdefault(pair_id, {})[sample_id] = ground_truth
    for pair_id, members in sorted(pairs.items()):
        if len(members) != 2:
            raise ValueError(f"pair {pair_id} requires exactly two unique source cases; found {len(members)}")
        if set(members.values()) != {"vulnerable", "not_vulnerable"}:
            raise ValueError(f"pair {pair_id} requires one vulnerable and one fixed source case")


def prepare_experiment(build_manifest, conditions, destination, dataset_id, development_data=True, *, oracle_v2=None, context_evidence=None):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError("experiment already exists; choose a new immutable manifest location")
    with Path(build_manifest).open(newline="") as f:
        cases = list(csv.DictReader(f, delimiter="\t"))
    if not cases or len({(r["sample_id"], r["optimization"]) for r in cases}) != len(cases):
        raise ValueError("empty or duplicate build cases")
    observations = []
    oracle = None
    if oracle_v2:
        from evaluation.oracle_v2 import load_oracle
        oracle = {(r["sample_id"], r["optimization"]): r for r in load_oracle(oracle_v2)}
        counts = load(context_evidence)["records"]
        if set(oracle) != {(r["sample_id"], r["optimization"]) for r in cases}:
            raise ValueError("oracle does not match build matrix")
    for condition, directory in sorted(conditions.items()):
        directory = Path(directory)
        expected = {f"{r['sample_id']}_{r['optimization']}.json" for r in cases
                    if oracle is None or oracle[(r["sample_id"], r["optimization"])]["binary_manifestation"] != "eliminated"}
        if {p.name for p in directory.glob("*.json")} != expected:
            raise ValueError(f"record file set differs for condition {condition}")
        for r in sorted(cases, key=lambda r: (r["sample_id"], r["optimization"])):
            if oracle is not None:
                truth = oracle[(r["sample_id"], r["optimization"])]
                eligible = truth["binary_manifestation"] != "eliminated"
                if truth["binary_manifestation"] == "unresolved": raise ValueError("unresolved final oracle")
                if truth["source_ground_truth"] != r["ground_truth"] or truth["pair_id"] != r["pair_id"] or truth["cwe"] != r["cwe"]:
                    raise ValueError("oracle/build source truth disagreement")
                record = directory / f"{r['sample_id']}_{r['optimization']}.json"
                h = file_hash(record) if eligible else None
                fit = counts[h] if eligible else {}
                observations.append({"observation_id": f"{condition}:{r['sample_id']}:{r['optimization']}",
                    "sample_id": r["sample_id"], "pair_id": r["pair_id"], "optimization": r["optimization"],
                    "condition": condition, "cwe": r["cwe"], "source_ground_truth": truth["source_ground_truth"],
                    "binary_manifestation": truth["binary_manifestation"], "target_effect_ground_truth": truth["target_effect_ground_truth"],
                    "inference_eligible": eligible, "inference_disposition": "eligible" if eligible else "proven_eliminated",
                    "evidence_locality": truth["evidence_locality"], "capacity_visibility": truth["capacity_visibility"],
                    "record_path": os.path.relpath(record.resolve(), destination.parent) if eligible else None, "record_sha256": h,
                    "prompt_tokens": fit.get("prompt_tokens"), "context_eligible": fit.get("fits_context"),
                    "context_rejection_reason": fit.get("context_rejection_reason"), "rendered_prompt_sha256": fit.get("rendered_prompt_sha256")})
                continue
            record = directory / f"{r['sample_id']}_{r['optimization']}.json"
            raw = record.read_bytes()
            project(raw)
            ground_truth = {"vulnerable": "vulnerable", "fixed": "not_vulnerable", "not_vulnerable": "not_vulnerable"}.get(r["ground_truth"])
            if ground_truth is None:
                raise ValueError("unknown build ground-truth value")
            observations.append({"observation_id": f"{condition}:{r['sample_id']}:{r['optimization']}",
                                 "sample_id": r["sample_id"], "pair_id": r["pair_id"], "optimization": r["optimization"],
                                 "condition": condition, "cwe": r["cwe"], "ground_truth": ground_truth,
                                 "record_path": os.path.relpath(record.resolve(), destination.parent), "record_sha256": digest(raw)})
    experiment = {"schema_version": "1.0", "dataset_id": dataset_id, "development_data": development_data,
                  "expected_matrix": {"conditions": sorted(conditions), "cases": [
                      {"sample_id": r["sample_id"], "optimization": r["optimization"]}
                      for r in sorted(cases, key=lambda r: (r["sample_id"], r["optimization"]))]}, "observations": observations}
    if oracle is not None:
        experiment.update(schema_version="2.0", oracle_sha256=file_hash(oracle_v2), context_evidence_sha256=file_hash(context_evidence))
    validate_experiment(experiment, destination.parent)
    save(destination, experiment, immutable=True)
    write(destination.with_suffix(destination.suffix + ".sha256"), (file_hash(destination) + "\n").encode(), immutable=True)
    _, experiment_hash = load_experiment(destination)
    blind_root = destination.parent / (destination.stem + ".inputs")
    records = {}
    for o in observations:
        if not o.get("inference_eligible", True): continue
        records[o["record_sha256"]] = (destination.parent / o["record_path"]).read_bytes()
    for h, raw in sorted(records.items()):
        write(blind_root / "records" / f"{h}.json", raw, immutable=True)
    save(blind_root / "manifest.json", {"record_paths": [f"records/{h}.json" for h in sorted(records)],
                                       "experiment_sha256": experiment_hash, "development_data": development_data}, immutable=True)
    return destination, blind_root / "manifest.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build-manifest", type=Path, required=True)
    ap.add_argument("--condition", action="append", required=True, help="NAME=DIRECTORY, repeat for every expected condition")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--dataset-id", required=True)
    ap.add_argument("--data-split", choices=["development", "final"], default="development")
    ap.add_argument("--oracle-v2", type=Path)
    ap.add_argument("--context-evidence", type=Path)
    args = ap.parse_args()
    conditions = {}
    for item in args.condition:
        name, path = item.split("=", 1)
        if not name or name in conditions:
            ap.error("empty or duplicate condition")
        conditions[name] = Path(path)
    if bool(args.oracle_v2) != bool(args.context_evidence): ap.error("oracle-v2 and context-evidence must be supplied together")
    experiment, blind = prepare_experiment(args.build_manifest, conditions, args.output, args.dataset_id, args.data_split == "development",
                                         oracle_v2=args.oracle_v2, context_evidence=args.context_evidence)
    print(f"Private experiment: {experiment}\nBlinded inputs: {blind}")


if __name__ == "__main__":
    main()
