#!/usr/bin/env python3
"""PRIVATE Phase F3: acceptance checks on the final-v1 static and LLM evidence.

Reads the private experiment only to verify the join. It computes no accuracy, coverage,
alert or error-rate metric; every number it reports is a count of records, runs or files.
Exit status is nonzero if any check fails.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from evaluation.check_static_predictions import CLASSES, FIELDS, RULES, isolation_errors
from evaluation.prepare_llm_experiment import load_experiment
from llm_analysis.build_prompt import build_prompt, project
from llm_analysis.common import decode, digest, encode, file_hash, load, method_files, now, save
from llm_analysis.history import replay_campaign

STATIC = ROOT / "results" / "final-v1" / "static"
LLM = ROOT / "results" / "final-v1" / "llm"
OPERATIONAL = {"timeout", "transport_error", "interrupted", "http_error", "context_overflow"}
OUTPUT_FAILURES = {"length_limit", "empty_response", "invalid_json", "schema_invalid", "evidence_invalid", "response_invalid"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--campaign", required=True, type=Path)
    ap.add_argument("--experiment", default=ROOT / "evaluation/experiments/final.json", type=Path)
    ap.add_argument("--output", default=ROOT / "results/final-v1/acceptance.json", type=Path)
    args = ap.parse_args()
    campaign = args.campaign.resolve()
    checks, errors = [], []

    def check(name, ok, detail=None):
        checks.append({"check": name, "passed": bool(ok), "detail": detail})
        if not ok:
            errors.append(f"{name}: {detail}")

    experiment, experiment_hash = load_experiment(args.experiment)
    observations = [o for o in experiment["observations"] if o["inference_eligible"]]
    eliminated = [o for o in experiment["observations"] if not o["inference_eligible"]]
    expected_hashes = {o["record_sha256"] for o in observations}
    by_hash = {}
    for o in observations:
        by_hash.setdefault(o["record_sha256"], []).append(o["observation_id"])
    check("eligible and eliminated observations cover the planned matrix",
          len(observations) + len(eliminated) == len(experiment["observations"]) == 320
          and len(observations) == 216 and len(eliminated) == 104,
          {"eligible": len(observations), "eliminated": len(eliminated), "distinct_records": len(expected_hashes)})

    # ---------------- static ----------------
    execution = load(STATIC / "execution.json")
    predictions = load(STATIC / "predictions.json")
    check("static output hash matches execution log", file_hash(STATIC / "predictions.json") == execution["output"]["sha256"])
    check("static analyzer and rules match the corpus freeze", execution["matches_corpus_freeze"])
    pred_by_hash = {p["record_sha256"]: p for p in predictions}
    check("one static prediction per distinct record, none extra or duplicated",
          len(pred_by_hash) == len(predictions) == len(expected_hashes) and set(pred_by_hash) == expected_hashes,
          {"predictions": len(predictions), "records": len(expected_hashes)})
    check("static input records are exactly the blinded records",
          set(execution["input_records"]) == expected_hashes)
    known_rules = set(re.findall(r"^\| `([a-z_]+)` \|", RULES.read_text(), re.M))
    bad = []
    for p in predictions:
        c, rules = p.get("classification"), p.get("triggered_rules")
        if (set(p) != FIELDS or c not in CLASSES or not p["evidence"] or not rules or not set(rules) <= known_rules
                or (c == "vulnerable") != (p["predicted_cwe"] in ("CWE-121", "CWE-122"))
                or (c != "vulnerable" and p["predicted_cwe"] is not None)):
            bad.append(p.get("record_sha256"))
    check("static predictions satisfy the documented contract and rule names", not bad, bad[:3])
    sample_ids = {o["record_sha256"]: o["sample_id"] for o in observations}
    check("static sample_id echoes each record", all(pred_by_hash[h]["sample_id"] == s for h, s in sample_ids.items()))
    check("every uncertain static result carries a structured reason (rule name and evidence)",
          all(p["triggered_rules"] and p["evidence"] for p in predictions if p["classification"] == "uncertain"),
          dict(Counter(r for p in predictions if p["classification"] == "uncertain" for r in p["triggered_rules"])))
    check("static analyzer is import/string isolated from private data", not isolation_errors(), isolation_errors())
    check("static execution log lists no private file", execution["private_files_opened_by_this_runner"] == [])
    with tempfile.TemporaryDirectory() as tmp:
        again = Path(tmp) / "p.json"
        files = [ROOT / "evaluation/experiments/final.inputs" / p for p in
                 load(ROOT / "evaluation/experiments/final.inputs/manifest.json")["record_paths"]]
        for label, ordering in (("forward", files), ("reversed", list(reversed(files)))):
            done = subprocess.run([sys.executable, str(ROOT / "static_analysis/analyze.py"), *map(str, ordering), "-o", str(again)],
                                  cwd=ROOT, capture_output=True)
            check(f"static rerun is byte-identical ({label} input order)",
                  done.returncode == 0 and file_hash(again) == execution["output"]["sha256"])

    # ---------------- LLM ----------------
    manifest = load(campaign / "manifest.json")
    pointer = load(ROOT / "llm_analysis/frozen/current.json")
    check("campaign uses the frozen selected method and unchanged method files",
          manifest["method_id"] == pointer["method_id"] and manifest["method"]["files"] == method_files())
    check("campaign is final-split and bound to this experiment",
          manifest["development_data"] is False and manifest["metadata"]["experiment_sha256"] == experiment_hash)
    check("campaign record set equals the eligible distinct records", set(manifest["record_hashes"]) == expected_hashes)
    check("campaign directory holds no private experiment or label files",
          not any(p.name in {"final.json", "oracle.jsonl"} or "oracle" in p.name for p in campaign.rglob("*") if p.is_file()))

    _, runs, aggregates = replay_campaign(campaign)  # raw-response, request, parser and attempt audit
    check("offline replay verified request isolation, raw hashes, parsing and attempts", True, {"runs": len(runs)})
    check("exported run_results and predictions equal replay",
          load(campaign / "run_results.json") == runs and load(campaign / "predictions.json") == aggregates)
    listed = dict(reversed(line.split("  ", 1)) for line in (campaign / "checksums.sha256").read_text().splitlines())
    actual = {str(p.relative_to(campaign)) for p in campaign.rglob("*") if p.is_file() and p.name not in {"checksums.sha256", ".lock"}}
    check("campaign checksum manifest covers every artifact and matches",
          set(listed) == actual and all(file_hash(campaign / n) == h for n, h in listed.items()))
    check("no temporary or partial files remain", not list(campaign.rglob(".pending-*")))

    run_ids = [r["run_id"] for r in runs]
    check("no duplicate run identifiers", len(run_ids) == len(set(run_ids)) == len(manifest["schedule"]) == 528)
    per_record = Counter(r["record_sha256"] for r in runs)
    check("every distinct record has exactly three outcomes, repetitions 1-3",
          set(per_record) == expected_hashes and set(per_record.values()) == {3}
          and all({r["repetition"] for r in runs if r["record_sha256"] == h} == {1, 2, 3} for h in expected_hashes))
    statuses = Counter(r["status"] for r in runs)
    check("every run is valid or an explicit classified failure",
          set(statuses) <= {"valid"} | OPERATIONAL | OUTPUT_FAILURES, dict(statuses))
    check("every aggregate has three run references and one entry per record",
          len(aggregates) == len(expected_hashes) and all(len(a["run_references"]) == 3 for a in aggregates))

    # prompts: stateless single-message requests, hash and content match the frozen preflight/experiment
    preflight = load(campaign / "preflight.json")
    drift, history, leaks = [], [], []
    private_tokens = {o[k] for o in experiment["observations"] for k in ("sample_id", "pair_id", "observation_id")}
    for r in runs:
        h = r["record_sha256"]
        request_path = campaign / "runs" / r["run_id"] / "request.json"
        payload = decode(request_path.read_bytes())
        if file_hash(request_path) != r["request_sha256"]:
            drift.append(r["run_id"])
        if len(payload["messages"]) != 1 or payload["messages"][0]["role"] != "user" or payload.get("cache_prompt") is not False:
            history.append(r["run_id"])
        if payload["messages"][0]["content"] != build_prompt((campaign / "records" / f"{h}.json").read_bytes()):
            drift.append(r["run_id"])
        text = request_path.read_text()
        if any(t in text for t in private_tokens) or re.search(r"retained|stripped|ground_truth", text):
            leaks.append(r["run_id"])
    check("every request hash and prompt content match the stored record", not drift, drift[:3])
    check("every request is one fresh user message with no history or cache", not history, history[:3])
    check("no request contains a private identifier or label", not leaks, leaks[:3])
    expected_prompt = {o["record_sha256"]: o["rendered_prompt_sha256"] for o in observations}
    check("rendered prompt hash per record equals the frozen experiment value",
          all(preflight["records"][h]["rendered_prompt_sha256"] == v for h, v in expected_prompt.items()))
    check("every record fit the context at preflight", all(v["fits_context"] for v in preflight["records"].values()))
    check("every (record, repetition) has exactly one run and one request",
          len({(r["record_sha256"], r["repetition"]) for r in runs}) == len(runs))
    # Distinct raw records can share a public projection (private sample_id is removed), so
    # identical requests are legitimate there, and only there. Each keeps its own run and result.
    projection = {h: digest(encode(project((campaign / "records" / f"{h}.json").read_bytes()))) for h in expected_hashes}
    groups = {}
    for r in runs:
        groups.setdefault(r["request_sha256"], []).append(r)
    repeated = {k: v for k, v in groups.items() if len(v) > 1}
    legitimate = all(len({r["record_sha256"] for r in v}) == len(v) and len({r["repetition"] for r in v}) == 1
                     and len({projection[r["record_sha256"]] for r in v}) == 1 for v in repeated.values())
    equivalent = Counter(projection.values())
    check("identical requests occur only across distinct, projection-equivalent records at the same repetition",
          legitimate and len(repeated) == 3 * sum(n > 1 for n in equivalent.values()),
          {"identical_request_groups": len(repeated), "projection_equivalent_record_groups": sum(n > 1 for n in equivalent.values())})
    check("each repetition uses one shared seed across records",
          all(len({r["seed"] for r in runs if r["repetition"] == k}) == 1 for k in (1, 2, 3)))

    # retries never replaced earlier evidence; raw attempt files are retained
    attempts = 0
    for r in runs:
        run_dir = campaign / "runs" / r["run_id"]
        found = sorted(p.name for p in run_dir.glob("attempt-*"))
        attempts += len(found)
        for name in found:
            if not (run_dir / name / "response.json").exists() or not (run_dir / name / "response.body").exists():
                errors.append(f"missing attempt evidence {r['run_id']}/{name}")
    retried = [r["run_id"] for r in runs if r["attempts"] == 2]
    check("all attempt directories retained with raw bodies", not any(e.startswith("missing attempt") for e in errors))
    check("retry history", True, {"runs_with_retry": len(retried), "http_attempts": attempts})

    # server-side cross-check: one inference task per recorded HTTP attempt that reached the server
    offsets = LLM / "pre_final_server_state" / "offsets.txt"
    log_check = "not available"
    if offsets.exists():
        start = int(offsets.read_text().split()[0])
        log = (ROOT / "llm_analysis/output/server.log").read_bytes()[start:].decode("utf-8", "replace")
        server_prompts = [int(n) for n in re.findall(r"new prompt, n_ctx_slot = \d+, n_keep = \d+, task\.n_tokens = (\d+)", log)]
        reached = sorted(((load(p)["started_at"], load(p)["http_status"], p.parent) for p in campaign.glob("runs/*/attempt-*/response.json")))
        expected_tokens = []
        for _, status, d in reached:
            body = (d / "response.body").read_bytes()
            if status == 200:
                expected_tokens.append(decode(body)["usage"]["prompt_tokens"])
        log_check = {"server_inference_tasks": len(server_prompts), "completed_http_200_attempts": len(expected_tokens)}
        check("server log shows exactly one inference task per completed attempt, in order with matching prompt tokens",
              len(server_prompts) >= len(expected_tokens) and server_prompts[:len(expected_tokens)] == expected_tokens
              and len(server_prompts) == len(reached), log_check)

    # ---------------- join ----------------
    agg_by_hash = {a["record_sha256"]: a for a in aggregates}
    joined = [(o["observation_id"], o["record_sha256"] in pred_by_hash and o["record_sha256"] in agg_by_hash) for o in observations]
    check("every eligible observation joins to one static prediction and one LLM aggregate",
          all(ok for _, ok in joined) and len(joined) == 216)
    check("repeated hashes map to multiple observations without loss",
          sum(len(v) for v in by_hash.values()) == 216 and Counter(len(v) for v in by_hash.values()) == {1: 136, 2: 40},
          dict(Counter(len(v) for v in by_hash.values())))
    check("eliminated observations have no hash, prediction or run",
          all(o["record_sha256"] is None for o in eliminated))
    check("expected row counts for later tables", True, {
        "raw_llm_rows": 216 * 3, "condition_rows": 216 * 2, "non_analyzable_rows": 104})

    report = {"phase": "F3", "checked_at": now(), "campaign_id": manifest["campaign_id"], "method_id": manifest["method_id"],
              "experiment_sha256": experiment_hash, "run_statuses": dict(sorted(statuses.items())),
              "server_log_cross_check": log_check, "checks": checks, "failed": errors,
              "metrics_computed": False,
              "limits": ["LLM determinism is not claimed: GPU generation can differ across runs; replay of saved raw responses is deterministic.",
                         "The static analyzer's non-access to private data is shown by its import/string isolation check, its input list and its logged file set, not by an OS-level sandbox.",
                         "LLM non-access is shown by the blinded manifest, the stored requests and the campaign file set, not by tracing the runner process."]}
    save(args.output, report)
    for c in checks:
        print(("PASS " if c["passed"] else "FAIL ") + c["check"])
    print(f"{'ACCEPTED' if not errors else 'REJECTED'}: {sum(c['passed'] for c in checks)}/{len(checks)} checks passed")
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
