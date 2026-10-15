#!/usr/bin/env python3
"""Phase F1: run the unchanged static analyzer on the frozen blinded final records.

The analyzer sees only the hash-named blinded records listed in the blinded manifest. The
private experiment (labels, conditions, record paths) is never opened here. Outputs are
written once under results/final-v1/static/ and never overwritten.
"""
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from llm_analysis.common import file_hash, load, now, save

ANALYZER = ROOT / "static_analysis" / "analyze.py"
RULES = ROOT / "static_analysis" / "rules.md"
MANIFEST = ROOT / "evaluation" / "experiments" / "final.inputs" / "manifest.json"
FREEZE = ROOT / "datasets" / "final-v1" / "private" / "corpus-freeze.json"
PRIOR = ROOT / "datasets" / "final-v1" / "private" / "validation" / "static_predictions.json"
OUT = ROOT / "results" / "final-v1" / "static"


def git(*args):
    return subprocess.run(["git", "--no-optional-locks", *args], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def run(files, output):
    start = now()
    p = subprocess.run([sys.executable, str(ANALYZER), *map(str, files), "-o", str(output)],
                       cwd=ROOT, capture_output=True, text=True)
    return {"argv": [sys.executable, "static_analysis/analyze.py", f"<{len(files)} blinded records>", "-o",
                     str(output.relative_to(ROOT)) if output.is_relative_to(ROOT) else "<temporary>"],
            "return_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr,
            "started_at": start, "ended_at": now()}


def main():
    if (OUT / "predictions.json").exists():
        raise SystemExit(f"{OUT / 'predictions.json'} exists; static evidence is never overwritten")
    manifest = load(MANIFEST)
    files = [MANIFEST.parent / p for p in manifest["record_paths"]]
    inputs = {}
    for f in files:
        h = file_hash(f)
        if f.stem != h:
            raise SystemExit(f"blinded record name differs from content hash: {f.name}")
        inputs[h] = str(f.relative_to(ROOT))
    if len(inputs) != len(files):
        raise SystemExit("duplicate blinded records")

    summary = load(FREEZE)["summary"]
    versions = {"analyzer_sha256": file_hash(ANALYZER), "rules_sha256": file_hash(RULES)}
    if (versions["analyzer_sha256"], versions["rules_sha256"]) != (summary["static_analyzer_sha256"], summary["static_rules_sha256"]):
        raise SystemExit("analyzer or rules differ from the corpus freeze")

    dirty = git("status", "--porcelain", "--", "static_analysis/analyze.py", "static_analysis/rules.md")
    if dirty:
        raise SystemExit("analyzer or rules differ from the committed version:\n" + dirty)
    commit = git("rev-parse", "HEAD")
    last_change = git("log", "-1", "--format=%H", "--", "static_analysis/analyze.py", "static_analysis/rules.md")

    OUT.mkdir(parents=True, exist_ok=True)
    predictions_path = OUT / "predictions.json"
    first = run(files, predictions_path)
    if first["return_code"]:
        raise SystemExit(f"analyzer failed: {first['stderr']}")
    output_hash = file_hash(predictions_path)

    # Determinism: reverse input order, byte-compare. The rerun is evidence, not a replacement.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        again = Path(tmp) / "predictions.json"
        second = run(list(reversed(files)), again)
        reversed_identical = second["return_code"] == 0 and file_hash(again) == output_hash

    prior_identical = file_hash(PRIOR) == output_hash if PRIOR.exists() else None

    save(OUT / "execution.json", {
        "phase": "F1", "matches_corpus_freeze": True,
        "analyzer": {"path": "static_analysis/analyze.py", **versions, "git_head": commit,
                     "last_commit_touching_analyzer_or_rules": last_change,
                     "working_tree_clean_for_analyzer_and_rules": True},
        "python": platform.python_version(),
        "blinded_manifest_sha256": file_hash(MANIFEST),
        "input_record_count": len(inputs), "input_records": dict(sorted(inputs.items())),
        "execution": first,
        "output": {"path": "results/final-v1/static/predictions.json", "sha256": output_hash},
        "reverse_order_rerun": {"return_code": second["return_code"], "byte_identical": reversed_identical},
        "prior_validation_only_output_byte_identical": prior_identical,
        "private_files_opened_by_this_runner": [],
        "note": "Analyzer rules, thresholds and code are unchanged; no rule was added after the final corpus was frozen."},
        immutable=True)
    print(first["stdout"].strip())
    print(f"analyzer sha256 {versions['analyzer_sha256'][:12]}  output sha256 {output_hash[:12]}")
    print(f"reverse-order byte-identical: {reversed_identical}; identical to prior validation-only output: {prior_identical}")
    if not reversed_identical:
        raise SystemExit("static output depends on input order")


if __name__ == "__main__":
    main()
