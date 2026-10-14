#!/usr/bin/env python3
"""Validate and score static_analysis/output/predictions.json (PRIVATE: reads ground truth).

Observations vs predictions
  An observation is one experimental input: (condition, case/optimization tag). A prediction
  is keyed by record_sha256, a content identifier. The evaluator maps each hash to one or more
  observations, so byte-identical records from different conditions stay separate here even
  though the analyzer (which never sees the condition) emits one prediction for them.

Checks
  * exactly 16 observations (8 retained + 8 stripped); every observation's record hash has a
    prediction and every prediction maps to at least one observation
  * each prediction has exactly the documented fields and value types, its sample_id matches
    every record it maps to, and its triggered_rules are documented in rules.md
  * analyze.py is isolated: whitelisted imports only, no oracle/ground-truth/path strings
  * the predictions reproduce when analyze.py is rerun on the records in reverse order
Then prints two informational views (development-set sanity results; the rules were written
after inspecting these cases):
  * three-way descriptive view with coverage and selective accuracy
  * binary alert view: vulnerable = alert; not_vulnerable and uncertain = no alert
"""
import ast
import csv
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANALYZER = ROOT / "static_analysis" / "analyze.py"
RULES = ROOT / "static_analysis" / "rules.md"
PREDICTIONS = ROOT / "static_analysis" / "output" / "predictions.json"
MANIFEST = ROOT / "build" / "artifacts" / "private" / "build_manifest.tsv"
FIELDS = {"record_sha256", "sample_id", "classification", "predicted_cwe", "evidence", "triggered_rules"}
CLASSES = {"vulnerable", "not_vulnerable", "uncertain"}
ALLOWED_IMPORTS = {"argparse", "hashlib", "json", "re", "sys", "pathlib"}
FORBIDDEN_STRINGS = re.compile(
    r"oracle|manifest|ground|truth|\.csv|\.tsv|logs|run\.json|build/|source/|retained|stripped|optimization",
    re.I)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def isolation_errors():
    errs, tree = [], ast.parse(ANALYZER.read_text())
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
                  and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods = {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods = {(n.module or "").split(".")[0]}
        else:
            mods = set()
        for m in mods - ALLOWED_IMPORTS:
            errs.append(f"analyze.py imports {m!r}")
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings:
            if m := FORBIDDEN_STRINGS.search(n.value):
                errs.append(f"analyze.py string literal mentions {m.group(0)!r}")
    return errs


def ratio(num, den):
    return num / den if den else float("nan")


def pct(x):
    return "n/a" if x != x else f"{100 * x:.1f}%"


def main():
    errors = []
    predictions = json.loads(PREDICTIONS.read_text())
    known_rules = set(re.findall(r"^\| `([a-z_]+)` \|", RULES.read_text(), re.M))

    # observation = (condition, tag); hash -> [observation, ...]
    observations, by_hash = {}, defaultdict(list)
    for cond in ("retained", "stripped"):
        for p in sorted((ROOT / "ghidra" / "output" / cond).glob("*.json")):
            observations[(cond, p.stem)] = (sha256(p), json.loads(p.read_text()))
            by_hash[sha256(p)].append((cond, p.stem))
    if len(observations) != 16:
        errors.append(f"expected 16 observations, found {len(observations)}")

    pred_by_hash = {}
    for p in predictions:
        h = p.get("record_sha256")
        if h in pred_by_hash:
            errors.append(f"duplicate prediction for record_sha256 {str(h)[:8]}")
        pred_by_hash[h] = p
    for h in set(by_hash) - set(pred_by_hash):
        errors.append(f"no prediction for {by_hash[h]}")
    for h in set(pred_by_hash) - set(by_hash):
        errors.append(f"prediction {str(h)[:8]} maps to no observation")
    if len(predictions) != len(by_hash):
        errors.append(f"{len(predictions)} predictions for {len(by_hash)} distinct record hashes")
    shared = {h: o for h, o in by_hash.items() if len(o) > 1}
    if shared:
        print(f"[NOTE] {len(shared)} hash(es) map to several observations: {shared}")

    for p in predictions:
        tag = (p.get("sample_id"), str(p.get("record_sha256"))[:8])
        if set(p) != FIELDS:
            errors.append(f"{tag}: fields {sorted(set(p) ^ FIELDS)} differ")
            continue
        if p["classification"] not in CLASSES:
            errors.append(f"{tag}: classification {p['classification']!r}")
        if p["classification"] == "vulnerable" and p["predicted_cwe"] not in ("CWE-121", "CWE-122"):
            errors.append(f"{tag}: vulnerable needs CWE-121/122, got {p['predicted_cwe']!r}")
        if p["classification"] != "vulnerable" and p["predicted_cwe"] is not None:
            errors.append(f"{tag}: non-vulnerable prediction has a CWE")
        if not (isinstance(p["evidence"], list) and p["evidence"] and all(isinstance(e, str) and e for e in p["evidence"])):
            errors.append(f"{tag}: evidence must be a nonempty list of strings")
        if not (isinstance(p["triggered_rules"], list) and p["triggered_rules"]
                and set(p["triggered_rules"]) <= known_rules):
            errors.append(f"{tag}: triggered_rules {p['triggered_rules']} not documented in rules.md")
        for obs in by_hash.get(p["record_sha256"], []):
            if observations[obs][1]["sample_id"] != p["sample_id"]:
                errors.append(f"{tag}: sample_id differs from record {obs}")

    errors += isolation_errors()

    with tempfile.TemporaryDirectory() as tmp:
        again = Path(tmp) / "again.json"
        files = [str(p) for c in ("stripped", "retained")
                 for p in sorted((ROOT / "ghidra" / "output" / c).glob("*.json"), reverse=True)]
        subprocess.run([sys.executable, str(ANALYZER), *files, "-o", str(again)], check=True, capture_output=True)
        if json.loads(again.read_text()) != predictions:
            errors.append("predictions are not reproducible / depend on input order")

    for e in errors:
        print("[FAIL]", e)
    print(f"{'FAIL' if errors else 'OK'}: {len(predictions)} predictions, {len(observations)} observations, {len(errors)} errors")
    if errors:
        sys.exit(1)

    # --- scoring (private ground truth) ------------------------------------------------
    truth = {(r["sample_id"], r["optimization"]): r
             for r in csv.DictReader(MANIFEST.open(newline=""), delimiter="\t")}
    rows = []
    for (cond, tag), (h, _) in sorted(observations.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        sid, opt = tag.rsplit("_", 1)
        t, p = truth[(sid, opt)], pred_by_hash[h]
        positive = t["ground_truth"] == "vulnerable"
        if p["classification"] == "uncertain":
            decision = "abstain"
        elif positive:
            decision = "correct" if p["classification"] == "vulnerable" and p["predicted_cwe"] == t["cwe"] else "incorrect"
        else:
            decision = "correct" if p["classification"] == "not_vulnerable" else "incorrect"
        rows.append((tag, cond, opt, positive, p["classification"], p["predicted_cwe"], decision))

    print("\n=== per observation ===")
    for tag, cond, _, positive, cls, cwe, decision in rows:
        print("  %-14s %-9s truth=%-14s pred=%-14s %-8s %s" % (
            tag, cond, "vulnerable" if positive else "not_vulnerable", cls, cwe, decision))

    def three_way(subset):
        c = Counter(r[6] for r in subset)
        decided = c["correct"] + c["incorrect"]
        return (f"correct={c['correct']} incorrect={c['incorrect']} abstain={c['abstain']} | "
                f"coverage={c['correct'] + c['incorrect']}/{len(subset)} ({pct(ratio(decided, len(subset)))}) "
                f"abstention={pct(ratio(c['abstain'], len(subset)))} "
                f"selective_accuracy={pct(ratio(c['correct'], decided))}")

    print("\n=== three-way descriptive view (selective accuracy, not ordinary accuracy) ===")
    print("  all           ", three_way(rows))
    for label, idx in (("opt", 2), ("condition", 1)):
        for value in sorted({r[idx] for r in rows}):
            print(f"  {label}={value:<9}", three_way([r for r in rows if r[idx] == value]))

    def binary(subset):
        tp = sum(r[3] and r[4] == "vulnerable" for r in subset)
        fn = sum(r[3] and r[4] != "vulnerable" for r in subset)
        fp = sum((not r[3]) and r[4] == "vulnerable" for r in subset)
        tn = sum((not r[3]) and r[4] != "vulnerable" for r in subset)
        tpr, tnr = ratio(tp, tp + fn), ratio(tn, tn + fp)
        precision = ratio(tp, tp + fp)
        f1 = ratio(2 * precision * tpr, precision + tpr) if precision == precision and tpr == tpr else float("nan")
        return tp, tn, fp, fn, {
            "accuracy": ratio(tp + tn, len(subset)), "balanced_accuracy": (tpr + tnr) / 2 if tpr == tpr and tnr == tnr else float("nan"),
            "precision": precision, "recall": tpr, "F1": f1,
            "FPR": ratio(fp, fp + tn), "FNR": ratio(fn, fn + tp)}

    tp, tn, fp, fn, m = binary(rows)
    abstained_negatives = sum((not r[3]) and r[4] == "uncertain" for r in rows)
    print("\n=== binary alert view: vulnerable=alert; not_vulnerable and uncertain=no alert ===")
    print(f"  TP={tp} TN={tn} FP={fp} FN={fn}  (TN includes {abstained_negatives} abstentions on non-vulnerable cases;"
          f" FN includes {sum(r[3] and r[4] == 'uncertain' for r in rows)} abstentions on vulnerable cases)")
    print("  " + "  ".join(f"{k}={pct(v)}" for k, v in m.items()))
    print("  false negatives:", [(r[0], r[1]) for r in rows if r[3] and r[4] != "vulnerable"])
    print("  development-set sanity results: the rules were written after inspecting these cases.")

    same = True
    for tag in {r[0] for r in rows}:
        keys = {(pred_by_hash[observations[(c, tag)][0]]["classification"],
                 pred_by_hash[observations[(c, tag)][0]]["predicted_cwe"],
                 tuple(pred_by_hash[observations[(c, tag)][0]]["triggered_rules"])) for c in ("retained", "stripped")}
        same &= len(keys) == 1
    print("\n  The symbol-insensitive baseline produced identical retained and stripped predictions in the pilot:", same)


if __name__ == "__main__":
    if "--experiment" in sys.argv:
        import argparse
        sys.path.insert(0, str(ROOT))
        from evaluation.validate_static_dataset import validate
        ap = argparse.ArgumentParser(description="Manifest-driven validation without scoring")
        ap.add_argument("--experiment", required=True, type=Path)
        ap.add_argument("--predictions", required=True, type=Path)
        ap.add_argument("--validate-only", action="store_true", required=True)
        args = ap.parse_args()
        validate(args.experiment.resolve(), args.predictions.resolve())
    else:
        main()
