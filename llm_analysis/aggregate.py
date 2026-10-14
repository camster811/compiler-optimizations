"""Deterministic three-repetition votes, with operational failures retained."""
from collections import Counter
from statistics import median


def aggregate(record_hash, runs):
    if len(runs) != 3 or {r["repetition"] for r in runs} != {1, 2, 3}:
        raise ValueError("expected exactly repetitions 1, 2, 3")
    valid = [r["prediction"] for r in runs if r["status"] == "valid"]
    votes = Counter(p["classification"] for p in valid)
    winner = next((k for k, n in votes.items() if n >= 2), None)
    classification, cwe = winner or "uncertain", None
    reason = None if winner else "insufficient_matching_votes"
    if winner == "vulnerable":
        cwes = Counter(p["predicted_cwe"] for p in valid if p["classification"] == winner)
        cwe = next((k for k, n in cwes.items() if n >= 2), None)
        if cwe is None:
            classification, reason = "uncertain", "cwe_disagreement"
    elif winner == "uncertain":
        reason = "model_abstention"
    return {"record_sha256": record_hash, "classification": classification,
            "predicted_cwe": cwe, "median_confidence": median(p["confidence"] for p in valid) if valid else None,
            "valid_run_count": len(valid), "failure_count": 3 - len(valid),
            "votes": dict(sorted(votes.items())), "aggregation_reason": reason,
            "unanimous": len(valid) == 3 and len(votes) == 1,
            "run_references": [r["run_id"] for r in sorted(runs, key=lambda r: r["repetition"])]}
