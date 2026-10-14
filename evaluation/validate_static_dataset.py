"""Private dataset static acceptance, without accuracy or coverage scores."""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from evaluation.check_static_predictions import ROOT, ANALYZER, RULES, FIELDS, CLASSES, isolation_errors
from evaluation.prepare_llm_experiment import load_experiment
from llm_analysis.common import file_hash, load, save


def validate(experiment_path, predictions_path):
    experiment, h = load_experiment(experiment_path)
    observations = [o for o in experiment['observations'] if o.get('inference_eligible', True)]
    files = sorted({(experiment_path.parent / o['record_path']).resolve() for o in observations})
    if not files: raise ValueError('no eligible records for static validation')
    errors = isolation_errors()
    known = set(re.findall(r'^\| `([a-z_]+)` \|', RULES.read_text(), re.M))
    subprocess.run([sys.executable, str(ANALYZER), *map(str, files), '-o', str(predictions_path)], check=True, capture_output=True)
    predictions = load(predictions_path)
    by_hash = {p['record_sha256']: p for p in predictions}
    if len(by_hash) != len(predictions) or set(by_hash) != {o['record_sha256'] for o in observations}:
        errors.append('predictions differ from eligible record hashes')
    for p in predictions:
        if (set(p) != FIELDS or p['classification'] not in CLASSES or not p['evidence']
                or not all(isinstance(e, str) and e for e in p['evidence']) or not p['triggered_rules'] or not set(p['triggered_rules']) <= known):
            errors.append('invalid static output contract')
        if (p['classification'] == 'vulnerable' and p['predicted_cwe'] not in ('CWE-121', 'CWE-122')) or (p['classification'] != 'vulnerable' and p['predicted_cwe'] is not None):
            errors.append('invalid static CWE relationship')
    for o in observations:
        if by_hash[o['record_sha256']]['sample_id'] != o['sample_id']: errors.append('static sample mismatch')
    with tempfile.TemporaryDirectory() as temporary:
        reversed_path = Path(temporary) / 'reversed.json'
        subprocess.run([sys.executable, str(ANALYZER), *map(str, reversed(files)), '-o', str(reversed_path)], check=True, capture_output=True)
        if load(reversed_path) != predictions: errors.append('static results depend on record order')
    if errors: raise ValueError('; '.join(errors))
    receipt = {'experiment_sha256': h, 'planned_observations': len(experiment['observations']),
               'eligible_observations': len(observations), 'distinct_records': len(predictions),
               'analyzer_sha256': file_hash(ANALYZER), 'rules_sha256': file_hash(RULES),
               'predictions_sha256': file_hash(predictions_path), 'validation_only': True, 'accuracy_computed': False}
    save(predictions_path.with_suffix('.validation.json'), receipt)
    print(f'Static validation only: {len(predictions)} predictions; {len(observations)} eligible / {len(experiment["observations"])} planned observations')
    return receipt


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--experiment', required=True, type=Path); ap.add_argument('--predictions', required=True, type=Path)
    args = ap.parse_args(); validate(args.experiment.resolve(), args.predictions.resolve())
