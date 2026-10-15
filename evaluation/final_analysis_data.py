"""Fail-closed verification of Phase F/G evidence before Phase H aggregation."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
from evaluation import build_final_tables
from evaluation.freeze_corpus import check_receipt
from llm_analysis.common import file_hash, load
from llm_analysis.history import replay_campaign
from evaluation.final_metrics import counts, outcome

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT/'results/final-v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_checksums(campaign):
    expected = {}
    for line in (campaign/'checksums.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        path = (campaign/name).resolve()
        require(path.is_relative_to(campaign.resolve()) and name not in expected, 'invalid campaign checksum entry')
        expected[name] = digest
    actual = {str(p.relative_to(campaign)) for p in campaign.rglob('*') if p.is_file()
              and p.name not in ('checksums.sha256', '.lock')}
    require(set(expected) == actual, 'campaign artifact set mismatch')
    for name, digest in expected.items():
        require(file_hash(campaign/name) == digest, 'campaign checksum mismatch: '+name)


def load_inputs(campaign=None):
    manifest_path = BASE/'private/tables_manifest.json'
    manifest = load(manifest_path)
    campaign = (campaign or ROOT/'llm_analysis/output/campaigns'/manifest['campaign_id']).resolve()
    acceptance = load(BASE/'acceptance.json')
    require(not acceptance['failed'] and acceptance['campaign_id'] == manifest['campaign_id'] == campaign.name,
            'Phase F3 not accepted for this campaign')
    require(file_hash(BASE/'acceptance.json') == manifest['acceptance_sha256'], 'acceptance receipt drift')
    require(file_hash(campaign/'checksums.sha256') == manifest['campaign_checksums_sha256'], 'campaign manifest drift')
    with contextlib.redirect_stdout(io.StringIO()):
        check_receipt(ROOT/'datasets/final-v1')
    verify_checksums(campaign)
    experiment_path = ROOT/'evaluation/experiments/final.json'
    require(file_hash(experiment_path) == manifest['experiment_sha256'] == acceptance['experiment_sha256'],
            'experiment binding mismatch')
    require(file_hash(BASE/'static/predictions.json') == manifest['static_predictions_sha256'], 'static prediction drift')
    for name, meta in manifest['tables'].items():
        require(file_hash(BASE/'private'/name) == meta['sha256'], 'Phase G table drift: '+name)

    # Rebuild ALL six Phase G tables from frozen predictions and raw-response replay,
    # without touching the original table directory or its timestamped manifest.
    with tempfile.TemporaryDirectory() as temporary:
        out = Path(temporary)
        with patch.object(build_final_tables, 'OUT', out), \
             patch('sys.argv', ['build_final_tables.py', '--campaign', str(campaign)]), \
             contextlib.redirect_stdout(io.StringIO()):
            build_final_tables.main()
        for name, meta in manifest['tables'].items():
            require(file_hash(out/name) == meta['sha256'], 'rederived Phase G table mismatch: '+name)

    cm, runs, aggregates = replay_campaign(campaign)
    require(cm['method_id'] == manifest['method_id'], 'frozen method mismatch')
    require(runs == load(campaign/'run_results.json') and aggregates == load(campaign/'predictions.json'),
            'campaign exports do not equal frozen replay')
    conditions, raw, eliminated = [[json.loads(s) for s in (BASE/'private'/f'{name}.jsonl').read_text().splitlines()]
                                  for name in ('condition_comparison', 'llm_runs', 'non_analyzable')]
    require((len(conditions),len(raw),len(eliminated),len(runs)) == (432,648,104,528), 'unexpected final cardinality')
    require(len({r['pair_id'] for r in conditions}) == 20, 'unexpected clustering units')
    for row in conditions+raw:
        require(row['source_ground_truth'] == row['target_effect_ground_truth'], 'eligible truth views differ')
        c = counts(row)
        require(row['primary_target_effect_decision'] == outcome(row), 'three-way annotation mismatch')
        require(row['binary_alert'] == bool(c['TP']+c['FP']) and row['abstained'] == bool(c['abstain']),
                'alert or abstention annotation mismatch')
        require(row['primary_target_effect_binary_correct'] ==
                (None if row['classification'] is None else bool(c['TP']+c['TN'])),
                'nullable binary correctness annotation mismatch')
    mapping = {}
    for row in raw:
        require(row['record_sha256'] not in mapping or mapping[row['record_sha256']] == row['pair_id'],
                'shared record crosses source-program pairs')
        mapping[row['record_sha256']] = row['pair_id']
    distinct = {}
    for row in raw:
        # The representative is used only for overall request-level summaries;
        # shared requests do not inherit this observation's factor assignments.
        distinct.setdefault(row['run_id'], row)
    require(len(distinct) == 528, 'expanded rows lost distinct requests')
    # Include the original manifests, raw-evidence checksum root and experiment chain.
    paths = [manifest_path, BASE/'acceptance.json', BASE/'llm/server_final_run.log',
             BASE/'static/predictions.json', BASE/'static/execution.json',
             experiment_path, ROOT/'datasets/final-v1/private/corpus-freeze.json',
             ROOT/'datasets/final-v1/private/inputs-freeze.json', campaign/'checksums.sha256',
             campaign/'manifest.json', campaign/'predictions.json', campaign/'run_results.json']
    paths += [BASE/'private'/name for name in manifest['tables']]
    hashes = {str(p.relative_to(ROOT)): file_hash(p) for p in paths}
    return conditions, raw, list(distinct.values()), eliminated, manifest, hashes
