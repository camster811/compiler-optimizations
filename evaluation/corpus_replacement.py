"""Whole-pair technical replacement; frozen scope and reserve order never change."""
import argparse
from pathlib import Path
from llm_analysis.common import load, save, now
from evaluation.corpus_selection import ROOT


def replace(root, candidate_id, reason, failed_conditions):
    if (root/'private/corpus-freeze.json').exists(): raise ValueError('frozen corpus cannot be reselected')
    if not reason or not failed_conditions: raise ValueError('technical reason and failed conditions required')
    original = load(root/'private/source_selection.json')
    effective_path = root/'private/effective_selection.json'
    effective = load(effective_path) if effective_path.exists() else {'selected': original['selected'], 'rejections': []}
    candidates = {c['candidate_id']:c for c in load(root/'private/candidates.json')}
    if candidate_id not in effective['selected']: raise ValueError('candidate is not an active pair')
    excluded = {r['candidate_id'] for r in effective['rejections']} | set(effective['selected'])
    replacement = next((cid for cid in original['reserve_order'] if cid not in excluded and candidates[cid]['cwe']==candidates[candidate_id]['cwe']), None)
    if replacement is None: raise ValueError('reserve exhausted: final-v1 fails acceptance; optimization scope remains fixed')
    scope_before = (root/'private/optimization_scope.json').read_bytes()
    effective['selected'] = [replacement if cid == candidate_id else cid for cid in effective['selected']]
    effective['rejections'].append({'candidate_id':candidate_id,'replacement':replacement,'reason':reason,
                                    'failed_conditions':failed_conditions,'recorded_at':now(),'whole_pair':True})
    # Preserve rejected evidence rather than leaving stale records in the active matrix.
    destination=root/'private/technical_rejections'/candidate_id
    for sample in candidates[candidate_id]['samples']:
        sid=sample['sample_id']
        for directory in [root/'ghidra/records'/c for c in ('retained','stripped')] + [root/'artifacts'/c for c in ('oracle','retained','stripped')]:
            for path in directory.glob(sid+'_O*'):
                target=destination/path.relative_to(root); target.parent.mkdir(parents=True,exist_ok=True); path.rename(target)
        if sample.get('source_path'):
            path=ROOT/sample['source_path']
            target=destination/'source'/path.name
            target.parent.mkdir(parents=True,exist_ok=True)
            path.rename(target);sample['source_path']=str(target.relative_to(ROOT))
    save(root/'private/candidates.json',list(candidates.values()))
    save(effective_path,effective)
    assert (root/'private/optimization_scope.json').read_bytes()==scope_before
    return replacement


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=ROOT/'datasets/final-v1')
    ap.add_argument('--candidate',required=True); ap.add_argument('--reason',required=True)
    ap.add_argument('--failed-condition',action='append',required=True)
    args=ap.parse_args(); print(replace(args.root.resolve(),args.candidate,args.reason,args.failed_condition))
