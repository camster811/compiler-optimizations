"""Accept and freeze final inputs without inference or prediction scores."""
import argparse
import csv
import gzip
import re
import tarfile
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from evaluation.corpus_pipeline import selected, run, CFLAGS, LDFLAGS
from evaluation.corpus_selection import ROOT, POLICY, bodies, clean, facets, proof, sanitize, verify_source_inputs
from evaluation.oracle_v2 import check as check_oracle
from evaluation.prepare_llm_experiment import prepare_experiment, load_experiment
from llm_analysis.common import HERE, digest, encode, file_hash, load, method_files, now, save, write


def acceptance(root):
    if load(root/'private/selection_policy.json') != POLICY: raise ValueError('source policy drift')
    candidates=selected(root)
    if len(candidates)!=20 or Counter(c['cwe'] for c in candidates)!={'CWE-121':10,'CWE-122':10}: raise ValueError('20 balanced pairs required')
    ids=[s['sample_id'] for c in candidates for s in c['samples']]
    if len(set(ids))!=40: raise ValueError('40 unique neutral source cases required')
    for c in candidates:
        raw=root/'private/upstream'/Path(c['original_path']).name
        if file_hash(raw)!=c['original_sha256']: raise ValueError('upstream evidence drift')
        original=bodies(raw.read_text())
        if [proof(body) for body in original]!=c['proofs']: raise ValueError('source proof differs from original operation')
        for body,facts in zip(original,c['proofs']): verify_source_inputs(body,raw.read_text(),facts)
        macros='\n'.join(re.findall(r'^#define\s+SRC_STRING\s+[^\n]+',clean(raw.read_text()),re.M))
        for s,body in zip(c['samples'],original):
            path=ROOT/s['source_path']
            if path.read_text()!=sanitize(body,macros) or file_hash(path)!=s['source_sha256']: raise ValueError('sanitization changed original body')
            facts=s['proof']
            expected_truth='vulnerable' if facts['write_extent_bytes']>facts['capacity_bytes'] else 'not_vulnerable'
            if s['source_ground_truth']!=expected_truth: raise ValueError('source truth contradicts byte arithmetic')
            heap=bool(re.search(r'\bdata\s*=.*?\bmalloc\s*\(',body))
            if heap!=(c['cwe']=='CWE-122'): raise ValueError('CWE label contradicts target allocation kind')
        if {s['source_ground_truth'] for s in c['samples']}!={'vulnerable','not_vulnerable'}: raise ValueError('malformed source pair')
    for cwe in ('CWE-121','CWE-122'):
        f=set().union(*(facets(c) for c in candidates if c['cwe']==cwe))
        if len({v for k,v in f if k=='mechanism'})<4 or len({v for k,v in f if k=='repair'})<3 or len({v for k,v in f if k=='flow'})<2:
            raise ValueError('required source diversity lost after replacement')
    scope=load(root/'private/optimization_scope.json')['optimizations']
    if scope not in (['O0','O2'],['O0','O1','O2','O3']): raise ValueError('invalid fixed optimization scope')
    build=list(csv.DictReader((root/'artifacts/private/build_manifest.tsv').open(),delimiter='\t'))
    expected={(sid,opt) for sid in ids for opt in scope}
    if len(build)!=len(expected) or {(r['sample_id'],r['optimization']) for r in build}!=expected: raise ValueError('incomplete source/optimization matrix')
    for row in build:
        if row['compile_flags']!=' '.join(CFLAGS+['-'+row['optimization']]+LDFLAGS): raise ValueError('case-specific build flags')
        hashes=[]
        with tempfile.TemporaryDirectory() as temporary:
            for condition in ('oracle','retained','stripped'):
                text=Path(temporary)/(condition+'.bin')
                run(['objcopy','--only-section=.text','-O','binary',ROOT/row[condition+'_path'],text])
                h=file_hash(text); hashes.append(h)
                if h!=row[condition+'_text_sha256']: raise ValueError('recorded .text hash drift')
        if len(set(hashes))!=1: raise ValueError('symbol condition .text differs')
    rows=check_oracle(root,True)
    eligible=[r for r in rows if r['binary_manifestation']!='eliminated']
    tags={r['sample_id']+'_'+r['optimization'] for r in eligible}
    for condition in ('retained','stripped'):
        if {p.stem for p in (root/'ghidra/records'/condition).glob('*.json')}!=tags: raise ValueError('extra/missing public records')
    options={load(p)['analysis_options_sha256'] for p in (root/'private/ghidra').glob('*/*.run.json') if p.stem.removesuffix('.run') in tags}
    if len(options)!=1: raise ValueError('Ghidra analysis options vary across matrix')
    context=load(root/'private/context.json')
    hashes={file_hash(p) for p in (root/'ghidra/records').glob('*/*.json')}
    if set(context['records'])!=hashes or any(not v['fits_context'] for v in context['records'].values()): raise ValueError('context scope incomplete or oversized')
    pointer=load(HERE/'frozen/current.json'); receipt=load(ROOT/pointer['receipt_path'])
    if method_files()!=receipt['method']['files'] or file_hash(ROOT/pointer['receipt_path'])!=pointer['receipt_sha256']: raise ValueError('selected method changed')
    if context['method_id']!=pointer['method_id'] or context['completion_requests']!=0: raise ValueError('token evidence not from selected method')
    for c in candidates:
        for s in c['samples']:
            diagnostic=load(root/'artifacts/private/asan'/(s['sample_id']+'.json'))
            if s['source_ground_truth']=='not_vulnerable' and (diagnostic['returncode']!=0 or diagnostic['timeout']): raise ValueError('fixed ASan failure')
            for opt in scope:
                outcome=load(root/'artifacts/private/runs'/f'{s["sample_id"]}_{opt}.json')
                if outcome['timeout'] or (s['source_ground_truth']=='not_vulnerable' and outcome['returncode']!=0): raise ValueError('runtime validation failure')
    tokens=[x['prompt_tokens'] for x in context['records'].values()]
    from llm_analysis.build_prompt import project
    groups=defaultdict(list)
    for row in eligible:
        for condition in ('retained','stripped'):
            path=root/'ghidra/records'/condition/f'{row["sample_id"]}_{row["optimization"]}.json'
            key=digest(encode(project(path.read_bytes())))
            groups[key].append({'sample_id':row['sample_id'],'pair_id':row['pair_id'],'optimization':row['optimization'],
                                'condition':condition,'target_effect_ground_truth':row['target_effect_ground_truth']})
    conflicts={h:items for h,items in groups.items() if len({i['target_effect_ground_truth'] for i in items})>1}
    if conflicts and any(next(r for r in rows if r['sample_id']==i['sample_id'] and r['optimization']==i['optimization'])['capacity_visibility']!='not_explicit'
                         for items in conflicts.values() for i in items):
        raise ValueError('conflicting input labels outside the declared latent-stack-capacity stratum')
    summary={'dataset_id':'final-v1','pairs':20,'source_cases':40,'cwe_pairs':{'CWE-121':10,'CWE-122':10},
             'optimizations':scope,'symbol_conditions':['retained','stripped'],'planned_observations':2*len(rows),
             'eligible_observations':2*len(eligible),'non_inference_observations':2*(len(rows)-len(eligible)),
             'distinct_eligible_records':len(hashes),'later_generations':3*len(hashes),
             'manifestations_source_optimization':dict(Counter(r['binary_manifestation'] for r in rows)),
             'prompt_tokens':{'minimum':min(tokens),'maximum':max(tokens)},'context_rejections':0,
             'technical_pair_replacements':len(load(root/'private/effective_selection.json')['rejections']) if (root/'private/effective_selection.json').exists() else 0,
             'conflicting_projected_input_groups':len(conflicts),'observations_in_conflicting_projected_groups':sum(map(len,conflicts.values())),
             'completion_requests':0,'accuracy_scores_computed':False,'selected_llm_method_id':pointer['method_id'],
             'static_analyzer_sha256':file_hash(ROOT/'static_analysis/analyze.py'), 'static_rules_sha256':file_hash(ROOT/'static_analysis/rules.md'),
             'scope':'Local target setup and effect in one complete function record fitting the frozen context; non-explicit stack capacity retained',
             'limitations':['All selected stack allocations use the original alloca families; no population-representativeness claim.',
                            'Candidate screening is conditioned on selected source families, single-function locality and model context compatibility.',
                            'Related Juliet mechanisms and repeated conditions are not independent programs.']}
    return candidates,summary


def check_receipt(root):
    receipt=load(root/'private/corpus-freeze.json')
    for name,h in receipt['files'].items():
        if file_hash(ROOT/name)!=h: raise ValueError('frozen dataset drift: '+name)
    inputs=load(root/'private/inputs-freeze.json')
    for name,h in inputs['files'].items():
        if file_hash(ROOT/name)!=h: raise ValueError('frozen input drift: '+name)
    if digest(encode(receipt))!=inputs['corpus_receipt_sha256']: raise ValueError('corpus receipt drift')
    experiment,_=load_experiment(ROOT/inputs['experiment_path'])
    eligible=[o for o in experiment['observations'] if o['inference_eligible']]
    if len(experiment['observations'])!=receipt['summary']['planned_observations'] or len(eligible)!=receipt['summary']['eligible_observations']:
        raise ValueError('input manifest differs from accepted dataset')
    print('Frozen corpus/input checksums and full/eligible matrices verified')
    return receipt


def freeze(root,experiment):
    if (root/'private/corpus-freeze.json').exists(): return check_receipt(root)
    candidates,summary=acceptance(root)
    save(root/'private/accepted_pairs.json',candidates,immutable=True)
    write(root/'private/build_manifest.tsv',(root/'artifacts/private/build_manifest.tsv').read_bytes(),immutable=True)
    # One receipt binds the immutable corpus chain. Input receipt adds the private
    # experiment and blinded export afterward, avoiding circular receipt hashes.
    paths=[p for p in root.rglob('*') if p.is_file() and 'tokenizer' not in p.parts and p.name not in ('corpus-freeze.json','inputs-freeze.json')]
    paths += [ROOT/name for name in ('build.sh','ghidra/run_headless.sh','ghidra/config.json','ghidra/scripts/ExtractRegion.java','ghidra/scripts/RecoverFunctions.java')]
    paths += list((ROOT/'evaluation').glob('*.py')) + list((ROOT/'evaluation').glob('*schema*.json'))
    receipt={'schema_version':'1.0','frozen_at':now(),'summary':summary,'files':{str(p.relative_to(ROOT)):file_hash(p) for p in sorted(set(paths))}}
    save(root/'private/corpus-freeze.json',receipt,immutable=True)
    private,blind=prepare_experiment(root/'private/build_manifest.tsv',{c:root/'ghidra/records'/c for c in ('retained','stripped')},
                                    experiment,'final-v1',False,oracle_v2=root/'private/oracle.jsonl',context_evidence=root/'private/context.json')
    input_paths=[private,private.with_suffix('.json.sha256')]+[p for p in blind.parent.rglob('*') if p.is_file()]
    inputs={'schema_version':'1.0','corpus_receipt_sha256':digest(encode(receipt)), 'experiment_path':str(private.relative_to(ROOT)),
            'blinded_manifest_path':str(blind.relative_to(ROOT)), 'files':{str(p.relative_to(ROOT)):file_hash(p) for p in sorted(input_paths)}}
    save(root/'private/inputs-freeze.json',inputs,immutable=True)
    archive=ROOT/'datasets/releases/final-v1.tar.gz'; archive.parent.mkdir(exist_ok=True)
    if archive.exists(): raise ValueError('unreceipted release archive exists')
    with archive.open('wb') as output, gzip.GzipFile(filename='',fileobj=output,mode='wb',mtime=0) as zipped, tarfile.open(fileobj=zipped,mode='w') as tar:
        archive_paths=set(paths+input_paths+[root/'private/corpus-freeze.json',root/'private/inputs-freeze.json'])
        archive_paths |= {p for p in (root/'private/tokenizer').glob('*') if p.is_file()}
        for p in sorted(archive_paths):
            info=tar.gettarinfo(str(p),arcname=str(p.relative_to(ROOT))); info.mtime=0; info.uid=info.gid=0; info.uname=info.gname=''
            with p.open('rb') as stream: tar.addfile(info,stream)
    save(root/'release.json',{'archive_path':str(archive.relative_to(ROOT)),'archive_sha256':file_hash(archive),
                            'archive_bytes':archive.stat().st_size,'corpus_receipt_sha256':file_hash(root/'private/corpus-freeze.json'),
                            'input_receipt_sha256':file_hash(root/'private/inputs-freeze.json')},immutable=True)
    print(summary)
    return receipt


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=ROOT/'datasets/final-v1'); ap.add_argument('--experiment',type=Path,default=ROOT/'evaluation/experiments/final.json')
    ap.add_argument('--check',action='store_true'); args=ap.parse_args()
    check_receipt(args.root.resolve()) if args.check else freeze(args.root.resolve(),args.experiment.resolve())
