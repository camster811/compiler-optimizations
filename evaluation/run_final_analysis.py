#!/usr/bin/env python3
"""Regenerate PRIVATE final-v1 Phase H analysis without inference.

python3 -m evaluation.analysis_environment --install
python3 evaluation/run_final_analysis.py
python3 evaluation/run_final_analysis.py --check
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path
import platform
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from evaluation.analysis_environment import activate
if __name__ == '__main__':
    activate()

import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
import numpy as np
import scipy
from evaluation.final_analysis_data import load_inputs, require
from evaluation.final_metrics import PairBootstrap, groups, counts, interval, RATE_NAMES, SEED, REPLICATES, outcome
from evaluation.final_models import fit_models, run_r, FORMULA
from evaluation.final_llm_summaries import operational, stability, confidence, symbol_agreement, decision_reasons
from llm_analysis.common import file_hash, save

DEFAULT_OUTPUT=ROOT/'results/final-v1/analysis'
AMENDMENTS=[
    'Replace custom Python GLMM with R/lme4 maximum likelihood, nAGQ=30; fixed BOBYQA and scaled-gradient diagnostics.',
    'Remove Firth fitting; fallback is full GLMM, main-effects GLMM, then descriptive pair-cluster intervals with no model of record.'
]
AMENDMENT_PROVENANCE=('Pre-analysis amendments documented before aggregate metrics were computed. '
    'The amendments are committed with the implementation and results, not as part of the original preregistration.')
REPORTING_CORRECTIONS=[
    'Post-analysis reporting correction: distinct-request status summaries are overall only; factor subgroups use observation-weighted rows because a request can span factor levels. Overall request counts, performance estimates, intervals and model selection are unchanged.'
]
DEFINITIONS={
    'three_way':'Correct: vulnerable with exact CWE on vulnerable truth, or not_vulnerable on fixed truth. Other decided calls incorrect; uncertain abstains; failed response unavailable.',
    'coverage':'(correct + incorrect) / N; abstention_rate = abstain / N; selective_accuracy = correct / (correct + incorrect). Always report these with counts.',
    'forced_alert':'vulnerable alerts; not_vulnerable, uncertain and unavailable do not. Failed-run nullable binary_correct is never reused; the operational policy is applied explicitly.',
    'primary_Correct':'1 for a correct decided classification ignoring CWE, 0 for incorrect, abstaining or unavailable outcomes. Fixed-case abstention scores 0.',
    'sensitivity_Correct_forced':'1 when forced alert/no-alert matches truth, including fixed-case abstention/failure; 0 otherwise.',
    'forced_metrics':'accuracy=(TP+TN)/N; balanced_accuracy=(TP/(TP+FN)+TN/(TN+FP))/2; precision=TP/(TP+FP); recall=TP/(TP+FN); F1=2TP/(2TP+FP+FN); FPR=FP/(FP+TN); FNR=FN/(FN+TP).',
    'intervals':'95% percentile whole-pair bootstrap, 10000 replicates, seed 20261014, shared weights across strata and paired method differences. Undefined denominators are null; intervals not estimable if >5% replicates undefined.',
    'agreement':'All-three-valid identical / all records or observations. Pairwise agreement pools equal classification pairs / valid repetition pairs; missing comparisons excluded and denominators shown.',
    'confidence':'Raw correctness/confidence is observation weighted. Majority confidence is frozen median over ALL valid repetitions, not only winning votes. High confidence >=0.8; explicit negative calls define high-confidence FN, with abstentions listed separately.',
    'sampling':'20 source-program pairs are the clusters. 528 distinct requests expand to 648 observation-linked rows; 216 observations per method. 104 eliminated observations are excluded entirely.'
}


def csv_table(root,name,rows,columns=None):
    path=root/'tables'/f'{name}.csv'
    path.parent.mkdir(parents=True,exist_ok=True)
    if columns is None:
        columns=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,lineterminator='\n')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v,sort_keys=True) if isinstance(v,(list,dict)) else v for k,v in row.items()})


def performance_tables(conditions,raw,bootstrap):
    reports=[]; cache={}
    for view,rows in [('condition',conditions),('raw_observation_weighted',raw)]:
        for label,subset in groups(rows):
            report,draws=bootstrap.performance(subset)
            reports.append(dict(view=view,**label,**report))
            if view=='condition':
                cache[(label['method'],label['factor'],label['level'])]=(report,draws)
    contrasts=[]
    for factor,level in sorted({(f,l) for m,f,l in cache}):
        a,ad=cache[('llm_majority',factor,level)]
        b,bd=cache[('static',factor,level)]
        for metric in ('primary_correct_rate','accuracy','balanced_accuracy','coverage','recall','false_positive_rate','f1'):
            point=np.nan if a[metric] is None or b[metric] is None else a[metric]-b[metric]
            contrasts.append(dict(comparison='llm_majority - static',factor=factor,level=level,measure=metric,
                n=a['n'],n_pairs=a['n_pairs'],comparison_rows=a['n']+b['n'],reference_n=b['n'],
                reference_pairs=b['n_pairs'],**interval(point,ad[metric]-bd[metric])))
    references={'optimization':'O0','condition':'retained','truth_cwe':'CWE-121','target_effect_ground_truth':'not_vulnerable'}
    for method in ('static','llm_majority'):
        for factor,reference in references.items():
            b,bd=cache[(method,factor,reference)]
            for m,f,l in sorted(cache):
                if m!=method or f!=factor or l==reference:
                    continue
                a,ad=cache[(m,f,l)]
                contrasts.append(dict(comparison=f'{method}: {l} - {reference}',factor=factor,level=l,
                    measure='primary_correct_rate',n=a['n'],n_pairs=a['n_pairs'],comparison_rows=a['n']+b['n'],
                    reference_n=b['n'],reference_pairs=b['n_pairs'],
                    **interval(a['primary_correct_rate']-b['primary_correct_rate'],
                               ad['primary_correct_rate']-bd['primary_correct_rate'])))
    return reports,contrasts


def model_tables(models):
    statuses=[]; coefficients=[]; interactions=[]
    for fit in models['fits']:
        of_record=models['model_of_record'][fit['outcome']]==fit['specification']
        base=dict(outcome=fit['outcome'],specification=fit['specification'],model_of_record=of_record,
                  n=fit['n'],n_pairs=fit['n_pairs'],accepted=fit['accepted'])
        statuses.append(dict(**base,reasons=fit['reasons'],boundary=fit.get('boundary'),
            random_intercept_variance=fit.get('random_intercept_variance'),
            max_absolute_scaled_gradient=fit.get('max_absolute_scaled_gradient'),
            hessian_positive_definite=fit.get('hessian_positive_definite'),warnings=fit.get('warnings',[])))
        for term in fit['coefficients']:
            coefficients.append(dict(**base,label='model of record' if of_record else 'diagnostic, not of record',**term))
        for term in fit['interactions']:
            interactions.append(dict(**base,**term))
    return statuses,coefficients,interactions


def errorbar(ax,x,row,metric,color,offset=0):
    value=row[metric]
    if value is None:
        return
    lo,hi=row[metric+'_ci_low'],row[metric+'_ci_high']
    # Percentile intervals need not contain the point estimate.
    ax.plot(x+offset,value,'o',color=color)
    if lo is not None:
        ax.vlines(x+offset,lo,hi,color=color,lw=1.5)
        ax.hlines([lo,hi],x+offset-.025,x+offset+.025,color=color,lw=1.5)


def figures(root,reports,raw,conditions,patterns):
    directory=root/'figures'; directory.mkdir(parents=True,exist_ok=True)
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'figure.dpi':120})
    overall=[r for r in reports if r['view']=='condition' and r['factor']=='overall']
    fig,axes=plt.subplots(1,2,figsize=(10,4.5),layout='constrained')
    labels=[]
    for i,row in enumerate(overall):
        labels.append(f"{row['method']}\nN={row['n']}, pairs={row['n_pairs']}\ncorrect={row['correct']}, incorrect={row['incorrect']}\nabstain={row['abstain']}, unavailable={row['unavailable']}")
        for ax,metric in zip(axes,('coverage','selective_accuracy')):
            errorbar(ax,i,row,metric,'#276184')
            ax.set(ylim=(-.04,1.04),xlim=(-.5,len(overall)-.5),xticks=range(len(overall)),xticklabels=labels if len(labels)==len(overall) else ['']*len(overall))
    for ax,title in zip(axes,('Coverage','Selective accuracy among decided cases')):
        ax.set_xticks(range(len(overall)),labels); ax.set_title(title); ax.grid(axis='y',alpha=.2)
    fig.suptitle('Three-way view: 95% whole-pair bootstrap intervals; 20 source pairs')
    fig.savefig(directory/'coverage_selective_accuracy.png',metadata={'Software':'Phase H'}); plt.close(fig)

    fig,axes=plt.subplots(2,2,figsize=(12,8),layout='constrained')
    for ax,factor in zip(axes.flat,('optimization','condition','truth_cwe','target_effect_ground_truth')):
        rows=[r for r in reports if r['view']=='condition' and r['factor']==factor]
        levels=sorted({r['level'] for r in rows}); labels=[]
        for i,level in enumerate(levels):
            pair=[r for r in rows if r['level']==level]
            labels.append(f"{level}\nN={pair[0]['n']}/method\npairs={pair[0]['n_pairs']}")
            for method,color,offset in [('static','#276184',-.09),('llm_majority','#b85625',.09)]:
                r=next(r for r in pair if r['method']==method)
                errorbar(ax,i,r,'accuracy',color,offset)
        ax.set(xticks=range(len(levels)),xticklabels=labels,ylim=(-.04,1.04),title=factor,ylabel='Forced-alert accuracy')
        ax.grid(axis='y',alpha=.2)
    axes[0,0].plot([],[],'o',color='#276184',label='static');axes[0,0].plot([],[],'o',color='#b85625',label='LLM majority')
    axes[0,0].legend()
    fig.suptitle('Eligible-case descriptive comparisons; 95% pair-cluster intervals; 216 observations/method, 20 pairs')
    fig.savefig(directory/'forced_accuracy_by_factor.png',metadata={'Software':'Phase H'});plt.close(fig)

    fig,axes=plt.subplots(1,2,figsize=(12,5),layout='constrained')
    for ax,view,rows in [(axes[0],'Raw observation-linked valid answers',raw),
                         (axes[1],'Majority results (frozen median confidence)',[r for r in conditions if r['method']=='llm_majority'])]:
        for i,category in enumerate(('correct','incorrect','abstain')):
            selected=[r for r in rows if outcome(r)==category and r['confidence'] is not None]
            if selected:
                ax.boxplot([[r['confidence'] for r in selected]],positions=[i],widths=.5,showfliers=True,
                           patch_artist=True,boxprops={'facecolor':'#b9d5dd'})
            ax.text(i,-.08,f"{category}\nn={len(selected)}\npairs={len({r['pair_id'] for r in selected})}",ha='center',va='top')
        available=sum(r['confidence'] is not None for r in rows)
        ax.set(title=view+f'\n{available} confidences / {len(rows)} cohort rows; pairs={len({r["pair_id"] for r in rows})}',
               ylim=(0,1.05),xlim=(-.6,2.6),xticks=[],ylabel='Self-reported confidence')
    fig.suptitle('Confidence is descriptive; raw answers are repeated measurements')
    fig.savefig(directory/'confidence_distributions.png',bbox_inches='tight',metadata={'Software':'Phase H'});plt.close(fig)


def fmt(value):
    return 'NA' if value is None else f'{100*value:.1f}%'


def points(value):
    return 'NA' if value is None else f'{100*value:+.1f}'


def with_ci(row,key):
    if row[key] is None:
        return 'NA'
    low,high=row.get(key+'_ci_low'),row.get(key+'_ci_high')
    return fmt(row[key])+(' [not estimable]' if low is None else f' [{fmt(low)}, {fmt(high)}]')


def markdown_table(headers,rows):
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+
                     ['| '+' | '.join(str(v) for v in row)+' |' for row in rows])


def report(root,reports,contrasts,statuses,coefficients,ops,resources,agreement,patterns,conf,errors,symbols,reasons,provenance):
    lines=['# Phase H quantitative analysis: final-v1','',
        'The analysis uses 216 eligible observations per method (432 condition rows), 648 observation-linked LLM repetitions, '
        '528 actual requests and 20 source-program pairs. The 104 proven-eliminated observations are never scored. '
        'All six Phase G tables were regenerated from frozen evidence and matched byte for byte.','',
        '## Definitions and pre-analysis amendments','']
    lines += [f'- **{key}**: {value}' for key,value in DEFINITIONS.items()]
    lines += ['', 'Original preregistration (committed): `7856cce`. '+AMENDMENT_PROVENANCE, '']
    lines += ['- '+v for v in AMENDMENTS]
    lines += ['', 'Post-analysis reporting corrections:', '']
    lines += ['- '+v for v in REPORTING_CORRECTIONS]
    lines += ['', 'F3 uses the preserved campaign server-log slice. Its refreshed receipt and Phase G manifest bind the same frozen prediction tables. '
        'Input, plan, code, environment and artifact hashes are in `analysis.json`.',
        '', '## Three-way view','', 'Intervals in brackets are approximate 95% whole-pair percentile bootstrap intervals.', '']
    overall=[r for r in reports if r['factor']=='overall']
    lines += [markdown_table(['Method / view','N','Pairs','Correct','Incorrect','Abstain','Unavailable','Coverage','Abstention rate','Selective accuracy'],
        [[r['method']+' / '+r['view'],r['n'],r['n_pairs'],r['correct'],r['incorrect'],r['abstain'],r['unavailable'],
          with_ci(r,'coverage'),with_ci(r,'abstention_rate'),with_ci(r,'selective_accuracy')] for r in overall]),
        '', 'Selective accuracy is conditional on deciding. It must be read with coverage and abstention counts.',
        '', '## Forced binary-alert view','',
        'Abstentions and failures raise no alert under the explicit operational policy; they are not confident safe decisions.','']
    lines += [markdown_table(['Method / view','N','Pairs','TP','TN','FP','FN','TN abstain','FN abstain','TN failure','FN failure'],
        [[r['method']+' / '+r['view'],r['n'],r['n_pairs'],*[r[k] for k in ('TP','TN','FP','FN','TN_from_abstention','FN_from_abstention','TN_from_failure','FN_from_failure')]] for r in overall]),'']
    lines += [markdown_table(['Method','N','Pairs','Accuracy','Balanced accuracy','Precision','Recall','F1','FPR','FNR'],
        [[r['method'],r['n'],r['n_pairs'],*[with_ci(r,k) for k in ('accuracy','balanced_accuracy','precision','recall','f1','false_positive_rate','false_negative_rate')]] for r in overall]),'']
    lines += ['## Experimental factors','',
        'These are unadjusted eligible-case comparisons. Eliminated variants change subgroup composition; optimization comparisons are not causal effects. '
        'The CSV tables include all counts, rates, intervals and usable bootstrap counts, including optimization × symbol strata and raw repetitions.','']
    for factor in ('optimization','condition','truth_cwe','target_effect_ground_truth','capacity_visibility','binary_manifestation','input_label_conflict_group'):
        selected=[r for r in reports if r['view']=='condition' and r['factor']==factor]
        lines += ['### '+factor,'',markdown_table(['Method','Level','N','Pairs','Correct','Incorrect','Abstain','Unavailable','Coverage','Selective accuracy','Forced accuracy','Balanced accuracy'],
            [[r['method'],r['level'],r['n'],r['n_pairs'],r['correct'],r['incorrect'],r['abstain'],r['unavailable'],with_ci(r,'coverage'),
              with_ci(r,'selective_accuracy'),with_ci(r,'accuracy'),with_ci(r,'balanced_accuracy')] for r in selected]),'']
    lines += ['## Repeated-measures models and fallback','',f'`{FORMULA}`','',
        'References: O0, retained, static, CWE-121, fixed. Only condition-level majority results enter the LLM model. '
        'Both rungs use R/lme4, binomial-logit maximum likelihood, nAGQ=30, fixed BOBYQA controls. '
        'Selection follows the predefined diagnostic rules, never p-values. Rejected estimates are diagnostic only.','',
        markdown_table(['Outcome','Specification','N','Pairs','Accepted','Model of record','Reason'],
            [[r['outcome'],r['specification'],r['n'],r['n_pairs'],r['accepted'],r['model_of_record'],'; '.join(r['reasons']) or 'none'] for r in statuses]),'']
    for target in ('Correct','Correct_forced'):
        chosen=[r for r in statuses if r['outcome']==target and r['model_of_record']]
        lines += [f"**{target}:** "+('model of record = '+chosen[0]['specification'] if chosen else
                   'no accepted model; descriptive pair-cluster comparisons are the fallback.'),'']
    accepted=[r for r in coefficients if r['model_of_record']]
    if accepted:
        lines += [markdown_table(['Outcome','Term','N','Pairs','Odds ratio','95% Wald interval','Approximate p'],
            [[r['outcome'],r['term'],r['n'],r['n_pairs'],f"{r['odds_ratio']:.4g}",
              f"[{r['odds_ratio_ci_low']:.4g}, {r['odds_ratio_ci_high']:.4g}]",f"{r['approximate_wald_p']:.4g}"] for r in accepted]),'']
    method_contrasts=[r for r in contrasts if r['factor']=='overall']
    lines += ['The primary model combines deciding and correct classification; its method coefficient does not estimate a selective-accuracy difference. '
        'Descriptive paired differences (LLM majority − static), always shown irrespective of model acceptance; all differences below are percentage points:','',
        markdown_table(['Measure','Matched observations','Pairs','Difference (pp)','95% cluster interval (pp)','Usable replicates'],
            [[r['measure'],r['n'],r['n_pairs'],points(r['estimate']),
              'not estimable' if r['ci_low'] is None else f"[{points(r['ci_low'])}, {points(r['ci_high'])}]",
              f"{r['bootstrap_usable']}/{r['bootstrap_total']}"] for r in method_contrasts]),'']
    lines += ['## LLM validity, stability and confidence','',
        'Validity counts below use actual requests at the overall level only. All factor summaries use observation-weighted rows, '
        'because requests shared by observations can span factor levels. '
        'Failure is a separate vote status, never an uncertain model answer. Correct-run counts use strict three-way correctness.','',
        markdown_table(['Status','N requests','Pairs','Events','Rate','95% zero-event bound on pair prevalence'],
            [[r['status'],r['n'],r['n_pairs'],r['events'],fmt(r['estimate']),fmt(r['zero_event_pair_upper_95'])]
             for r in ops if r['view']=='distinct_requests' and r['factor']=='overall' and
             (r['events'] or r['status'] in ('timeout','any_failure'))]),'',
        'The zero-event bound concerns the proportion of pairs containing an event, not the per-request timeout probability.','',
        markdown_table(['View','Measure','N units','Pairs','Numerator / denominator','Estimate','95% cluster interval'],
            [[r['view'],r['measure'],r['n'],r['n_pairs'],f"{r['numerator']}/{r['denominator']}",fmt(r['estimate']),
              'not estimable' if r['ci_low'] is None else f"[{fmt(r['ci_low'])}, {fmt(r['ci_high'])}]"]
             for r in agreement if r['factor']=='overall']),'',
        'Vote patterns (all patterns retained; observation patterns also stratified by truth):','',
        markdown_table(['View','Vote triple','Count','N units','Pairs in cohort','Pairs with pattern'],
            [[r['view'],r['vote_pattern'].replace('|','/'),r['count'],r['n'],r['n_pairs'],r['event_pairs']] for r in patterns if r['factor']=='overall']),'',
        'Confidence summaries (valid numeric confidence only; unavailable responses remain separate):','',
        markdown_table(['View','Outcome','Outcome rows','n confidences','Pairs with confidence','Stratum N','Mean','Median','Q1','Q3','Range'],
            [[r['view'],r['outcome'],r['cohort_n'],r['n'],r['n_pairs'],r['stratum_n'],
              *['NA' if r[k] is None else f'{r[k]:.3f}' for k in ('mean','median','q1','q3')],
              'NA' if r['minimum'] is None else f"[{r['minimum']:.3f}, {r['maximum']:.3f}]"]
             for r in conf if r['factor']=='overall']),'',
        'High-confidence error and abstention listings include observation IDs, run IDs, pair IDs, truth and predictions. '
        'They are descriptive self-reported confidence, not calibrated probabilities.','']
    for view in ('raw_observation_weighted','llm_majority'):
        for kind in ('false_positive','false_negative_explicit','abstention','wrong_cwe'):
            selected=[r for r in errors if r['view']==view and r['error_type']==kind]
            denom=648 if view=='raw_observation_weighted' else 216
            lines += [f"- {view}, {kind}: {len(selected)} rows / {denom}; {len({r['pair_id'] for r in selected})} pairs with events (20 total)."]
    lines += ['', 'Abstention and aggregation reasons (full factor tables are also available):','',
        markdown_table(['Method','Classification','Reason','Valid runs','Failed runs','Count','Pairs with result','Cohort N'],
            [[r['method'],r['classification'],r['reason'],r['valid_runs'] if r['valid_runs'] is not None else 'NA',
              r['failed_runs'] if r['failed_runs'] is not None else 'NA',r['n'],r['n_pairs'],r['cohort_n']]
             for r in reasons if r['factor']=='overall']),'',
        'Retained/stripped classification agreement:','',
        markdown_table(['Method','Matched cells','Observation rows','Pairs','Agreements','Rate'],
            [[r['method'],r['n'],r['n_observation_rows'],r['n_pairs'],r['agreements'],fmt(r['estimate'])]
             for r in symbols if r['optimization']=='all' and r['measure']=='classification_agreement']),'',
        '## Interpretation limits and regeneration','',
        'The 20 clusters and selected source families limit generalization. Bootstrap intervals can be too narrow near 0 or 1; '
        'zero-width observed intervals do not establish population certainty. Small subgroup differences and intervals spanning zero '
        'are not evidence of an effect. Wald inference with 20 clusters is approximate and can be anti-conservative. '
        'No multiplicity correction is applied; no result is confirmatory. CWE is a between-pair factor. '
        'The static baseline and LLM use different public evidence; comparisons do not isolate model architecture. '
        'Saved-response replay is deterministic; LLM generation determinism and runner-process file tracing are not claimed.','',
        'Run `python3 -m evaluation.analysis_environment --install`, then `python3 evaluation/run_final_analysis.py`. '
        'Use `python3 evaluation/run_final_analysis.py --check` for byte-for-byte regeneration verification. '
        'Package versions and archive hashes are pinned in the environment lock; R session information is in `models.json`.','',
        '### Tables','']
    lines += [f'- [{p.name}](tables/{p.name})' for p in sorted((root/'tables').glob('*.csv'))]
    lines += ['', '### Figures','',
        '![Coverage and selective accuracy](figures/coverage_selective_accuracy.png)','',
        '![Forced accuracy by factor](figures/forced_accuracy_by_factor.png)','',
        '![Confidence distributions](figures/confidence_distributions.png)','']
    (root/'report.md').write_text('\n'.join(lines))


def generate(output,campaign=None):
    sources=sorted(set([Path(__file__),ROOT/'evaluation/final_analysis_plan.md']+
        list((ROOT/'evaluation').glob('final_*.py'))+[ROOT/'evaluation/final_glmm.R',
        ROOT/'evaluation/analysis_environment.py',ROOT/'evaluation/analysis_environment.lock.json',
        ROOT/'evaluation/build_final_tables.py',ROOT/'evaluation/check_final_acceptance.py',
        ROOT/'evaluation/tests/test_final_analysis.py',ROOT/'evaluation/tests/test_final_acceptance.py',
        ROOT/'evaluation/phase_h.md']))
    source_hashes={str(p.relative_to(ROOT)):file_hash(p) for p in sources}
    # Dependencies and the backend must work even if separation later rejects all models.
    preflight=run_r({'self_test':True})
    expected=json.loads((ROOT/'evaluation/analysis_environment.lock.json').read_text())['runtime_versions']
    actual=dict(python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__,
                matplotlib=matplotlib.__version__,**preflight['versions'])
    require(actual==expected,'runtime versions differ from the pinned environment: '+json.dumps(actual,sort_keys=True))
    conditions,raw,distinct,eliminated,manifest,input_hashes=load_inputs(campaign)
    bootstrap=PairBootstrap([r['pair_id'] for r in conditions])
    print('Verified frozen evidence and byte-identical Phase G rebuild; computing Phase H.',flush=True)
    reports,contrasts=performance_tables(conditions,raw,bootstrap)
    models=fit_models(conditions)
    statuses,coefficients,interactions=model_tables(models)
    ops,resources=operational(raw,distinct,bootstrap)
    agreement,patterns,correct_counts=stability(raw,bootstrap)
    conf,errors=confidence(raw,conditions)
    symbols=symbol_agreement(conditions,bootstrap)
    reasons=decision_reasons(conditions)
    performance_columns=list(reports[0])
    tables={'performance':reports,'descriptive_contrasts':contrasts,'model_status':statuses,
            'model_coefficients':coefficients,'model_interactions':interactions,
            'response_status':ops,'resources':resources,'repetition_agreement':agreement,
            'vote_patterns':patterns,'correct_repetitions':correct_counts,
            'confidence':conf,'high_confidence_cases':errors,'symbol_agreement':symbols,'decision_reasons':reasons}
    empty_columns={
        'model_coefficients':['outcome','specification','n','n_pairs','accepted','model_of_record','term','estimate','standard_error','odds_ratio','odds_ratio_ci_low','odds_ratio_ci_high','approximate_wald_p'],
        'model_interactions':['outcome','specification','n','n_pairs','accepted','model_of_record','term','df','statistic','approximate_wald_p'],
        'high_confidence_cases':['view','n','n_pairs','error_type','observation_id','pair_id','run_id','confidence']}
    for name,rows in tables.items():
        csv_table(output,name,rows,empty_columns.get(name) if not rows else None)
    # Publish the full H1 bundle together, and a separate operational H2 table.
    identifiers=['view','method','factor','level','n','n_pairs','n_records']
    h1=['correct','incorrect','abstain','unavailable','decided','wrong_cwe']
    h1 += [k for k in performance_columns if any(k==v or k.startswith(v+'_') for v in ('coverage','abstention_rate','unavailable_rate','selective_accuracy','primary_correct_rate'))]
    csv_table(output,'three_way',[{k:r[k] for k in identifiers+h1} for r in reports])
    h2=[k for k in performance_columns if k not in identifiers+h1]
    csv_table(output,'forced_alert',[{k:r[k] for k in identifiers+h2} for r in reports])
    # Paths in backend sessionInfo are normalized for relocation/reproducibility.
    models['session_info']=[line.replace(str(ROOT),'<REPO>') for line in models['session_info']]
    save(output/'models.json',models)
    figures(output,reports,raw,conditions,patterns)
    provenance=dict(schema_version='1.0',phase='H',campaign_id=manifest['campaign_id'],
        original_preregistration='7856cce',amendments=AMENDMENTS,amendment_provenance=AMENDMENT_PROVENANCE,
        deviations=REPORTING_CORRECTIONS,definitions=DEFINITIONS,
        input_hashes=input_hashes,source_hashes=source_hashes,
        bootstrap=dict(seed=SEED,replicates=REPLICATES,cluster='pair_id',n_clusters=20,
            pair_order=bootstrap.pairs,weight_matrix_sha256=hashlib.sha256(bootstrap.weights.astype('<i8').tobytes()).hexdigest()),
        cardinality=manifest['cardinality'],
        environment=dict(python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__,matplotlib=matplotlib.__version__,
                         R=models['versions'],platform=platform.platform()),
        backend_validation=dict(self_test=preflight['self_test'],cbpp_coefficients=preflight['cbpp_coefficients']),
        model_of_record=models['model_of_record'])
    report(output,reports,contrasts,statuses,coefficients,ops,resources,agreement,patterns,conf,errors,symbols,reasons,provenance)
    provenance['outputs']={str(p.relative_to(output)):dict(sha256=file_hash(p),bytes=p.stat().st_size,
        **({'rows':sum(1 for _ in csv.DictReader(p.open()))} if p.suffix=='.csv' else {}))
        for p in sorted(output.rglob('*')) if p.is_file()}
    save(output/'analysis.json',provenance)
    for name,digest in {**source_hashes,**input_hashes}.items():
        require(file_hash(ROOT/name)==digest,'source or input changed during analysis: '+name)
    return provenance


def compare_outputs(expected,actual):
    a={str(p.relative_to(expected)):file_hash(p) for p in expected.rglob('*') if p.is_file()}
    b={str(p.relative_to(actual)):file_hash(p) for p in actual.rglob('*') if p.is_file()}
    require(a==b,'analysis regeneration differs: '+', '.join(sorted(k for k in a.keys()|b.keys() if a.get(k)!=b.get(k))))
    return len(a)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign',type=Path)
    parser.add_argument('--output',type=Path,default=DEFAULT_OUTPUT)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    output=args.output.resolve()
    # Prevent accidental replacement of the evidence directory or its ancestors.
    require(output != ROOT and output != ROOT/'results/final-v1' and
            not output.is_relative_to(ROOT/'results/final-v1/private') and
            not output.is_relative_to(ROOT/'llm_analysis/output'), 'unsafe output location')
    with tempfile.TemporaryDirectory(prefix='phase-h-') as temporary:
        staged=Path(temporary)
        provenance=generate(staged,args.campaign)
        if args.check:
            require(output.is_dir(),'analysis output missing; generate before --check')
            count=compare_outputs(output,staged)
            print(f'Phase H regeneration verified: {count} byte-identical artifacts.')
        else:
            if output.exists():
                # Refuse stale-file accumulation and unreviewed changes to an existing analysis.
                count=compare_outputs(output,staged)
                print(f'Phase H already current: {count} identical artifacts.')
            else:
                output.parent.mkdir(parents=True,exist_ok=True)
                shutil.copytree(staged,output)
                print('Phase H written to',output)
        print('Models of record:',json.dumps(provenance['model_of_record'],sort_keys=True))


if __name__=='__main__':
    main()
