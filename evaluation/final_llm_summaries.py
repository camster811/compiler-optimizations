"""LLM stability, validity, and confidence summaries with explicit denominators."""
from collections import defaultdict
from itertools import combinations
import numpy as np
from evaluation.final_metrics import groups, counts, outcome

STATUSES = ('valid','timeout','schema_invalid','length_limit','empty_response','invalid_json',
            'evidence_invalid','response_invalid','transport_error','interrupted','http_error','context_overflow')


def numeric(rows, key):
    valid = [r for r in rows if r.get(key) is not None]
    values = [r[key] for r in valid]
    result = dict(n=len(values), n_pairs=len({r['pair_id'] for r in valid}), cohort_n=len(rows),
                  cohort_pairs=len({r['pair_id'] for r in rows}))
    result.update(dict.fromkeys(('mean','median','q1','q3','minimum','maximum')))
    if values:
        result.update(mean=float(np.mean(values)), median=float(np.median(values)),
                      q1=float(np.quantile(values,.25)), q3=float(np.quantile(values,.75)),
                      minimum=float(min(values)), maximum=float(max(values)))
    return result


def operational(raw, distinct, bootstrap):
    result, resources = [], []
    for view, rows in [('distinct_requests',distinct),('observation_weighted',raw)]:
        # One request can belong to several observation factors (e.g. O2/O3).
        # Its first expanded row is not a unique factor assignment.
        cohorts = ([(dict(method='llm',factor='overall',level='all'),rows)] if view=='distinct_requests'
                   else groups(rows, include_method=False, include_interaction=False))
        for label, subset in cohorts:
            pairs = len({r['pair_id'] for r in subset})
            for status in STATUSES+('any_failure',):
                event = lambda r, status=status: int(r['run_status'] != 'valid' if status=='any_failure' else r['run_status']==status)
                events = sum(map(event,subset))
                ci = bootstrap.ratio(subset,event,lambda r:1)
                result.append(dict(view=view,**label,status=status,n=len(subset),n_pairs=pairs,events=events,
                    event_pairs=len({r['pair_id'] for r in subset if event(r)}), **ci,
                    zero_event_pair_upper_95=1-.05**(1/pairs) if not events and pairs else None))
        for key in ('terminal_latency_seconds','total_attempt_latency_seconds','prompt_tokens','completion_tokens','total_tokens'):
            resources.append(dict(view=view,measure=key,**numeric(rows,key)))
    return result, resources


def stability_units(raw):
    by_observation = defaultdict(list)
    for row in raw:
        by_observation[row['observation_id']].append(row)
    result = []
    for _, runs in sorted(by_observation.items()):
        runs = sorted(runs,key=lambda r:r['repetition'])
        if len(runs)!=3 or {r['repetition'] for r in runs}!={1,2,3}:
            raise ValueError('stability requires exactly three repetitions')
        valid = [r for r in runs if r['run_status']=='valid']
        comparisons = list(combinations(valid,2))
        label = dict(runs[0])
        label.pop('repetition')
        label.update(all_three_valid_identical=int(len(valid)==3 and len({r['classification'] for r in valid})==1),
                     all_three_valid=int(len(valid)==3),
                     pairwise_agree=sum(a['classification']==b['classification'] for a,b in comparisons),
                     pairwise_valid=len(comparisons),
                     correct_runs=sum(counts(r)['correct'] for r in runs),
                     vote_pattern=' | '.join(sorted(r['classification'] if r['run_status']=='valid'
                                                  else '['+r['run_status']+']' for r in runs)))
        result.append(label)
    return result


def stability(raw, bootstrap):
    units = stability_units(raw)
    unique = {}
    for row in units:
        unique.setdefault(row['record_sha256'],row)
    summary, patterns, correct_counts = [], [], []
    cohorts = [('distinct_records',dict(method='llm',factor='overall',level='all'),list(unique.values()))]
    cohorts += [('observation_weighted',label,rows) for label,rows in groups(units,include_method=False)]
    for view,label,rows in cohorts:
        base = dict(view=view,**label,n=len(rows),n_pairs=len({r['pair_id'] for r in rows}))
        for metric,num,den in [('all_three_valid_identical',lambda r:r['all_three_valid_identical'],lambda r:1),
                               ('all_three_valid',lambda r:r['all_three_valid'],lambda r:1),
                               ('pairwise_classification_agreement',lambda r:r['pairwise_agree'],lambda r:r['pairwise_valid'])]:
            summary.append(dict(**base,measure=metric,numerator=sum(map(num,rows)),
                                denominator=sum(map(den,rows)),**bootstrap.ratio(rows,num,den)))
        # Overall patterns and by-truth observation patterns; failure is never an uncertain vote.
        if label['factor'] in ('overall','target_effect_ground_truth'):
            for pattern in sorted({r['vote_pattern'] for r in rows}):
                selected=[r for r in rows if r['vote_pattern']==pattern]
                patterns.append(dict(**base,vote_pattern=pattern,count=len(selected),
                                     event_pairs=len({r['pair_id'] for r in selected})))
        # Correctness may differ between observations sharing a response; no unique-record correctness.
        if view=='observation_weighted':
            for k in range(4):
                correct_counts.append(dict(**base,correct_runs=k,count=sum(r['correct_runs']==k for r in rows)))
    return summary,patterns,correct_counts


def confidence(raw,conditions):
    summaries, errors = [], []
    for view,rows in [('raw_observation_weighted',raw),('llm_majority',[r for r in conditions if r['method']=='llm_majority'])]:
        for label,subset in groups(rows,include_method=False,include_interaction=False):
            for category in ('correct','incorrect','abstain','unavailable'):
                selected=[r for r in subset if outcome(r)==category]
                summaries.append(dict(view=view,**label,outcome=category,**numeric(selected,'confidence'),
                                      stratum_n=len(subset),stratum_pairs=len({r['pair_id'] for r in subset})))
        for row in rows:
            if row['confidence'] is None or row['confidence']<.8:
                continue
            cls,truth=row['classification'],row['target_effect_ground_truth']
            category = ('false_positive' if cls=='vulnerable' and truth=='not_vulnerable' else
                        'false_negative_explicit' if cls=='not_vulnerable' and truth=='vulnerable' else
                        'abstention' if cls=='uncertain' else
                        'wrong_cwe' if counts(row)['wrong_cwe'] else None)
            if category:
                errors.append(dict(view=view,n=1,n_pairs=1,error_type=category,
                    **{k:row.get(k) for k in ('observation_id','pair_id','source_case_id','record_sha256','run_id','repetition',
                          'optimization','condition','truth_cwe','target_effect_ground_truth','classification','predicted_cwe','confidence')}))
    return summaries,errors


def symbol_agreement(conditions,bootstrap):
    cells=defaultdict(dict)
    for row in conditions:
        key=(row['method'],row['source_case_id'],row['optimization'])
        cells[key][row['condition']]=row
    matches=[]
    for key,pair in sorted(cells.items()):
        if set(pair)!= {'retained','stripped'}:
            raise ValueError('incomplete symbol match')
        a,b=pair['retained'],pair['stripped']
        matches.append(dict(a,agrees=int(a['classification']==b['classification']),
                            exact_agrees=int((a['classification'],a['predicted_cwe'])==(b['classification'],b['predicted_cwe']))))
    result=[]
    for method in sorted({r['method'] for r in matches}):
        for optimization in ['all','O0','O1','O2','O3']:
            rows=[r for r in matches if r['method']==method and (optimization=='all' or r['optimization']==optimization)]
            for measure,key in [('classification_agreement','agrees'),('classification_cwe_agreement','exact_agrees')]:
                result.append(dict(method=method,optimization=optimization,measure=measure,n=len(rows),n_observation_rows=2*len(rows),
                    n_pairs=len({r['pair_id'] for r in rows}),agreements=sum(r[key] for r in rows),
                    **bootstrap.ratio(rows,lambda r:r[key],lambda r:1)))
    return result


def decision_reasons(conditions):
    """Distinguish model abstention from frozen aggregation failure/disagreement."""
    result=[]
    for label,rows in groups(conditions,include_interaction=False):
        buckets=defaultdict(list)
        for row in rows:
            buckets[(row['classification'], row.get('uncertain_reason') or 'decided',
                     row.get('valid_runs'),row.get('failed_runs'))].append(row)
        for key,subset in sorted(buckets.items(),key=lambda item:str(item[0])):
            cls,reason,valid,failed=key
            result.append(dict(**label,classification=cls,reason=reason,valid_runs=valid,failed_runs=failed,
                n=len(subset),n_pairs=len({r['pair_id'] for r in subset}),cohort_n=len(rows),
                cohort_pairs=len({r['pair_id'] for r in rows})))
    return result
