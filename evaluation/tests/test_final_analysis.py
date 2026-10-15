"""Phase H synthetic and backend validation; never loads final predictions."""
from collections import Counter
import itertools
import tempfile
from pathlib import Path
import unittest
import numpy as np
from evaluation.final_metrics import counts, outcome, PairBootstrap, rates, COUNT_NAMES, interval
from evaluation.final_models import design, screen, run_r, fit_models, choose_record
from evaluation.final_llm_summaries import stability, operational, confidence, symbol_agreement
from evaluation.run_final_analysis import performance_tables, compare_outputs
from evaluation.final_analysis_data import verify_checksums
from evaluation.final_llm_summaries import decision_reasons
from llm_analysis.common import file_hash


def row(cls='vulnerable',positive=True,pair='p0',cwe='CWE-121',predicted_cwe=None,**kwargs):
    result=dict(classification=cls,target_effect_ground_truth='vulnerable' if positive else 'not_vulnerable',
        truth_cwe=cwe,predicted_cwe=(cwe if cls=='vulnerable' else None) if predicted_cwe is None else predicted_cwe,
        pair_id=pair,record_sha256=pair,source_case_id=pair,observation_id=pair,method='static',
        condition='retained',optimization='O0',capacity_visibility='explicit',binary_manifestation='present',
        input_label_conflict_group=False,confidence=.9,run_status='valid',repetition=1,run_id=pair)
    result.update(kwargs)
    return result


class ScoringTests(unittest.TestCase):
    def test_hand_calculated_views_and_provenance(self):
        rows=[row('vulnerable'),row('not_vulnerable',False),row('vulnerable',False),row('not_vulnerable'),
              row('uncertain'),row('uncertain',False),row(None),row(None,False),
              row('vulnerable',predicted_cwe='CWE-122')]
        boot=PairBootstrap(['p0'],replicates=100)
        result,_=boot.performance(rows)
        expected=dict(n=9,correct=2,incorrect=3,abstain=2,unavailable=2,decided=5,primary_correct=3,
                      TP=2,TN=3,FP=1,FN=3,wrong_cwe=1,TP_exact_cwe=1,
                      TN_from_abstention=1,FN_from_abstention=1,TN_from_failure=1,FN_from_failure=1,
                      TN_from_not_vulnerable=1,FN_from_not_vulnerable=1)
        for k,v in expected.items():
            self.assertEqual(result[k],v,k)
        for key,value in dict(coverage=5/9,selective_accuracy=2/5,accuracy=5/9,balanced_accuracy=(2/5+3/4)/2,
                              precision=2/3,recall=2/5,f1=4/8,false_positive_rate=1/4,false_negative_rate=3/5).items():
            self.assertAlmostEqual(result[key],value,msg=key)
        self.assertEqual(outcome(rows[-1]),'incorrect')

    def test_nulls_and_fixed_abstention_model_difference(self):
        report,_=PairBootstrap(['p0'],replicates=100).performance([row('uncertain',False)])
        self.assertEqual(report['primary_correct_rate'],0)
        self.assertEqual(report['accuracy'],1)
        self.assertIsNone(report['selective_accuracy'])
        self.assertEqual(report['selective_accuracy_reason'],'undefined denominator')
        self.assertIsNone(report['precision'])
        self.assertIsNone(report['balanced_accuracy'])
        with self.assertRaises(ValueError): counts(row('invented'))
        with self.assertRaises(ValueError): counts(row(target_effect_ground_truth=None))

    def test_cluster_weights_keep_copies_and_methods_together(self):
        boot=PairBootstrap(['a','b'],replicates=500)
        rows=[row('vulnerable',pair='a'),row('not_vulnerable',pair='b')]
        report,draws=boot.performance(rows)
        copied=[dict(r) for r in rows for _ in range(3)]
        duplicate,ddraws=boot.performance(copied)
        self.assertEqual(duplicate['n'],3*report['n'])
        np.testing.assert_array_equal(draws['accuracy'],ddraws['accuracy'])
        np.testing.assert_array_equal(boot.weights.sum(axis=1),2)
        self.assertEqual(duplicate['n_pairs'],2)
        np.testing.assert_array_equal(boot.weights,PairBootstrap(['b','a'],replicates=500).weights)
        self.assertEqual(set(draws['accuracy']),{0,.5,1})

    def test_interval_denominator_policy(self):
        self.assertEqual(interval(.5,[np.nan]*6+[.5]*94)['reason'],'more than 5% undefined bootstrap replicates')
        self.assertIsNone(interval(.5,[np.nan]*5+[.5]*95)['reason'])
        self.assertEqual(interval(np.nan,[.5]*100)['reason'],'undefined denominator')


class LlmTests(unittest.TestCase):
    def test_distinct_requests_are_overall_only_for_shared_optimization_records(self):
        runs=[row('vulnerable',optimization='O2',repetition=k,run_id=f'r{k}') for k in (1,2,3)]
        expanded=runs+[dict(r,optimization='O3',observation_id='shared_O3') for r in runs]
        boot=PairBootstrap(['p0'],replicates=100)
        result,_=operational(expanded,runs,boot)
        distinct=[r for r in result if r['view']=='distinct_requests']
        self.assertTrue(distinct)
        self.assertEqual({r['factor'] for r in distinct},{'overall'})
        self.assertTrue(all(r['n']==3 for r in distinct))
        weighted=[r for r in result if r['view']=='observation_weighted' and r['factor']=='optimization'
                  and r['status']=='valid']
        self.assertEqual({r['level']:r['n'] for r in weighted},{'O2':3,'O3':3})
        # Reversing representatives may change their factor, never the request summary.
        o3_first=[dict(r,optimization='O3') for r in runs]
        reversed_result,_=operational(list(reversed(expanded)),o3_first,boot)
        self.assertEqual(distinct,[r for r in reversed_result if r['view']=='distinct_requests'])

    def test_failure_not_uncertain_vote_and_unique_request_denominator(self):
        runs=[row('vulnerable',repetition=1,run_id='r1'),row('vulnerable',repetition=2,run_id='r2'),
              row(None,repetition=3,run_id='r3',run_status='schema_invalid',confidence=None)]
        expanded=runs+[dict(r,observation_id='copy') for r in runs]
        boot=PairBootstrap(['p0'],replicates=100)
        agreement,patterns,correct=stability(expanded,boot)
        distinct_pattern=next(r for r in patterns if r['view']=='distinct_records')
        self.assertEqual(distinct_pattern['n'],1)
        self.assertIn('[schema_invalid]',distinct_pattern['vote_pattern'])
        self.assertNotIn('uncertain',distinct_pattern['vote_pattern'])
        matching=next(r for r in agreement if r['view']=='observation_weighted' and r['factor']=='overall'
                      and r['measure']=='pairwise_classification_agreement')
        self.assertEqual((matching['numerator'],matching['denominator']),(2,2))
        operational_rows,_=operational(expanded,runs,boot)
        actual=next(r for r in operational_rows if r['view']=='distinct_requests' and r['factor']=='overall' and r['status']=='schema_invalid')
        weighted=next(r for r in operational_rows if r['view']=='observation_weighted' and r['factor']=='overall' and r['status']=='schema_invalid')
        self.assertEqual((actual['n'],actual['events']),(3,1))
        self.assertEqual((weighted['n'],weighted['events']),(6,2))
        timeout=next(r for r in operational_rows if r['view']=='distinct_requests' and r['factor']=='overall' and r['status']=='timeout')
        self.assertAlmostEqual(timeout['zero_event_pair_upper_95'],.95)

    def test_high_confidence_boundaries_and_abstention(self):
        rows=[row('vulnerable',False,confidence=.8),row('not_vulnerable',True,confidence=.799),
              row('not_vulnerable',True,confidence=.8),row('uncertain',True,confidence=.99)]
        _,errors=confidence(rows,[])
        self.assertEqual(Counter(r['error_type'] for r in errors),
                         Counter(false_positive=1,false_negative_explicit=1,abstention=1))

    def test_uncertain_majority_cause_is_not_model_abstention(self):
        rows=[row('uncertain',method='llm_majority',uncertain_reason='insufficient_matching_votes',valid_runs=1,failed_runs=2),
              row('uncertain',method='llm_majority',uncertain_reason='model_abstention',valid_runs=3,failed_runs=0)]
        result=[r for r in decision_reasons(rows) if r['factor']=='overall']
        self.assertEqual({r['reason'] for r in result},{'insufficient_matching_votes','model_abstention'})
        self.assertTrue(all(r['cohort_n']==2 for r in result))

    def test_paired_method_differences_and_symbol_matching(self):
        rows=[]
        for pair in ('a','b'):
            for method in ('static','llm_majority'):
                for opt in ('O0','O1','O2','O3'):
                    for condition in ('retained','stripped'):
                        for cwe in ('CWE-121','CWE-122'):
                            for positive in (True,False):
                                rows.append(row('vulnerable',positive,pair=pair,method=method,optimization=opt,
                                    cwe=cwe,condition=condition,source_case_id=pair+cwe+str(positive)))
        boot=PairBootstrap(['a','b'],replicates=100)
        _,contrasts=performance_tables(rows,[],boot)
        for contrast in contrasts:
            if contrast['comparison']=='llm_majority - static' and contrast['estimate'] is not None:
                self.assertEqual((contrast['estimate'],contrast['ci_low'],contrast['ci_high']),(0,0,0))
        symbols=symbol_agreement(rows,boot)
        self.assertTrue(all(r['estimate']==1 for r in symbols))
        with self.assertRaises(ValueError):symbol_agreement(rows[:-1],boot)


class ModelTests(unittest.TestCase):
    def test_complete_quasicomplete_and_nonseparation(self):
        x=np.column_stack((np.ones(4),[-1,-1,1,1]))
        self.assertIsNotNone(screen(x,[0,0,1,1]))
        self.assertIsNone(screen(x,[0,1,0,1]))
        quasi=np.column_stack((np.ones(4),[-1,0,0,1]))
        self.assertIsNotNone(screen(quasi,[0,0,1,1]))
        self.assertEqual(screen(np.ones((4,2)),[0,1,0,1]),'rank-deficient fixed-effect design')

    def test_design_references_and_interactions(self):
        base=row('not_vulnerable',False)
        x,names=design([base])
        self.assertEqual(x.shape,(1,15))
        np.testing.assert_array_equal(x[0],[1]+[0]*14)
        x,_=design([row(optimization='O2',condition='stripped',method='llm_majority')])
        self.assertEqual(x[0,names.index('OptimizationO2:Methodllm_majority')],1)
        self.assertEqual(x[0,names.index('OptimizationO2:Stripped')],1)

    def test_fixed_selection_order(self):
        fits=[dict(specification='full',accepted=True),dict(specification='main_effects',accepted=True)]
        self.assertEqual(choose_record(fits),'full')
        fits[0]['accepted']=False
        self.assertEqual(choose_record(fits),'main_effects')
        fits[1]['accepted']=False
        self.assertIsNone(choose_record(fits))

    def test_lme4_reference_and_boundary_diagnostics(self):
        result=run_r({'self_test':True})
        self.assertTrue(result['self_test'])
        self.assertAlmostEqual(result['cbpp_coefficients'][0],-1.3992,places=3)

    def test_synthetic_clustered_model_and_primary_sensitivity(self):
        rng=np.random.default_rng(711)
        rows=[]
        for pair in range(36):
            intercept=rng.normal(0,.6)
            for opt,condition,method,positive in itertools.product(('O0','O1','O2','O3'),('retained','stripped'),('static','llm_majority'),(False,True)):
                eta=intercept+.35*(method=='llm_majority')-.2*(opt=='O3')
                correct=rng.random()<1/(1+np.exp(-eta))
                predicted=('vulnerable' if positive else 'not_vulnerable') if correct else ('not_vulnerable' if positive else 'vulnerable')
                rows.append(row(predicted,positive,pair=f'p{pair:02}',optimization=opt,condition=condition,method=method,
                                cwe='CWE-121' if pair<18 else 'CWE-122'))
        result=fit_models(rows)
        self.assertEqual(result['model_of_record']['Correct'],'full')
        self.assertEqual(result['model_of_record']['Correct_forced'],'full')
        coefficients={r['term']:r['estimate'] for r in result['fits'][0]['coefficients']}
        self.assertLess(abs(coefficients['Methodllm_majority']-.35),.7)

    def test_regeneration_detects_missing_extra_or_changed_files(self):
        with tempfile.TemporaryDirectory() as temp:
            a,b=Path(temp)/'a',Path(temp)/'b';a.mkdir();b.mkdir()
            (a/'one').write_text('same');(b/'one').write_text('same')
            self.assertEqual(compare_outputs(a,b),1)
            (b/'one').write_text('changed')
            with self.assertRaises(ValueError):compare_outputs(a,b)
            (b/'one').write_text('same');(b/'extra').write_text('extra')
            with self.assertRaises(ValueError):compare_outputs(a,b)

    def test_frozen_artifact_manifest_rejects_drift_and_unlisted_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            payload=root/'prediction.json';payload.write_text('{}')
            checksum=root/'checksums.sha256';checksum.write_text(file_hash(payload)+'  prediction.json\n')
            verify_checksums(root)
            payload.write_text('{"tampered":true}')
            with self.assertRaises(ValueError):verify_checksums(root)
            checksum.write_text(file_hash(payload)+'  prediction.json\n')
            extra=root/'extra';extra.write_text('extra')
            with self.assertRaises(ValueError):verify_checksums(root)
            checksum.write_text('0'*64+'  ../outside\n')
            with self.assertRaises(ValueError):verify_checksums(root)


if __name__=='__main__':unittest.main()
