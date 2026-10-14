"""Final matrix/effect contracts; synthetic generations only."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evaluation.check_llm_predictions import check
from evaluation.corpus_selection import number, proof, fingerprint, select, verify_source_inputs
from evaluation.corpus_replacement import replace
from evaluation.oracle_v2 import store_intervals, immediate_before, effects, require_complete_extent, loop_extent
from evaluation.prepare_llm_experiment import validate_experiment, load_experiment
from llm_analysis.common import config, digest, encode, file_hash, save, write
from llm_analysis.run_llm import prepare, verify, execute_run, export
from llm_analysis.tests.test_pipeline import record, prediction, response


def fixture(root):
    observations = []
    files = []
    for sid, truth in (('sample_0101', 'vulnerable'), ('sample_0102', 'not_vulnerable')):
        for opt in ('O0', 'O2'):
            for condition in ('retained', 'stripped'):
                eligible = opt == 'O0'
                path = root / f'{sid}_{opt}_{condition}.json'
                h = None
                if eligible:
                    public = record(); public['sample_id'] = sid
                    public['function']['name'] = 'copy_payload' if condition == 'retained' else 'FUN_0010'
                    write(path, encode(public)); files.append(path); h = file_hash(path)
                observations.append(dict(observation_id=f'{sid}:{opt}:{condition}', sample_id=sid, pair_id='pair_0101',
                    optimization=opt, condition=condition, cwe='CWE-121', source_ground_truth=truth,
                    binary_manifestation='transformed' if eligible else 'eliminated', target_effect_ground_truth=truth if eligible else None,
                    inference_eligible=eligible, inference_disposition='eligible' if eligible else 'proven_eliminated',
                    evidence_locality='local' if eligible else 'not_applicable', capacity_visibility='not_explicit' if eligible else 'not_applicable',
                    record_path=path.name if eligible else None, record_sha256=h,
                    prompt_tokens=3968 if eligible else None, context_eligible=True if eligible else None,
                    context_rejection_reason=None, rendered_prompt_sha256='a'*64 if eligible else None))
    return dict(schema_version='2.0', dataset_id='synthetic-final', development_data=True, oracle_sha256='a'*64, context_evidence_sha256='b'*64,
                expected_matrix=dict(conditions=['retained','stripped'], cases=[dict(sample_id=s, optimization=o)
                    for s in ('sample_0101','sample_0102') for o in ('O0','O2')]), observations=observations), files


class FinalContractTests(unittest.TestCase):
    def test_missing_readonly_inputs_are_not_hidden_as_local_evidence(self):
        class FakeElf:
            insns={0x10:(5,'call   400 <wcscpy@plt>')}
            def host(self,a): return 0x10
        row={'operation_kind':'library_copy_call','source_proof':{'operation':'wcscpy'},'canonical_address':'0x10'}
        public={'decompilation':{'text':'source = _DAT_00402020; wcscpy(dst, source);'}}
        with self.assertRaisesRegex(ValueError,'context_insufficient'): require_complete_extent(row,FakeElf(),public)
        row['operation_kind']='explicit_store_sequence'
        require_complete_extent(row,FakeElf(),public)
        row['operation_kind']='library_copy_call';row['source_proof']['operation']='wcsncpy'
        FakeElf.insns={0x10:(5,'mov    edx,0xb'),0x15:(5,'call   400 <wcsncpy@plt>')};row['canonical_address']='0x15'
        require_complete_extent(row,FakeElf(),public)

    def test_loop_extent_comes_from_machine_bound_and_stride(self):
        class FakeElf:
            insns={0x10:(4,'mov    QWORD PTR [rbp-0x8],0x0'),0x14:(2,'jmp    30 <copy+0x20>'),
                   0x16:(4,'lea    rdx,[rax*4+0x0]'),0x1a:(3,'mov    DWORD PTR [rdx],eax'),
                   0x1d:(4,'add    QWORD PTR [rbp-0x8],0x1'),0x21:(4,'cmp    QWORD PTR [rbp-0x8],0x9'),
                   0x25:(2,'jbe    16 <copy+0x6>')}
            def host(self,a): return 0x10
        extent=loop_extent(FakeElf(),0x10,0x16,[0x1a])
        self.assertEqual(extent['body_entry'],'0x16')
        self.assertEqual(extent['iterations'],10)
        self.assertEqual(extent['byte_extent'],40)
    def test_late_failure_replaces_whole_pair_and_preserves_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            save(root/'private/source_selection.json',{'selected':['a','b'],'reserve_order':['wrong_family','next','last']})
            save(root/'private/optimization_scope.json',{'optimizations':['O0','O1','O2','O3']})
            candidates=[{'candidate_id':cid,'cwe':cwe,'samples':[{'sample_id':sid}]} for cid,cwe,sid in
                        [('a','CWE-121','sample_0101'),('b','CWE-122','sample_0102'),('wrong_family','CWE-122','sample_0103'),('next','CWE-121','sample_0104'),('last','CWE-121','sample_0105')]]
            save(root/'private/candidates.json',candidates)
            for opt in ('O0','O1','O2','O3'):
                write(root/'ghidra/records/retained'/f'sample_0101_{opt}.json',b'{}')
            original=(root/'private/optimization_scope.json').read_bytes()
            self.assertEqual(replace(root,'a','ambiguous mapping',['O3:stripped']),'next')
            self.assertFalse(any((root/'ghidra/records/retained').glob('*.json')))
            self.assertEqual(len(list((root/'private/technical_rejections/a/ghidra/records/retained').glob('*.json'))),4)
            self.assertEqual((root/'private/optimization_scope.json').read_bytes(),original)
            self.assertEqual(replace(root,'next','context limit',['O0:retained']),'last')
            with self.assertRaisesRegex(ValueError,'reserve exhausted'): replace(root,'last','mapping',['O1:retained'])
            save(root/'private/corpus-freeze.json',{})
            with self.assertRaisesRegex(ValueError,'frozen corpus'): replace(root,'last','mapping',['O1:retained'])

    def test_actual_store_union_and_instruction_mechanisms(self):
        class FakeElf:
            insns={0x10:(3,'mov    edi,0xb'),0x13:(5,'call   400 <malloc@plt>'),
                   0x18:(3,'mov    QWORD PTR [rax],rbx'),0x1b:(4,'mov    DWORD PTR [rax+0x7],0'),
                   0x1f:(2,'rep movsb BYTE PTR es:[rdi],BYTE PTR ds:[rsi]')}
            def host(self,address): return 0x10
            def store_addrs(self,ranges): return [a for a in (0x18,0x1b) if any(lo<=a<hi for lo,hi in ranges)]
        elf=FakeElf()
        merged=store_intervals(elf,[0x18,0x1b])
        self.assertEqual(merged['merged_intervals'],[[0,11]])
        self.assertEqual(immediate_before(elf,0x13),11)
        self.assertEqual(effects(elf,0x10,0x21)[2],[0x1f])
        elf.insns[0x1b]=(4,'mov    DWORD PTR [rdx+0x7],0')
        with self.assertRaisesRegex(ValueError,'different bases'): store_intervals(elf,[0x18,0x1b])

    def test_local_stack_capacity_and_elimination_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); experiment, _ = fixture(root)
            validate_experiment(experiment, root)
            for modification in ('oversized', 'split', 'fabricated', 'manifestation', 'truth'):
                broken = copy.deepcopy(experiment)
                if modification == 'oversized': broken['observations'][0]['prompt_tokens'] = 3969
                elif modification == 'split': broken['observations'][0]['evidence_locality'] = 'not_applicable'
                elif modification == 'fabricated': broken['observations'][2]['record_sha256'] = 'a'*64
                elif modification == 'manifestation': broken['observations'][1]['binary_manifestation'] = 'present'
                else: broken['observations'][4]['source_ground_truth'] = 'vulnerable'
                with self.subTest(modification=modification), self.assertRaises(ValueError): validate_experiment(broken, root)

    def test_eliminated_rows_never_become_false_negatives_or_abstentions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); experiment, files = fixture(root)
            path = root/'experiment.json'; save(path,experiment); write(path.with_suffix('.json.sha256'), (file_hash(path)+'\n').encode())
            _, h = load_experiment(path)
            save(root/'runtime.json', {'artifacts': {}})
            campaign = prepare(files, root/'runtime.json', root/'campaigns', config(), experiment_sha256=h)
            manifest = verify(campaign)
            flight = {'records': {h:{'prompt_tokens':100,'fits_context':True} for h in manifest['record_hashes']}}
            save(campaign/'preflight.json',flight)
            calls = []
            def transport(c, route, payload):
                calls.append(route)
                return dict(http_status=200,headers=[],body=response(prediction('not_vulnerable')),error=None,latency_seconds=0.1)
            for job in manifest['schedule']: execute_run(campaign,job,manifest,flight,exchange_fn=transport,idle_fn=lambda c:None)
            export(campaign); report = check(campaign,path)
            self.assertEqual(len(calls), 12)
            self.assertEqual(report['planned_observations'],8)
            self.assertEqual(report['overall']['observations'],4)
            self.assertEqual(report['overall']['binary_alert']['FN'],2)
            self.assertEqual(report['overall']['abstentions'],0)
            self.assertEqual(report['source_origin_view']['non_analyzable_observations'],4)
            self.assertEqual(report['source_origin_view']['non_analyzable_source_ground_truth_counts'],{'vulnerable':2,'not_vulnerable':2})
            self.assertEqual(report['paired_run_symbol_summary']['matched_pairs'],6)

    def test_source_proof_includes_bounded_concat_terminator(self):
        body = "char * data; data = (char*)malloc(10); data[0]='\\0'; char source[11]=SRC_STRING; strncat(data,source,10);"
        self.assertEqual(proof(body)['write_extent_bytes'],11)
        self.assertEqual(number('10*sizeof(wchar_t)'),40)
        self.assertEqual(fingerprint('int *data; data=malloc(10);'), fingerprint('int *data; data=malloc(20);'))
        self.assertEqual(fingerprint('int *data; data=malloc(10);'), fingerprint('int *buffer; buffer=malloc(20);'))
        with self.assertRaises(ValueError): number('__import__("os")')
        verify_source_inputs(body,'#define SRC_STRING "AAAAAAAAAA"',proof(body))
        with self.assertRaisesRegex(ValueError,'literal length'):
            verify_source_inputs(body,'#define SRC_STRING "AA"',proof(body))


if __name__ == '__main__': unittest.main()
