"""Private source/effect oracle. Labels and proofs never enter Ghidra records."""
import argparse
import csv
import re
from collections import Counter
from pathlib import Path

from evaluation.check_oracle_mapping import Elf
from evaluation.corpus_selection import ROOT
from llm_analysis.common import decode, encode, file_hash, load, save, write

MANIFESTATIONS = {'present', 'transformed', 'relocated', 'eliminated', 'unresolved'}
KINDS = {'explicit_store_sequence', 'library_copy_call', 'string_instruction', 'loop_write', 'helper_call', 'transformed', 'eliminated'}
COPY_CALL = re.compile(r'^(?:call|jmp)\s+[0-9a-f]+\s+<(?:__)?(?:strcpy|wcscpy|strncpy|wcsncpy|memcpy|memmove|strcat|wcscat|strncat|wcsncat|memset|wmemset)(?:@|>)')


def load_oracle(path):
    rows = [decode(line) for line in Path(path).read_bytes().splitlines() if line.strip()]
    from jsonschema import Draft202012Validator
    validator = Draft202012Validator(load(Path(__file__).with_name('oracle_schema_v2.json')))
    for row in rows: validator.validate(row)
    if not rows or len({(r['sample_id'], r['optimization']) for r in rows}) != len(rows):
        raise ValueError('empty or duplicate oracle rows')
    return rows


def ranges(addresses, elf):
    result = []
    for address in sorted(set(addresses)):
        end = address + elf.insns[address][0]
        if result and result[-1][1] == address: result[-1][1] = end
        else: result.append([address, end])
    return [[hex(a), hex(b)] for a, b in result]


def effects(elf, start, end):
    stores = elf.store_addrs([(start, end)])
    # Arithmetic/atomic memory destinations also write. They must prevent a
    # false absence proof even when this corpus normally lowers copies to MOV.
    stores += [a for a,(_,t) in elf.insns.items() if start <= a < end
               and re.match(r'^(?:add|sub|and|or|xor|inc|dec|xchg|cmpxchg|pop)\s+(?:\w+ PTR )?\[', t)]
    calls = [a for a, (_, t) in elf.insns.items() if start <= a < end and COPY_CALL.match(t)]
    strings = [a for a, (_, t) in elf.insns.items() if start <= a < end and re.search(r'\b(?:rep\s+)?(?:movs|stos)[bwdq]?\b', t)]
    return stores, calls, strings


def store_intervals(elf, addresses):
    """Independent extent evidence for a straight-line lowered store sequence."""
    widths = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16, 'YMMWORD': 32}
    intervals, bases = [], set()
    for address in addresses:
        text = elf.insns[address][1]
        m = re.match(r'^mov\w*\s+(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD) PTR \[([a-z0-9]+)([+-]0x[0-9a-f]+)?\],', text)
        if not m: raise ValueError('store sequence has an unresolved destination expression')
        bases.add(m[2]); offset = int(m[3], 16) if m[3] else 0
        intervals.append([offset, offset + widths[m[1]]])
    if len(bases) != 1: raise ValueError('store sequence uses unproved different bases')
    merged = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1]: merged[-1][1] = max(merged[-1][1], hi)
        else: merged.append([lo, hi])
    return {'base_register': next(iter(bases)), 'intervals': intervals, 'merged_intervals': merged,
            'merged_extent_bytes': max(hi for lo,hi in merged) - min(lo for lo,hi in merged)}


def immediate_before(elf, address, register='di'):
    host = elf.host(address)
    value = None
    for a, (_, text) in sorted(elf.insns.items()):
        if elf.host(a) != host or a >= address: continue
        m = re.match(r'mov\s+[er]' + register + r',(0x[0-9a-f]+|[0-9]+)$', text)
        if m: value = int(m[1], 0)
        elif re.match(r'(?:mov|lea|xor|add|sub)\s+[er]' + register + ',', text): value = None
        elif text.startswith('call'): value = None
    return value


def loop_extent(elf, entry, canonical, writes):
    """Certify this corpus's counter/pointer loops from their actual bounds."""
    instructions={a:t for a,(_,t) in elf.insns.items() if elf.host(a)==entry}
    destinations=[(a,re.match(r'mov\w*\s+(BYTE|WORD|DWORD|QWORD) PTR \[([^]]+)\],',instructions[a])) for a in writes]
    destinations=[(a,m) for a,m in destinations if m]
    if len(destinations)!=1: raise ValueError('loop requires one certified destination write')
    write_address,store=destinations[0]
    width={'BYTE':1,'WORD':2,'DWORD':4,'QWORD':8}[store[1]]
    backedges=[]
    for a,t in instructions.items():
        m=re.match(r'(jbe|jne|jb)\s+([0-9a-f]+)',t)
        if m and canonical<=int(m[2],16)<=write_address<a: backedges.append((a,m[1],int(m[2],16)))
    if len(backedges)!=1: raise ValueError('destination loop backedge ambiguous')
    branch,condition,body=backedges[0]
    comparisons=[(a,t) for a,t in instructions.items() if write_address<a<branch and t.startswith('cmp')]
    if len(comparisons)!=1: raise ValueError('loop comparison ambiguous')
    compare,comparison=comparisons[0]
    counter=re.match(r'cmp\s+((?:QWORD|DWORD) PTR \[[^]]+\]),(0x[0-9a-f]+)$',comparison)
    if counter and condition in ('jbe','jb'):
        slot,limit=counter[1],int(counter[2],16)
        init=[a for a,t in instructions.items() if a<body and t==f'mov    {slot},0x0']
        increment=[a for a,t in instructions.items() if write_address<a<compare and t==f'add    {slot},0x1']
        scale=[a for a,t in instructions.items() if body<=a<write_address and re.search(r'\*[0-9]+',t)]
        if not init or len(increment)!=1 or not scale or not any('*'+str(width) in instructions[a] for a in scale):
            raise ValueError('index-loop initial value/increment/stride unproved')
        iterations=limit+int(condition=='jbe')
        return {'form':'index_counter','initialization':hex(max(init)),'increment':hex(increment[0]),'comparison':hex(compare),
                'backedge':hex(branch),'body_entry':hex(body),'write_address':hex(write_address),'iterations':iterations,
                'write_width_bytes':width,'byte_extent':iterations*width}
    pointer=re.match(r'cmp\s+([a-z0-9]+),([a-z0-9]+)$',comparison)
    if pointer and condition=='jne' and store[2]==pointer[1]:
        position,end=pointer[1],pointer[2]
        limits=[(a,re.match(r'lea\s+'+end+r',\[([a-z0-9]+)\+(0x[0-9a-f]+)\]$',t)) for a,t in instructions.items() if a<body]
        limits=[(a,m) for a,m in limits if m]
        increments=[a for a,t in instructions.items() if write_address<a<compare and t==f'add    {position},{hex(width)}']
        if len(limits)!=1 or len(increments)!=1: raise ValueError('pointer-loop limit/increment unproved')
        limit_address,limit=limits[0];base=limit[1];extent=int(limit[2],16)
        if base!=position:
            writes=[(a,t) for a,t in instructions.items() if a<body and re.match(r'(?:mov|lea|add|sub|xor|and)\s+'+position+',',t)]
            if not writes or max(writes)[1]!=f'mov    {position},{base}': raise ValueError('pointer-loop starting base differs')
            initial=max(writes)[0]
            if any(initial<a<limit_address and re.match(r'(?:mov|lea|add|sub|xor|and)\s+'+base+',',t) for a,t in instructions.items()):
                raise ValueError('pointer-loop base changed before limit setup')
        if extent%width: raise ValueError('pointer-loop extent not aligned with stride')
        return {'form':'pointer_limit','limit_setup':hex(limit_address),'increment':hex(increments[0]),'comparison':hex(compare),
                'backedge':hex(branch),'body_entry':hex(body),'write_address':hex(write_address),'iterations':extent//width,
                'write_width_bytes':width,'byte_extent':extent}
    raise ValueError('unsupported destination-loop bound')


def require_complete_extent(row, elf, record):
    operation=row['source_proof']['operation']
    opaque=bool(re.search(r'\b_(?:DAT|UNK)_[0-9a-f]+',record['decompilation']['text'] or ''))
    strings={'strcpy','wcscpy','strcat','wcscat','strncat','wcsncat','strncpy','wcsncpy'}
    bounded=operation in ('strncpy','wcsncpy') and immediate_before(elf,int(row['canonical_address'],16),'dx') is not None
    if row['operation_kind']=='library_copy_call' and operation in strings and opaque and not bounded:
        raise ValueError('context_insufficient: unavailable readonly source contents are required for string extent')


def draft(root):
    candidates = load(root / 'private/candidates.json')
    samples = {s['sample_id']: (c, s) for c in candidates if c['status'] == 'qualified' for s in c['samples']}
    manifest = list(csv.DictReader((root / 'artifacts/private/build_manifest.tsv').open(), delimiter='\t'))
    rows = []
    for build in manifest:
        sid, opt = build['sample_id'], build['optimization']; c, source = samples[sid]
        path = ROOT / build['oracle_path']; elf = Elf(path)
        span = source['target_source_span']
        source_ranges = sorted({r for line in range(span[0], span[1] + 1) for r in elf.line_ranges(line)})
        reachable = elf.reachable_from_main()
        candidates_by_host = {}
        for lo, hi in source_ranges:
            host = elf.host(lo)
            if host not in reachable: continue
            candidates_by_host.setdefault(host, []).append((lo, hi))
        instances = []
        for entry in sorted({elf.host(lo) for lo, _ in source_ranges} - {None}):
            size, name = elf.funcs[entry]
            instances.append({'entry': hex(entry), 'name': name, 'reachable': entry in reachable,
                              'source_ranges': [[hex(a), hex(b)] for a, b in source_ranges if elf.host(a) == entry]})
        choices = []
        for entry, selected_ranges in candidates_by_host.items():
            size, name = elf.funcs[entry]; all_effects = effects(elf, entry, entry + size)
            target_effects = [[a for a in values if any(lo <= a < hi for lo, hi in selected_ranges)] for values in all_effects]
            if any(target_effects): choices.append((size, entry, selected_ranges, target_effects))
        original_contexts = [(entry, size, name) for entry, (size, name) in elf.funcs.items()
                             if entry in reachable and (name == source['target_function'] or name == 'main')]
        row = {'schema_version': '2.0', 'sample_id': sid, 'pair_id': build['pair_id'], 'optimization': opt,
               'cwe': c['cwe'], 'source_ground_truth': source['source_ground_truth'],
               'source_path': source['source_path'], 'source_sha256': source['source_sha256'],
               'target_source_span': span, 'source_function': source['target_function'],
               'source_proof': source['proof'], 'oracle_sha256': file_hash(path), 'oracle_path': build['oracle_path'],
               'instances': instances, 'binary_manifestation': 'unresolved', 'operation_kind': None,
               'canonical_address': None, 'selected_function_entry': None, 'selected_function_name': None,
               'evidence_ranges': [], 'allocation_ranges': [], 'target_effect_ground_truth': None,
               'evidence_locality': 'unresolved', 'capacity_visibility': 'unresolved', 'verification': None}
        relocated = False
        if not choices:
            # A unique unchanged library operation inside a proven source/inline context
            # can be associated even when line attribution moved. Other effects remain unresolved.
            for entry, size, name in original_contexts:
                calls = [a for a, (_, text) in elf.insns.items() if entry <= a < entry + size
                         and re.match(r'^(call|jmp)\s+[0-9a-f]+\s+<' + source['proof']['operation'] + r'@', text)]
                if len(calls) == 1:
                    a = calls[0]; choices.append((size, entry, [(a, a + elf.insns[a][0])], [[], calls, []])); relocated = True
        if choices:
            size, entry, target_ranges, target_effects = min(choices, key=lambda item: (item[0], item[1]))
            stores, calls, strings = target_effects
            backwards = any(re.match(r'j\w*\s+([0-9a-f]+)', text) and int(re.match(r'j\w*\s+([0-9a-f]+)', text)[1], 16) < address
                            for address, (_, text) in elf.insns.items() if entry <= address < entry + size)
            if calls: canonical, kind = min(calls), 'library_copy_call'
            elif strings: canonical, kind = min(strings), 'string_instruction'
            elif source['proof']['operation'] == 'loop' and backwards:
                bodies=[]
                for a,(_,text) in elf.insns.items():
                    branch=re.match(r'(?:jbe|jne|jb)\s+([0-9a-f]+)',text)
                    if branch:
                        target=int(branch[1],16)
                        if target<=min(stores)<a and any(lo<=target<hi for lo,hi in target_ranges): bodies.append(target)
                if len(set(bodies))!=1: raise ValueError('destination-write loop body is ambiguous')
                canonical,kind=bodies[0],'loop_write'
            else: canonical, kind = min(stores), 'explicit_store_sequence'
            matching_call = any(re.search(r'<' + source['proof']['operation'] + r'@', elf.insns[a][1]) for a in calls)
            manifestation = 'present' if matching_call or kind == 'loop_write' else 'transformed'
            if relocated: manifestation = 'relocated'
            allocation_lines = [n for n, line in enumerate((ROOT / source['source_path']).read_text().splitlines(), 1)
                                if 'malloc(' in line or '__builtin_alloca(' in line or re.search(r'\bregion_[ab]\[', line)]
            allocation_ranges = [r for line in allocation_lines for r in elf.line_ranges(line) if elf.host(r[0]) == entry]
            if c['cwe'] == 'CWE-122' and not any('<malloc@plt>' in text for a, (_, text) in elf.insns.items() if entry <= a < entry + size):
                row['verification'] = 'target writes survive, but allocation is outside selected context or eliminated'
            else:
                evidence = [a for a in elf.insns if any(lo <= a < hi for lo, hi in target_ranges + allocation_ranges)]
                row.update(binary_manifestation=manifestation, operation_kind=kind, canonical_address=hex(canonical),
                           selected_function_entry=hex(entry), selected_function_name=elf.funcs[entry][1],
                           evidence_ranges=ranges(evidence, elf), allocation_ranges=[[hex(a), hex(b)] for a, b in allocation_ranges],
                           target_effect_ground_truth='vulnerable' if source['proof']['write_extent_bytes'] > source['proof']['capacity_bytes'] else 'not_vulnerable',
                           evidence_locality='local', capacity_visibility='explicit' if c['cwe'] == 'CWE-122' else 'not_explicit',
                           verification='source bounds/extent arithmetic; DWARF target span and disassembly implementing that effect; reachable enclosing function')
                row['effect_instruction_addresses'] = [hex(a) for a in sorted(set(stores + calls + strings))]
                if kind == 'explicit_store_sequence':
                    interval_proof = store_intervals(elf, stores)
                    if interval_proof['merged_extent_bytes'] != source['proof']['write_extent_bytes']:
                        raise ValueError(f'lowered extent differs from source proof: {sid}/{opt}')
                    row['store_interval_evidence'] = interval_proof
                if kind == 'loop_write':
                    loop=loop_extent(elf,entry,canonical,stores)
                    if loop['byte_extent']!=source['proof']['write_extent_bytes']: raise ValueError('actual loop extent differs from source proof')
                    row['loop_extent_evidence']=loop
                if c['cwe'] == 'CWE-122':
                    allocation_calls = [a for a,(_,text) in elf.insns.items() if entry <= a < entry + size and re.search(r'^(?:call|jmp).*<malloc@plt>', text)]
                    if len(allocation_calls) != 1: raise ValueError('allocation call is ambiguous')
                    actual_capacity = immediate_before(elf, allocation_calls[0])
                    if actual_capacity != source['proof']['capacity_bytes']: raise ValueError(f'machine allocation size differs: {sid}/{opt}')
                    row['allocation_argument_evidence'] = {'call_address': hex(allocation_calls[0]), 'requested_bytes': actual_capacity}
                if kind == 'library_copy_call' and source['proof']['operation'] in ('memcpy', 'memmove'):
                    length = immediate_before(elf, canonical, 'dx')
                    if length != source['proof']['write_extent_bytes']: raise ValueError('machine copy length differs from source proof')
                    row['copy_length_argument_evidence'] = {'register': 'RDX', 'bytes': length}
        else:
            # Positive absence proof: every reachable corresponding context has no explicit
            # write, copy/initialization call or string-write instruction. Missing DWARF is insufficient.
            if original_contexts and all(not any(effects(elf, entry, entry + size)) for entry, size, name in original_contexts):
                row.update(binary_manifestation='eliminated', operation_kind='eliminated',
                           verification='all reachable corresponding source/main contexts contain no explicit memory writes, copy/initialization calls, or string-write instructions',
                           evidence_locality='not_applicable', capacity_visibility='not_applicable',
                           elimination_contexts=[{'entry': hex(entry), 'name': name, 'end': hex(entry + size)} for entry, size, name in original_contexts])
            else: row['verification'] = 'no certified effect in source ranges; remaining memory effects require review'
        rows.append(row)
        disassembly = root / 'private/disassembly' / f'{sid}_{opt}.txt'
        from evaluation.check_oracle_mapping import run
        write(disassembly, run('objdump', '-dl', '-Mintel', '--insn-width=16', str(path)).encode())
        print(f'ORACLE {sid}/{opt}: {row["binary_manifestation"]} {row["operation_kind"]}', flush=True)
    write(root / 'private/oracle.jsonl', b''.join(encode(r).replace(b'\n', b'') + b'\n' for r in rows))
    return rows


def check(root, require_records=False):
    rows = load_oracle(root / 'private/oracle.jsonl')
    manifest = list(csv.DictReader((root / 'artifacts/private/build_manifest.tsv').open(), delimiter='\t'))
    expected = {(r['sample_id'], r['optimization']): r for r in manifest}
    if {(r['sample_id'], r['optimization']) for r in rows} != set(expected): raise ValueError('oracle matrix differs from build')
    for row in rows:
        b = expected[(row['sample_id'], row['optimization'])]
        if row['binary_manifestation'] not in MANIFESTATIONS or row['binary_manifestation'] == 'unresolved':
            raise ValueError(f'unresolved oracle: {row["sample_id"]}/{row["optimization"]}')
        if row['operation_kind'] not in KINDS: raise ValueError('invalid operation kind')
        if row['source_ground_truth'] != b['ground_truth'] or row['pair_id'] != b['pair_id']: raise ValueError('oracle truth/pair drift')
        if file_hash(ROOT / row['source_path']) != row['source_sha256'] or file_hash(ROOT / row['oracle_path']) != row['oracle_sha256']:
            raise ValueError('oracle/source drift')
        elf = Elf(ROOT / row['oracle_path'])
        if row['binary_manifestation'] == 'eliminated':
            if row['canonical_address'] is not None or row['target_effect_ground_truth'] is not None or row['selected_function_entry'] is not None or row['evidence_ranges']:
                raise ValueError('eliminated row invents target/context')
            contexts = row.get('elimination_contexts', [])
            if not contexts or any(any(effects(elf, int(c['entry'], 16), int(c['end'], 16))) for c in contexts):
                raise ValueError('elimination proof is false')
            continue
        if row['evidence_locality'] != 'local': raise ValueError('nonlocal primary evidence')
        entry, address = int(row['selected_function_entry'], 16), int(row['canonical_address'], 16)
        if entry not in elf.reachable_from_main() or elf.host(address) != entry or address not in elf.insns: raise ValueError('unreachable or invalid target')
        text = elf.insns[address][1]
        kind = row['operation_kind']
        if kind == 'library_copy_call' and not COPY_CALL.match(text): raise ValueError('canonical copy call is not a copy call')
        if kind == 'helper_call' and not text.startswith('call'): raise ValueError('canonical helper call is not a call')
        if kind == 'string_instruction' and not re.search(r'\b(?:rep\s+)?(?:movs|stos)[bwdq]?\b', text): raise ValueError('canonical string write is not a string instruction')
        if kind == 'explicit_store_sequence':
            addresses = [int(a,16) for a in row.get('effect_instruction_addresses', [])]
            if (not addresses or address != min(addresses) or store_intervals(elf, addresses) != row['store_interval_evidence']
                    or row['store_interval_evidence']['merged_extent_bytes']!=row['source_proof']['write_extent_bytes']):
                raise ValueError('invalid first-write/merged-extent evidence')
        if kind=='loop_write' and (loop_extent(elf,entry,address,[int(a,16) for a in row['effect_instruction_addresses']])!=row['loop_extent_evidence']
                                  or row['loop_extent_evidence']['byte_extent']!=row['source_proof']['write_extent_bytes']):
            raise ValueError('machine loop bound proof drift')
        if kind=='library_copy_call' and row['source_proof']['operation'] in ('memcpy','memmove'):
            if immediate_before(elf,address,'dx')!=row['source_proof']['write_extent_bytes']:
                raise ValueError('machine copy extent differs from source effect')
        if row['cwe'] == 'CWE-122':
            proof = row['allocation_argument_evidence']
            if immediate_before(elf, int(proof['call_address'],16)) != proof['requested_bytes'] or proof['requested_bytes'] != row['source_proof']['capacity_bytes']:
                raise ValueError('machine allocation proof drift')
        for lo, hi in row['evidence_ranges']:
            lo, hi = int(lo, 16), int(hi, 16)
            if lo not in elf.insns or hi not in elf.boundaries or lo >= hi or elf.host(lo) != entry or elf.host(hi - 1) != entry:
                raise ValueError('invalid evidence range')
        if not any(int(lo,16) <= address < int(hi,16) for lo,hi in row['evidence_ranges']): raise ValueError('canonical address lacks evidence')
        if row['target_effect_ground_truth'] != ('vulnerable' if row['source_proof']['write_extent_bytes'] > row['source_proof']['capacity_bytes'] else 'not_vulnerable'):
            raise ValueError('effect truth inconsistent with verified extent')
        if require_records:
            for condition in ('retained', 'stripped'):
                public = root / 'ghidra/records' / condition / f'{row["sample_id"]}_{row["optimization"]}.json'
                from llm_analysis.build_prompt import project
                record = load(public); project(public.read_bytes())
                if record['status'] != 'ok': raise ValueError('no recovered primary function')
                try: require_complete_extent(row,elf,record)
                except ValueError as error:
                    raise ValueError(f'{row["pair_id"]}/{row["sample_id"]}/{row["optimization"]}/{condition}: {error}') from error
                recovery = load(root / 'private/ghidra' / condition / f'{row["sample_id"]}_{row["optimization"]}.recovery.json')
                recovered = next((f for f in recovery if f['entry'] == record['function']['entry']), None)
                if recovered is None or recovered['body_ranges'] != record['function']['body_ranges']: raise ValueError('recovery evidence drift')
                bounds = record['function']['body_ranges']
                if not any(int(lo,16) <= address < int(hi,16) for lo,hi in bounds): raise ValueError('target outside recovered function')
                if any(not any(int(lo,16) <= int(a,16) and int(z,16) <= int(hi,16) for lo,hi in bounds) for a,z in row['evidence_ranges']):
                    raise ValueError('required local evidence outside recovered body')
                meta = load(root / 'private/ghidra' / condition / f'{row["sample_id"]}_{row["optimization"]}.run.json')
                if meta['program_sha256'] != file_hash(root / 'artifacts' / condition / f'{row["sample_id"]}_{row["optimization"]}.elf'):
                    raise ValueError('extraction binary drift')
                config = load(ROOT / 'ghidra/config.json')
                for key in ('ghidra_version', 'script_version', 'schema_version', 'language_id'):
                    if meta[key] != config[key]: raise ValueError('extraction configuration drift')
                if meta['decompiler_timeout_s'] != config['decompiler']['timeout_s'] or meta['target_address'] != row['selected_function_entry']:
                    raise ValueError('extraction target/timeout drift')
                if record['function']['instruction_count'] != len(record['instructions']): raise ValueError('record instruction count mismatch')
    print('Oracle verified:', dict(Counter(r['binary_manifestation'] for r in rows)))
    return rows


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['draft', 'check']); ap.add_argument('--root', type=Path, default=ROOT / 'datasets/final-v1')
    ap.add_argument('--records', action='store_true'); args = ap.parse_args()
    if args.command == 'draft': draft(args.root.resolve())
    else: check(args.root.resolve(), args.records)
