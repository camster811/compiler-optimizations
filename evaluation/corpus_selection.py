"""Source-only, deterministic Juliet selection; never reads analyzer predictions."""
import argparse
import ast
import difflib
import hashlib
import json
import random
import re
from pathlib import Path

from llm_analysis.common import encode, file_hash, load, save, write

ROOT = Path(__file__).resolve().parent.parent
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\d+|\S')
COPY = re.compile(r'\b(strcpy|wcscpy|strncpy|wcsncpy|memcpy|memmove|strcat|wcscat|strncat|wcsncat)\s*\(')
LEAK = re.compile(r'cwe|juliet|good|bad|fixed|vulnerable', re.I)
SIZES = {"char": 1, "int": 4, "int64_t": 8, "wchar_t": 4}
POLICY = {
    "version": "1.0", "dataset_id": "final-v1", "pairs_per_cwe": 10,
    "candidate_flows": ["01", "31"], "adaptation": "original bodies; equivalent common standalone harness",
    "eligibility": "CWE131, CWE193, CWE805 or destination-copy family; one target copy/loop to the declared allocation; initialized inputs",
    "duplicate_policy": "ignore identifiers/literals/comments; reject equal pair fingerprints; retain substantive type, allocation, repair, primitive or pointer-flow differences",
    "selection": "greedy unmet diversity gain; original path tie-break; deterministic reserve order",
    "required": {"mechanisms_per_cwe": 4, "repairs_per_cwe": 3, "pointer_flows_per_cwe": 2,
                 "capacity_bands": ["small", "medium", "large"], "structures": ["straight_line", "loop", "helper"]},
    "optimization_gate": "four-pair batch, one generic correction pass, then fixed O0/O1/O2/O3 or O0/O2",
    "whole_pair_replacement": True, "no_completion_requests": True,
    "context_scope": "all non-eliminated function records fit exact frozen context without truncation",
}


def clean(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def balanced(text, start, opening='(', closing=')'):
    depth = 0
    quoted = None
    escaped = False
    for i in range(start, len(text)):
        c = text[i]
        if quoted:
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == quoted: quoted = None
            continue
        if c in "\"'": quoted = c; continue
        if c == opening: depth += 1
        if c == closing:
            depth -= 1
            if depth == 0: return text[start + 1:i], i + 1
    raise ValueError("unbalanced source construct")


def arguments(text):
    values, start, depth = [], 0, 0
    for i, c in enumerate(text):
        if c in '([': depth += 1
        elif c in ')]': depth -= 1
        elif c == ',' and depth == 0: values.append(text[start:i].strip()); start = i + 1
    return values + [text[start:].strip()]


def number(expression):
    expression = re.sub(r'sizeof\s*\(\s*(char|int|int64_t|wchar_t)\s*\)', lambda m: str(SIZES[m[1]]), expression)
    tree = ast.parse(expression.strip(), mode='eval')
    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int: return node.value
        if isinstance(node, ast.BinOp):
            a, b = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Add): return a + b
            if isinstance(node.op, ast.Sub): return a - b
            if isinstance(node.op, ast.Mult): return a * b
        raise ValueError(f"unsupported capacity expression: {expression}")
    return visit(tree.body)


def bodies(source):
    source = clean(source)
    bad = re.search(r'\bvoid\s+\w+_bad\s*\([^)]*\)\s*\{', source)
    good = re.search(r'\b(?:static\s+)?void\s+goodG2B\s*\([^)]*\)\s*\{', source)
    if not bad or not good: raise ValueError("no comparable original allocation-repair bodies")
    return [balanced(source, m.end() - 1, '{', '}')[0] for m in (bad, good)]


def proof(body):
    dtype = re.search(r'\b(char|wchar_t|int64_t|int)\s*\*\s*data\s*;', body)
    if not dtype: raise ValueError("unsupported target type or compound object")
    dtype = dtype[1]
    allocation = None
    source_object = None
    for m in re.finditer(r'\b(malloc|ALLOCA)\s*\(', body):
        prefix = body[max(0, body.rfind(';', 0, m.start()) + 1):m.start()]
        if 'data' in prefix:
            expression, _ = balanced(body, m.end() - 1)
            variable = re.search(r'(data\w*)\s*=.*$', prefix, re.S)
            if variable and variable[1] == 'data': allocation = number(expression); source_object = 'data'
    assignment = re.search(r'\bdata\s*=\s*(data(?:Bad|Good)?Buffer)\s*;', body)
    if assignment:
        variable = assignment[1]
        declared = re.search(r'\b' + variable + r'\s*\[([^]]+)\]', body)
        if declared: allocation = number(declared[1]) * SIZES[dtype]
        else:
            m = re.search(r'\b' + variable + r'\s*=.*?\bALLOCA\s*\(', body)
            if m: allocation = number(balanced(body, m.end() - 1)[0])
        source_object = variable
    if allocation is None: raise ValueError("target allocation capacity cannot be established")
    calls = list(COPY.finditer(body))
    if len(calls) == 1:
        m = calls[0]; args, end = balanced(body, m.end() - 1); args = arguments(args)
        if args[0] != 'data': raise ValueError("selected write targets another allocation/CWE family")
        op = m[1]
        start = m.start()
    elif not calls:
        writes = list(re.finditer(r'\bdata\s*\[i\]\s*=\s*source\s*\[i\]\s*;', body))
        if len(writes) != 1: raise ValueError("no unique target copy or destination-write loop")
        m = writes[0]; start, end = m.span(); op = 'loop'
        bound = re.search(r'for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*([^;]+);', body[:start])
        if not bound: raise ValueError("unsupported loop bound")
    else: raise ValueError("multiple independent copy targets")
    # All selected source families use initialized 11- or 100-element inputs.
    src = re.search(r'\b' + dtype + r'\s+source\s*\[([^]]+)\]', body)
    if not src: raise ValueError("source extent unavailable")
    elements = number(src[1])
    terminated = dtype in ('char', 'wchar_t')
    if terminated and not ('SRC_STRING' in body or re.search(r'source\s*\[[^]]+\]\s*=\s*(?:L)?\'\\0\'', body)):
        raise ValueError("source termination not established")
    if op in ('strcpy', 'wcscpy', 'strcat', 'wcscat'):
        extent = elements * SIZES[dtype]
    elif op in ('strncat', 'wcsncat'):
        expression = re.sub(r'(?:strlen|wcslen)\s*\(source\)', str(elements - 1), args[2])
        extent = (min(number(expression), elements - 1) + 1) * SIZES[dtype]
    else:
        expression = args[2] if calls else bound[1]
        expression = re.sub(r'(?:strlen|wcslen)\s*\(source\)|sourceLen', str(elements - 1), expression)
        extent = number(expression) * (SIZES[dtype] if op not in ('memcpy', 'memmove') else 1)
    # Exclude copies accompanied by a second independently overflowing terminator store.
    for index in re.findall(r'\bdata\s*\[([^]]+)\]\s*=\s*(?:L)?\'\\0\'', body):
        if number(index) * SIZES[dtype] >= allocation: raise ValueError("second independent out-of-bounds terminator write")
    return {"capacity_bytes": allocation, "write_extent_bytes": extent, "data_type": dtype,
            "destination_object": source_object, "operation": op, "body_target_span": [start, end],
            "pointer_flow": "alias" if 'dataCopy' in body else "direct",
            "structures": ["helper", "loop" if op == 'loop' else "straight_line"]}


def fingerprint(body):
    names = {}
    keep = set(SIZES) | {'malloc', 'ALLOCA', 'sizeof', 'for', 'if', 'while', 'NULL',
                        'memcpy', 'memmove', 'strcpy', 'wcscpy', 'strncpy', 'wcsncpy', 'strcat', 'wcscat', 'strncat', 'wcsncat'}
    tokens = []
    for t in TOKEN.findall(clean(body)):
        if t[0].isdigit() or t[0] in "\"'": tokens.append('literal')
        elif re.fullmatch(r'[A-Za-z_]\w*', t) and t not in keep:
            tokens.append(names.setdefault(t, 'id' + str(len(names))))
        else: tokens.append(t)
    return hashlib.sha256(' '.join(tokens).encode()).hexdigest()


def verify_source_inputs(body, upstream, facts):
    """Certify initialization/string length, independently of the benchmark label."""
    dtype=facts['data_type']
    match=re.search(r'\b'+dtype+r'\s+source\s*\[([^]]+)\]',body)
    if not match: raise ValueError('source array unavailable')
    elements=number(match[1])
    if dtype not in ('char','wchar_t'):
        if not re.match(r'\s*=\s*\{0\}',body[match.end():]): raise ValueError('source elements are not initialized')
        return
    if 'SRC_STRING' in body:
        literal=re.search(r'^#define\s+SRC_STRING\s+L?"([^"\\]*)"\s*$',clean(upstream),re.M)
        if not literal or len(literal[1])+1!=elements: raise ValueError('literal length differs from certified source extent')
    else:
        fill=re.search(r'\b(memset|wmemset)\s*\(\s*source\s*,\s*(L?\'[^\']+\')\s*,\s*([^;]+)\);',body)
        null=re.search(r'source\s*\[([^]]+)\]\s*=\s*L?\'\\0\'',body)
        if (not fill or not null or fill[2] not in ("'A'","'C'","L'A'","L'C'")
                or number(fill[3])!=elements-1 or number(null[1])!=elements-1
                or (fill[1]=='wmemset')!=(dtype=='wchar_t')):
            raise ValueError('source fill/termination does not certify claimed string length')


def sanitize(body, macros):
    replacements = {'dataBadBuffer': 'region_a', 'dataGoodBuffer': 'region_b', 'dataBuffer': 'region',
                    'dataCopy': 'alias', 'SRC_STRING': 'PAYLOAD', 'ALLOCA': '__builtin_alloca'}
    text = body
    for a, b in replacements.items(): text = re.sub(r'\b' + a + r'\b', b, text)
    text = re.sub(r'printLine\(([^;]+)\);', r'puts(\1);', text)
    text = re.sub(r'printWLine\(([^;]+)\);', r'wprintf(L"%ls\\n", \1);', text)
    text = re.sub(r'printIntLine\(([^;]+)\);', r'printf("%d\\n", \1);', text)
    text = re.sub(r'printLongLongLine\(([^;]+)\);', r'printf("%lld\\n", (long long)(\1));', text)
    text = '\n'.join(line.rstrip() for line in text.splitlines() if line.strip())
    header = '#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n#include <string.h>\n#include <wchar.h>\n'
    if macros: header += macros.replace('SRC_STRING', 'PAYLOAD') + '\n'
    return header + '\nvoid copy_payload(void)\n{\n' + text + '\n}\n\nint main(void)\n{\n    copy_payload();\n    return 0;\n}\n'


def facets(candidate):
    p = candidate['proofs'][0]
    band = 'small' if p['capacity_bytes'] <= 16 else 'medium' if p['capacity_bytes'] <= 64 else 'large'
    return {('mechanism', p['operation']), ('repair', candidate['repair_pattern']),
            ('flow', p['pointer_flow']), ('type', p['data_type']), ('band', band)} | {('structure', s) for s in p['structures']}


def select(candidates, rejected=(), count=10):
    chosen = []
    for cwe in ('CWE-121', 'CWE-122'):
        seen = set()
        pool = [c for c in candidates if c['status'] == 'qualified' and c['cwe'] == cwe and c['candidate_id'] not in rejected]
        for _ in range(count):
            if not pool: raise ValueError(f"reserve exhausted for {cwe}")
            def priority(c):
                new = facets(c) - seen
                gain = sum({'mechanism': 5, 'repair': 5, 'flow': 4, 'type': 1, 'band': 2, 'structure': 3}[f[0]] for f in new)
                return (-gain, c['original_path'])
            best = min(pool, key=priority); chosen.append(best); seen |= facets(best); pool.remove(best)
        if len({v for k, v in seen if k == 'mechanism'}) < 4 or len({v for k, v in seen if k == 'repair'}) < 3 or len({v for k, v in seen if k == 'flow'}) < 2:
            raise ValueError(f"diversity requirements not met for {cwe}")
    all_facets = set().union(*(facets(c) for c in chosen))
    if not {('band', b) for b in ('small', 'medium', 'large')} <= all_facets:
        raise ValueError("capacity-band diversity not met")
    return chosen


def inventory(root=ROOT / 'datasets/final-v1'):
    policy_path = root / 'private/selection_policy.json'
    if policy_path.exists() and load(policy_path) != POLICY: raise ValueError('selection policy drift')
    if not policy_path.exists(): save(policy_path, POLICY, immutable=True)
    if (root / 'private/candidates.json').exists():
        candidates = load(root / 'private/candidates.json')
        for c in candidates:
            for sample in c.get('samples', []):
                if file_hash(ROOT / sample['source_path']) != sample['source_sha256']: raise ValueError('existing candidate source drift')
        print('Existing source inventory verified; no reselection or renaming')
        return
    paths = sorted(p for family in ('CWE121_Stack_Based_Buffer_Overflow', 'CWE122_Heap_Based_Buffer_Overflow')
                   for p in (ROOT / 'corpus' / family).rglob('*.c') if p.name.endswith(('_01.c', '_31.c')))
    candidates, seen = [], {}
    for index, p in enumerate(paths, 1):
        source = p.read_text()
        candidate = {'candidate_id': f'candidate_{index:04d}', 'original_path': str(p.relative_to(ROOT)),
                     'original_sha256': file_hash(p), 'cwe': 'CWE-121' if 'CWE121' in p.name else 'CWE-122',
                     'status': 'rejected', 'reason': None, 'sanitization_status': 'not_attempted', 'duplicate_status': 'not_screened'}
        write(root / 'private/upstream' / p.name, p.read_bytes())
        try:
            if not any(tag in p.name for tag in ('CWE131_', 'CWE193_', 'CWE805_', '__dest_', '__c_dest_')):
                raise ValueError('outside prespecified initialized allocation/copy families; source truth not certified')
            if 'struct' in p.name: raise ValueError('upstream testcase support type layout is unavailable')
            if 'CWE193_char_' in p.name and p.name.endswith('_cpy_01.c'):
                raise ValueError('development-pilot mechanism/repair near duplicate')
            original_bodies = bodies(source)
            proofs = [proof(b) for b in original_bodies]
            for body,facts in zip(original_bodies,proofs): verify_source_inputs(body,source,facts)
            if not proofs[0]['write_extent_bytes'] > proofs[0]['capacity_bytes'] or proofs[1]['write_extent_bytes'] > proofs[1]['capacity_bytes']:
                raise ValueError('source byte arithmetic does not establish vulnerable/fixed pair')
            if proofs[0]['operation'] != proofs[1]['operation']: raise ValueError('repair changes copy mechanism')
            key = tuple(fingerprint(b) for b in original_bodies)
            if key in seen:
                candidate.update(duplicate_status='near_duplicate', duplicate_of=seen[key]); raise ValueError('normalized pair duplicates earlier candidate')
            seen[key] = candidate['candidate_id']
            macros = '\n'.join(re.findall(r'^#define\s+SRC_STRING\s+[^\n]+', clean(source), re.M))
            sanitized = [sanitize(b, macros) for b in original_bodies]
            samples = []
            for member, text in enumerate(sanitized):
                if LEAK.search(text): raise ValueError('sanitized source leaks a benchmark identifier')
                sid = f'sample_{1000 + index * 2 + member:04d}'
                path = root / 'source' / f'{sid}.c'
                write(path, text.encode())
                lines = text.splitlines()
                targets = [n for n, line in enumerate(lines, 1) if COPY.search(line) or re.search(r'\bdata\[i\]\s*=\s*source\[i\]', line)]
                if len(targets) != 1: raise ValueError('sanitization has no deterministic unique target location')
                samples.append({'sample_id': sid, 'source_path': str(path.relative_to(ROOT)),
                                'source_sha256': file_hash(path), 'source_ground_truth': 'vulnerable' if member == 0 else 'not_vulnerable',
                                'target_function': 'copy_payload', 'target_source_span': [targets[0], targets[0]],
                                'proof': proofs[member]})
            # IDs are permuted independently of truth; filenames cannot encode member parity.
            candidate.update(status='qualified', reason='source arithmetic and equivalent neutral bodies verified',
                             sanitization_status='reviewed', duplicate_status='unique', samples=samples, proofs=proofs,
                             repair_pattern='element_size' if 'CWE131_' in p.name else 'terminator_capacity' if 'CWE193_' in p.name else 'destination_capacity',
                             source_diff=list(difflib.unified_diff(sanitized[0].splitlines(), sanitized[1].splitlines(), lineterm='')))
            write(root / 'private/upstream' / p.name, p.read_bytes())
        except (ValueError, SyntaxError) as error: candidate['reason'] = str(error)
        candidates.append(candidate)
    # Permute neutral IDs once, before any analyzer results exist.
    qualified = [c for c in candidates if c['status'] == 'qualified']
    ids = [f'sample_{n:04d}' for n in range(101, 101 + 2 * len(qualified))]
    random.Random('final-v1:opaque-source-ids').shuffle(ids)
    for c in qualified:
        for sample in c['samples']:
            old = ROOT / sample['source_path']; raw = old.read_bytes(); old.unlink()
            sample['sample_id'] = ids.pop()
            target = root / 'source' / (sample['sample_id'] + '.c')
            write(target, raw); sample['source_path'] = str(target.relative_to(ROOT))
    save(root / 'private/candidates.json', candidates)
    chosen = select(candidates)
    # Freeze the greedy reserve ordering with the same source-only rules.
    reserve = []
    for cwe in ('CWE-121', 'CWE-122'):
        pool = [c for c in qualified if c['cwe'] == cwe and c not in chosen]
        reserve += [c['candidate_id'] for c in sorted(pool, key=lambda c: c['original_path'])]
    save(root / 'private/source_selection.json', {'selected': [c['candidate_id'] for c in chosen], 'reserve_order': reserve,
                                                'analyzer_results_used': False}, immutable=True)
    print(f'{len(candidates)} considered, {len(qualified)} source-qualified, {len(chosen)} provisionally selected')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=ROOT / 'datasets/final-v1')
    args = ap.parse_args(); inventory(args.root.resolve())
