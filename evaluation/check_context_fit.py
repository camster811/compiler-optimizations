"""Token-only eligibility with the exact selected method; no completion endpoint."""
import argparse
from pathlib import Path
from llm_analysis.build_prompt import request
from llm_analysis.common import HERE, config, digest, file_hash, load, method_files, now, save
from llm_analysis.transport import json_call


def check(records, output):
    c = config()
    pointer = load(HERE / 'frozen/current.json')
    receipt = load(HERE.parent / pointer['receipt_path'])
    if file_hash(HERE.parent / pointer['receipt_path']) != pointer['receipt_sha256'] or receipt['method']['files'] != method_files() or receipt['method']['config'] != c:
        raise ValueError('selected method drift before tokenization')
    for name, h in receipt['method']['runtime']['artifacts'].items():
        if file_hash(Path(name)) != h: raise ValueError('frozen tokenizer/backend artifact drift')
    props = json_call(c, '/props')
    if (props['model_path'] != c['model_path'] or props['total_slots'] != 1
            or props['default_generation_settings']['n_ctx'] != c['context_tokens']
            or props['chat_template'].rstrip('\n') != (HERE / 'chat_template.jinja').read_text().rstrip('\n')):
        raise ValueError('tokenizer server differs from frozen method')
    counts = {}
    for path in sorted(records):
        raw = path.read_bytes(); h = digest(raw)
        if h in counts: continue
        payload = request(c, raw, h, 1)
        rendered = json_call(c, '/apply-template', {'messages': payload['messages'], 'add_generation_prompt': True})['prompt']
        if not rendered.endswith('<｜Assistant｜><think>\n'): raise ValueError('frozen reasoning prefix differs')
        tokens = json_call(c, '/tokenize', {'content': rendered, 'add_special': False, 'parse_special': True})['tokens']
        fits = len(tokens) + c['max_tokens'] + c['context_reserve'] <= c['context_tokens']
        counts[h] = {'prompt_tokens': len(tokens), 'rendered_prompt_sha256': digest(rendered.encode()),
                     'fits_context': fits, 'context_rejection_reason': None if fits else 'complete prompt plus frozen generation budget/reserve exceeds context'}
    result = {'method_id': pointer['method_id'], 'checked_at': now(), 'records': counts,
              'endpoints_used': ['/props', '/apply-template', '/tokenize'], 'completion_requests': 0,
              'tokenization_options': {'add_special': False, 'parse_special': True, 'add_generation_prompt': True},
              'context_tokens': c['context_tokens'], 'generation_allowance': c['max_tokens'], 'reserve': c['context_reserve']}
    save(output, result)
    print(f'Token-only validation: {len(counts)} distinct records; {sum(not x["fits_context"] for x in counts.values())} oversized; no completions')
    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('inputs', nargs='+', type=Path); ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    records = [p for value in args.inputs for p in (value.glob('*.json') if value.is_dir() else [value])]
    check(records, args.output)
