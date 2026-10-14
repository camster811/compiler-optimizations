"""Manifest-driven build/extraction for a separate dataset; no analyzer tuning."""
import argparse
import csv
import json
import os
import re
import resource
import subprocess
import tempfile
from pathlib import Path

from evaluation.corpus_selection import ROOT, SIZES, facets
from llm_analysis.common import encode, file_hash, load, save, write

CFLAGS = ['-std=c11', '-Wall', '-Wextra', '-g', '-gdwarf-5', '-fno-stack-protector', '-U_FORTIFY_SOURCE',
          '-D_FORTIFY_SOURCE=0', '-fcf-protection=none', '-fno-pie',
          f'-fdebug-prefix-map={ROOT}=/experiment', f'-ffile-prefix-map={ROOT}=/experiment']
LDFLAGS = ['-no-pie', '-Wl,-z,noexecstack']
LEAK = re.compile(r'CWE-?12[12]|Juliet|source/(?:vulnerable|fixed)|(?:^|[^a-z0-9])(?:vulnerable|fixed|good|bad)(?:$|[^a-z0-9])', re.I)


def run(argv, **kwargs):
    return subprocess.run([str(a) for a in argv], capture_output=True, check=True, **kwargs)


def selected(root, ids=None):
    candidates = {c['candidate_id']: c for c in load(root / 'private/candidates.json')}
    selection = load(root / 'private/effective_selection.json') if (root / 'private/effective_selection.json').exists() else load(root / 'private/source_selection.json')
    chosen = ids or selection['selected']
    return [candidates[cid] for cid in chosen]


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def execute(path, directory):
    try:
        result = subprocess.run([str(path.resolve())], cwd=directory, capture_output=True, timeout=10, preexec_fn=no_core,
                                env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0:halt_on_error=1'})
        return {'returncode': result.returncode, 'timeout': False, 'stdout': result.stdout.decode(errors='replace')[:16000],
                'stderr': result.stderr.decode(errors='replace')[:16000]}
    except subprocess.TimeoutExpired as error:
        return {'returncode': None, 'timeout': True, 'stdout': '', 'stderr': str(error)}


def build(root, ids, optimizations):
    if run(['gcc-15', '-dumpfullversion'], text=True).stdout.strip() != '15.2.0': raise ValueError('GCC version drift')
    if run(['objcopy', '--version'], text=True).stdout.splitlines()[0].split()[-1] != '2.46': raise ValueError('binutils drift')
    with tempfile.TemporaryDirectory() as temporary:
        probe = Path(temporary) / 'sizes.c'
        probe.write_text('#include <stdio.h>\n#include <stdint.h>\n#include <wchar.h>\nint main(void) { printf("%zu %zu %zu %zu",sizeof(char),sizeof(int),sizeof(int64_t),sizeof(wchar_t)); }\n')
        binary = probe.with_suffix('')
        run(['gcc-15', probe, '-o', binary])
        measured = dict(zip(SIZES, map(int, run([binary], text=True).stdout.split())))
    if measured != SIZES: raise ValueError('platform sizes invalidate source proofs')
    save(root / 'private/platform_sizes.json', {'compiler': 'gcc-15', 'measured_sizeof': measured})
    samples = [(c, s) for c in selected(root, ids) for s in c['samples']]
    artifacts = root / 'artifacts'; rows = []
    for c, s in samples:
        source = ROOT / s['source_path']
        if file_hash(source) != s['source_sha256']: raise ValueError('sanitized source drift')
        for opt in optimizations:
            tag = f"{s['sample_id']}_{opt}"
            oracle = artifacts / 'oracle' / (tag + '.elf')
            oracle.parent.mkdir(parents=True, exist_ok=True)
            log = artifacts / 'private/logs' / (tag + '.txt'); log.parent.mkdir(parents=True, exist_ok=True)
            argv = ['gcc-15', *CFLAGS, '-' + opt, str(source), *LDFLAGS, '-o', str(oracle)]
            result = subprocess.run(argv, capture_output=True)
            write(log, result.stdout + result.stderr)
            if result.returncode: raise ValueError(f'compilation failed: {tag}')
            hashes = {}
            for condition in ('oracle', 'retained', 'stripped'):
                binary = artifacts / condition / (tag + '.elf'); binary.parent.mkdir(parents=True, exist_ok=True)
                if condition != 'oracle':
                    write(binary, oracle.read_bytes()); binary.chmod(0o755)
                    run(['objcopy', '--strip-debug', binary] if condition == 'retained' else ['strip', '--strip-all', binary])
                with tempfile.TemporaryDirectory() as temporary:
                    text = Path(temporary) / 'text.bin'
                    run(['objcopy', '--only-section=.text', '-O', 'binary', binary, text]); hashes[condition] = file_hash(text)
                sections = run(['readelf', '-SW', binary], text=True).stdout
                debug = bool(re.search(r'\.(?:z?debug_|gdb_index)', sections))
                if debug != (condition == 'oracle'): raise ValueError('DWARF derivation failure')
                if ('.symtab' in sections) != (condition != 'stripped'): raise ValueError('symbol derivation failure')
                if re.search(r'GNU_STACK.*RWE', run(['readelf', '-lW', binary], text=True).stdout): raise ValueError('executable stack')
                if condition != 'oracle' and LEAK.search(run(['strings', '-a', binary], text=True).stdout): raise ValueError('binary leakage')
            if len(set(hashes.values())) != 1: raise ValueError('.text differs across conditions')
            if '_chk@' in run(['nm', '-D', oracle], text=True).stdout: raise ValueError('FORTIFY import')
            with tempfile.TemporaryDirectory() as temporary: execution = execute(oracle, temporary)
            save(artifacts / 'private/runs' / (tag + '.json'), execution)
            if execution['timeout'] or (s['source_ground_truth'] == 'not_vulnerable' and execution['returncode'] != 0):
                raise ValueError(f'fixed execution or timeout failure: {tag}')
            rows.append({'sample_id': s['sample_id'], 'pair_id': 'pair_' + c['candidate_id'].split('_')[1],
                         'cwe': c['cwe'], 'ground_truth': s['source_ground_truth'],
                         'allocation': 'stack' if c['cwe'] == 'CWE-121' else 'heap', 'optimization': opt,
                         'source_path': s['source_path'], 'source_sha256': s['source_sha256'],
                         'gcc_version': '15.2.0', 'binutils_version': '2.46', 'compile_flags': ' '.join(CFLAGS + ['-' + opt] + LDFLAGS),
                         **{condition + '_path': str((artifacts / condition / (tag + '.elf')).relative_to(ROOT)) for condition in hashes},
                         **{condition + '_text_sha256': h for condition, h in hashes.items()}, 'validation_passed': 'true'})
            print(f'BUILD {tag}: text verified; exit={execution["returncode"]}', flush=True)
        # Diagnostic builds are separate and never extracted by Ghidra.
        diagnostic = artifacts / 'private/asan' / (s['sample_id'] + '.elf'); diagnostic.parent.mkdir(parents=True, exist_ok=True)
        run(['gcc-15', '-std=c11', '-g', '-O0', '-fsanitize=address', '-fno-omit-frame-pointer', source, '-o', diagnostic])
        with tempfile.TemporaryDirectory() as temporary: checked = execute(diagnostic, temporary)
        save(diagnostic.with_suffix('.json'), checked)
        if s['source_ground_truth'] == 'not_vulnerable' and (checked['timeout'] or checked['returncode'] != 0):
            raise ValueError(f'fixed ASan execution failure: {s["sample_id"]}')
    path = artifacts / 'private/build_manifest.tsv'; path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter='\t'); writer.writeheader(); writer.writerows(rows)
    save(artifacts / 'private/environment.json', {'gcc': run(['gcc-15', '--version'], text=True).stdout.splitlines()[0],
                                               'sizes': SIZES, 'optimization_scope': optimizations})
    return rows


def extract(root):
    from evaluation.oracle_v2 import load_oracle
    entries = load_oracle(root / 'private/oracle.jsonl')
    home = Path(os.environ.get('GHIDRA_HOME', str(ROOT / 'ghidra/ghidra_12.1.4_PUBLIC')))
    headless = home / 'support/analyzeHeadless'
    config = ROOT / 'ghidra/config.json'
    for row in entries:
        if row['binary_manifestation'] == 'eliminated': continue
        sid, opt = row['sample_id'], row['optimization']; tag = f'{sid}_{opt}'
        for condition in ('retained', 'stripped'):
            binary = root / 'artifacts' / condition / (tag + '.elf')
            public = root / 'ghidra/records' / condition / (tag + '.json')
            private = root / 'private/ghidra' / condition
            meta, recovery, log = (private / (tag + suffix) for suffix in ('.run.json', '.recovery.json', '.log'))
            public.parent.mkdir(parents=True, exist_ok=True); private.mkdir(parents=True, exist_ok=True)
            if public.exists() and meta.exists() and recovery.exists():
                m = load(meta)
                if m['program_sha256'] != file_hash(binary) or m['target_address'] != row['selected_function_entry']:
                    raise ValueError('stale extraction outputs')
                print(f'EXTRACT {condition}/{tag}: saved', flush=True); continue
            with tempfile.TemporaryDirectory(prefix='final-ghidra-') as temporary:
                work = Path(temporary); staged = work / (sid + '.elf'); write(staged, binary.read_bytes())
                (work / 'project').mkdir()
                result = subprocess.run([str(headless), str(work / 'project'), 'extract', '-import', str(staged),
                    '-scriptPath', str(ROOT / 'ghidra/scripts'), '-postScript', 'RecoverFunctions.java', str(recovery),
                    '-postScript', 'ExtractRegion.java', str(config), sid, row['selected_function_entry'], str(public), str(meta),
                    '-analysisTimeoutPerFile', '300', '-deleteProject'], capture_output=True, timeout=420)
                write(log, result.stdout + result.stderr)
                if result.returncode or b'SCRIPT ERROR' in log.read_bytes() or not public.exists() or not recovery.exists():
                    raise ValueError(f'Ghidra extraction failed: {condition}/{tag}; {log}')
            print(f'EXTRACT {condition}/{tag}: new', flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['build', 'extract'])
    ap.add_argument('--root', type=Path, default=ROOT / 'datasets/final-v1')
    ap.add_argument('--ids', nargs='*')
    ap.add_argument('--optimizations', nargs='+', default=['O0', 'O1', 'O2', 'O3'])
    args = ap.parse_args()
    if args.command == 'build': build(args.root.resolve(), args.ids, args.optimizations)
    else: extract(args.root.resolve())


if __name__ == '__main__': main()
