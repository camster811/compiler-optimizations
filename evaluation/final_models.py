"""Predefined GLMM design, separation screen, and R/lme4 process boundary."""
import json
from pathlib import Path
import subprocess
import tempfile
import numpy as np
from scipy.optimize import linprog
from evaluation.analysis_environment import environment, r_command
from evaluation.final_metrics import counts

FORMULA = ('Correct ~ Optimization + Stripped + Method + CWE + GroundTruthLabel + '
           'Optimization:Method + Optimization:Stripped + Method:Stripped + (1 | pair_id)')


def design(rows, full=True):
    base = [np.ones(len(rows))]
    names = ['(Intercept)']
    fields = [('optimization', 'O1', 'OptimizationO1'), ('optimization', 'O2', 'OptimizationO2'),
              ('optimization', 'O3', 'OptimizationO3'), ('condition', 'stripped', 'Stripped'),
              ('method', 'llm_majority', 'Methodllm_majority'), ('truth_cwe', 'CWE-122', 'CWECWE-122'),
              ('target_effect_ground_truth', 'vulnerable', 'GroundTruthLabelvulnerable')]
    for field, level, name in fields:
        base.append(np.array([r[field] == level for r in rows], dtype=float)); names.append(name)
    if full:
        for left, right in [(i, 5) for i in (1, 2, 3)] + [(i, 4) for i in (1, 2, 3)] + [(4, 5)]:
            base.append(base[left]*base[right]); names.append(names[left]+':'+names[right])
    return np.column_stack(base), names


def screen(x, y):
    """Separation iff a nonzero nonnegative margin is feasible (bounded L1 beta).

    Maximize sum((2y-1) X beta), subject to nonnegative margins and ||beta||1<=1.
    Any positive optimum detects complete OR quasi-complete separation. Null-space
    directions alone have zero objective. Rank is checked independently.
    """
    if np.linalg.matrix_rank(x) < x.shape[1]:
        return 'rank-deficient fixed-effect design'
    signed = x * (2*np.asarray(y)-1)[:, None]
    a = np.column_stack((signed, -signed))
    fit = linprog(-a.sum(axis=0), A_ub=np.vstack((-a, np.ones(2*x.shape[1]))),
                  b_ub=np.r_[np.zeros(len(x)), 1.], bounds=(0, None), method='highs')
    if not fit.success:
        raise RuntimeError('separation screen failed: '+fit.message)
    return 'complete or quasi-complete separation' if -fit.fun > 1e-7 else None


def model_outcome(row, sensitivity=False):
    c = counts(row)
    return c['TP']+c['TN'] if sensitivity else c['primary_correct']


def choose_record(fits):
    return next((f['specification'] for f in fits if f['accepted']), None)


def fit_models(rows):
    jobs = []
    for sensitivity in (False, True):
        target = 'Correct_forced' if sensitivity else 'Correct'
        y = [model_outcome(r, sensitivity) for r in rows]
        for full in (True, False):
            x, names = design(rows, full)
            jobs.append(dict(outcome=target, specification='full' if full else 'main_effects',
                             rejection=screen(x, y), columns=names, x=x.tolist(), y=y))
    payload = dict(pair_ids=[r['pair_id'] for r in rows], jobs=jobs)
    result = run_r(payload)
    for target in ('Correct', 'Correct_forced'):
        fits = [f for f in result['fits'] if f['outcome'] == target]
        result.setdefault('model_of_record', {})[target] = choose_record(fits)
    return result


def run_r(payload):
    script = Path(__file__).with_name('final_glmm.R')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source, output = root/'input.json', root/'output.json'
        source.write_text(json.dumps(payload, allow_nan=False))
        cmd = r_command()
        if Path(cmd[0]).name == 'R':
            cmd += ['--file='+str(script), '--args', str(source), str(output)]
        else:
            cmd += [str(script), str(source), str(output)]
        completed = subprocess.run(cmd, env=environment(), capture_output=True, text=True, timeout=180)
        if completed.returncode or not output.exists():
            raise RuntimeError('R/lme4 execution failed (not a statistical fallback):\n'+completed.stderr+completed.stdout)
        return json.loads(output.read_text())
