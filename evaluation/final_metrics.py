"""Phase H scoring definitions and whole-source-pair percentile bootstrap.

These functions never reuse nullable Phase G binary_correct as an operational score.
Strict three-way correctness checks CWE; primary Correct checks classification only.
Forced alerts intentionally count uncertain/unavailable negatives as TN, with provenance.
"""
from collections import defaultdict
import numpy as np

SEED = 20261014
REPLICATES = 10000
COUNT_NAMES = ('n', 'correct', 'incorrect', 'abstain', 'unavailable', 'decided',
               'primary_correct', 'wrong_cwe', 'TP', 'TN', 'FP', 'FN', 'TP_exact_cwe',
               'TN_from_not_vulnerable', 'TN_from_abstention', 'TN_from_failure',
               'FN_from_not_vulnerable', 'FN_from_abstention', 'FN_from_failure')
RATE_NAMES = ('coverage', 'abstention_rate', 'unavailable_rate', 'selective_accuracy',
              'primary_correct_rate', 'accuracy', 'balanced_accuracy', 'precision',
              'recall', 'f1', 'false_positive_rate', 'false_negative_rate', 'tp_exact_cwe_rate')


def counts(row):
    cls = row['classification']
    if cls not in (None, 'uncertain', 'vulnerable', 'not_vulnerable'):
        raise ValueError('unknown classification')
    truth = row['target_effect_ground_truth']
    if truth not in ('vulnerable', 'not_vulnerable'):
        raise ValueError('non-eligible ground truth')
    positive = truth == 'vulnerable'
    alert = cls == 'vulnerable'
    decided = cls in ('vulnerable', 'not_vulnerable')
    primary = decided and alert == positive
    exact = row['predicted_cwe'] == row['truth_cwe']
    correct = primary and (not positive or exact)
    cell = ('TP' if positive else 'FP') if alert else ('FN' if positive else 'TN')
    result = dict.fromkeys(COUNT_NAMES, 0)
    result.update(n=1, correct=int(correct), incorrect=int(decided and not correct),
                  abstain=int(cls == 'uncertain'), unavailable=int(cls is None), decided=int(decided),
                  primary_correct=int(primary), wrong_cwe=int(positive and alert and not exact),
                  TP_exact_cwe=int(positive and alert and exact))
    result[cell] = 1
    if not alert:
        reason = 'from_failure' if cls is None else 'from_abstention' if cls == 'uncertain' else 'from_not_vulnerable'
        result[cell+'_'+reason] = 1
    return result


def outcome(row):
    c = counts(row)
    return next(k for k in ('correct', 'incorrect', 'abstain', 'unavailable') if c[k])


def divide(numerator, denominator):
    a, b = np.broadcast_arrays(np.asarray(numerator, dtype=float), np.asarray(denominator, dtype=float))
    return np.divide(a, b, out=np.full(a.shape, np.nan), where=b != 0)


def rates(values):
    c = {name: values[..., i] for i, name in enumerate(COUNT_NAMES)}
    sensitivity = divide(c['TP'], c['TP']+c['FN'])
    specificity = divide(c['TN'], c['TN']+c['FP'])
    return dict(coverage=divide(c['decided'], c['n']), abstention_rate=divide(c['abstain'], c['n']),
                unavailable_rate=divide(c['unavailable'], c['n']),
                selective_accuracy=divide(c['correct'], c['decided']),
                primary_correct_rate=divide(c['primary_correct'], c['n']),
                accuracy=divide(c['TP']+c['TN'], c['n']), balanced_accuracy=(sensitivity+specificity)/2,
                precision=divide(c['TP'], c['TP']+c['FP']), recall=sensitivity,
                f1=divide(2*c['TP'], 2*c['TP']+c['FP']+c['FN']),
                false_positive_rate=1-specificity, false_negative_rate=1-sensitivity,
                tp_exact_cwe_rate=divide(c['TP_exact_cwe'], c['TP']))


def finite(value):
    return float(value) if np.isfinite(value) else None


def interval(point, draws):
    valid = np.asarray(draws)[np.isfinite(draws)]
    usable = len(valid)
    reason = 'undefined denominator' if not np.isfinite(point) else (
        'more than 5% undefined bootstrap replicates' if usable < .95*len(draws) else None)
    limits = [None, None] if reason else np.quantile(valid, [.025, .975]).tolist()
    return dict(estimate=finite(point), ci_low=limits[0], ci_high=limits[1],
                bootstrap_usable=usable, bootstrap_total=len(draws), reason=reason)


class PairBootstrap:
    def __init__(self, pairs, replicates=REPLICATES, seed=SEED):
        self.pairs = sorted(set(pairs))
        self.index = {p: i for i, p in enumerate(self.pairs)}
        rng = np.random.default_rng(seed)
        picks = rng.integers(0, len(self.pairs), size=(replicates, len(self.pairs)))
        self.weights = np.stack([(picks == i).sum(axis=1) for i in range(len(self.pairs))], axis=1)

    def count_matrix(self, rows):
        matrix = np.zeros((len(self.pairs), len(COUNT_NAMES)), dtype=np.int64)
        for row in rows:
            c = counts(row)
            matrix[self.index[row['pair_id']]] += [c[k] for k in COUNT_NAMES]
        return matrix

    def performance(self, rows):
        matrix = self.count_matrix(rows)
        total = matrix.sum(axis=0)
        point, draws = rates(total), rates(self.weights @ matrix)
        report = {k: int(total[i]) for i, k in enumerate(COUNT_NAMES)}
        report.update(n_pairs=len({r['pair_id'] for r in rows}), n_records=len({r['record_sha256'] for r in rows}))
        for metric in RATE_NAMES:
            ci = interval(point[metric], draws[metric])
            report[metric] = ci.pop('estimate')
            report.update({metric+'_'+k: v for k, v in ci.items()})
        return report, draws

    def ratio(self, rows, numerator, denominator):
        matrix = np.zeros((len(self.pairs), 2))
        for row in rows:
            matrix[self.index[row['pair_id']]] += [numerator(row), denominator(row)]
        total, draws = matrix.sum(axis=0), self.weights @ matrix
        return interval(divide(total[0], total[1]), divide(draws[:, 0], draws[:, 1]))


FACTORS = ('optimization', 'condition', 'truth_cwe', 'target_effect_ground_truth',
           'capacity_visibility', 'binary_manifestation', 'input_label_conflict_group')


def groups(rows, include_method=True, include_interaction=True):
    """Deterministic method-by-factor strata, plus the optimization/symbol interaction."""
    dimensions = [()] + [(f,) for f in FACTORS]
    if include_interaction:
        dimensions += [('optimization', 'condition')]
    if rows and 'repetition' in rows[0]:
        dimensions += [('repetition',)]
    for dimensions_ in dimensions:
        dims = (('method',) if include_method else ()) + dimensions_
        grouped = defaultdict(list)
        for row in rows:
            grouped[tuple(str(row[d]) for d in dims)].append(row)
        for values, subset in sorted(grouped.items()):
            label = dict(zip(dims, values))
            yield dict(method=label.get('method', 'llm'), factor='+'.join(dimensions_) or 'overall',
                       level='|'.join(label[d] for d in dimensions_) or 'all'), subset
