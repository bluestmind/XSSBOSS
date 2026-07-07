"""Deterministic precision/recall gates for scanner benchmark runs."""
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class AccuracyMetrics:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    complete: bool
    missing_cases: tuple[str, ...]

    def as_dict(self) -> dict:
        result = asdict(self)
        result["missing_cases"] = list(self.missing_cases)
        return result


def evaluate_accuracy(truth_cases: Iterable[dict], predictions: Iterable[dict]) -> AccuracyMetrics:
    """Compare one prediction per slug against a versioned ground-truth set."""
    truth = {str(case["slug"]): bool(case["expected_vulnerable"]) for case in truth_cases}
    predicted = {str(case["slug"]): bool(case["detected"]) for case in predictions}
    missing = tuple(sorted(set(truth) - set(predicted)))
    tp = fp = tn = fn = 0
    for slug, expected in truth.items():
        detected = predicted.get(slug, False)
        if expected and detected:
            tp += 1
        elif not expected and detected:
            fp += 1
        elif not expected and not detected:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return AccuracyMetrics(tp, fp, tn, fn, precision, recall, f1, not missing, missing)


def passes_accuracy_gate(
    metrics: AccuracyMetrics,
    minimum_precision: float = 0.98,
    minimum_recall: float = 0.95,
) -> bool:
    return metrics.complete and metrics.precision >= minimum_precision and metrics.recall >= minimum_recall
