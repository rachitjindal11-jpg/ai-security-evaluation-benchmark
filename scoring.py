"""Deterministic scoring of structured security findings."""
from collections.abc import Iterable, Mapping


def _pairs(items: Iterable[Mapping[str, str]]) -> set[tuple[str, str]]:
    result = set()
    for item in items:
        case_id = item.get("case_id")
        cwe = item.get("cwe")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Each finding requires a nonempty case_id")
        if not isinstance(cwe, str) or not cwe.startswith("CWE-"):
            raise ValueError("Each finding requires a CWE identifier")
        result.add((case_id, cwe))
    return result


def evaluate(ground_truth: Iterable[Mapping[str, str]], findings: Iterable[Mapping[str, str]]) -> dict:
    expected = _pairs(ground_truth)
    predicted = _pairs(findings)
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}
