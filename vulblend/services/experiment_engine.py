"""Research evaluation metrics for controlled ground-truth runs."""
from __future__ import annotations


def ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def calculate_metrics(tp: int, fp: int, tn: int, fn: int, execution_time: float | None = None, crawl_coverage: float | None = None, verification_rate: float | None = None) -> dict:
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": ratio(fp, fp + tn), "verification_rate": verification_rate, "execution_time": execution_time, "crawl_coverage": crawl_coverage}


def metric_label(value: float | None, percent: bool = True) -> str:
    if value is None:
        return "Unavailable"
    return f"{value * 100:.1f}%" if percent else f"{value:.2f}"
