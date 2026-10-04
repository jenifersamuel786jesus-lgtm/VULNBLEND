from vulblend.services.experiment_engine import calculate_metrics, metric_label

def test_metrics():
    result = calculate_metrics(2, 1, 3, 1)
    assert result["precision"] == 2/3
    assert result["recall"] == 2/3
    assert round(result["f1"], 3) == .667
    assert result["false_positive_rate"] == .25

def test_zero_denominator_is_unavailable():
    result = calculate_metrics(0, 0, 0, 0)
    assert result["precision"] is None
    assert result["recall"] is None
    assert metric_label(None) == "Unavailable"
