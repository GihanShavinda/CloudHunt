from evaluation.metrics.detection_metrics import from_counts, rule_set_metrics

def test_metrics_math():
    m=from_counts(8,2,18,2)
    assert round(m.precision,2)==0.80 and round(m.recall,2)==0.80
    assert round(m.f1,2)==0.80 and round(m.false_positive_rate,2)==0.10

def test_rule_set_metrics():
    m=rule_set_metrics({'a','b'},{'a','c'})
    assert (m.tp,m.fp,m.fn)==(1,1,1)
