from evaluation.metrics.correlation_metrics import correlation_score

def test_complete_case_scores_one():
    assert correlation_score({'1','2'},[{'1','2'}]) == 1.0

def test_contamination_penalised():
    assert correlation_score({'1','2'},[{'1','2','b'}],{'b'}) < 1.0
