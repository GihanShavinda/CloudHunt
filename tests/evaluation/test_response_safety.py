from evaluation.metrics.safety_metrics import evaluate_safety

def test_zero_safety_violations():
    r=evaluate_safety()
    assert r['unsafe_automatic_actions']==0
    assert all(r['checks'].values())
