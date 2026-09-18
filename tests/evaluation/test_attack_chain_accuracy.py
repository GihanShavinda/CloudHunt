from evaluation.metrics.attack_chain_metrics import chain_accuracy

def test_chain_order():
    assert chain_accuracy(['A','B','C'],['A','B','C'])==1.0
    assert chain_accuracy(['A','B','C'],['C','B','A']) < 1.0
