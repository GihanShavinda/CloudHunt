from evaluation.metrics.ranking_metrics import ranking_agreement

def test_ranking_agreement():
    assert ranking_agreement(['C','B','A'],['C','B','A'])==1.0
    assert ranking_agreement(['C','B','A'],['A','B','C'])==0.0
