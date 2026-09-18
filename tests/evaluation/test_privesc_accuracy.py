from evaluation.metrics.graph_metrics import compare_paths

def test_exact_path():
    r=compare_paths(['a','b','c'],['a','b','c'])
    assert r['exact_path_match'] and r['path_similarity']==1.0
