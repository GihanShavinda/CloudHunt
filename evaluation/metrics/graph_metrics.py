from __future__ import annotations

def _edges(path: list[str]) -> set[tuple[str,str]]:
    return set(zip(path, path[1:]))

def compare_paths(expected: list[str], actual: list[str]) -> dict:
    if not expected and not actual:
        return {'exact_path_match': True, 'edge_precision': 1.0, 'edge_recall': 1.0, 'path_similarity': 1.0}
    ee, ae = _edges(expected), _edges(actual)
    common = ee & ae
    ep = len(common) / len(ae) if ae else 0.0
    er = len(common) / len(ee) if ee else 0.0
    # ordered-prefix aware similarity plus edge agreement
    positional = sum(1 for a,b in zip(expected,actual) if a==b) / max(1, max(len(expected),len(actual)))
    similarity = round((positional + (2*ep*er/(ep+er) if ep+er else 0.0))/2, 4)
    return {'exact_path_match': expected == actual, 'edge_precision': round(ep,4), 'edge_recall': round(er,4), 'path_similarity': similarity}
