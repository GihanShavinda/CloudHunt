from __future__ import annotations

def ranking_agreement(expected_order: list[str], actual_order: list[str]) -> float:
    """Pairwise ordering agreement (Kendall-style, ties ignored)."""
    common = [x for x in expected_order if x in actual_order]
    if len(common) < 2:
        return 1.0 if common else 0.0
    pos = {x:i for i,x in enumerate(actual_order)}
    agree = total = 0
    for i in range(len(common)):
        for j in range(i+1,len(common)):
            total += 1
            if pos[common[i]] < pos[common[j]]: agree += 1
    return round(agree/total if total else 1.0, 4)
