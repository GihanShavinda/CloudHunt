from __future__ import annotations

def chain_accuracy(expected_actions: list[str], actual_actions: list[str]) -> float:
    """Order-aware LCS similarity, bounded [0,1]."""
    if not expected_actions:
        return 1.0 if not actual_actions else 0.0
    dp = [0] * (len(actual_actions) + 1)
    for e in expected_actions:
        prev = 0
        for j, a in enumerate(actual_actions, 1):
            old = dp[j]
            dp[j] = prev + 1 if e == a else max(dp[j], dp[j-1])
            prev = old
    return round(dp[-1] / max(len(expected_actions), len(actual_actions), 1), 4)
