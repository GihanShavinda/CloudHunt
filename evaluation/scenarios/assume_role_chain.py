SCENARIO = {
    "id": 'assume-role-chain',
    "attack": True,
    "expected_detection_keys": ['bhv-new-geo'],
    "expected_actions": ['AssumeRole', 'AssumeRole', 'AssumeRole'],
}
