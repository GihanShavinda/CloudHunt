SCENARIO = {
    "id": 'iam-privesc',
    "attack": True,
    "expected_detection_keys": ['bhv-automation-iam-write'],
    "expected_actions": ['AssumeRole', 'PassRole', 'CreateFunction', 'InvokeFunction'],
}
