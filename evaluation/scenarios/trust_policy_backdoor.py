SCENARIO = {
    "id": 'trust-policy-backdoor',
    "attack": True,
    "expected_detection_keys": ['m8-backdoor-trust-policy'],
    "expected_actions": ['UpdateAssumeRolePolicy'],
}
