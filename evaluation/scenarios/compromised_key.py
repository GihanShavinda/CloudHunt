SCENARIO = {
    "id": 'compromised-key',
    "attack": True,
    "expected_detection_keys": ['bhv-new-geo', 'bhv-enumeration-burst'],
    "expected_actions": ['Discovery (8 reads)', 'AssumeRole'],
}
