SCENARIO = {
    "id": 's3-exfiltration',
    "attack": True,
    "expected_detection_keys": ['m8-s3-exfil-anomaly'],
    "expected_actions": ['ListBucket', 'GetObject'],
}
