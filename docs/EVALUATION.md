# CloudHunt P13 — Final Evaluation

P13 evaluates the existing CloudHunt pipeline without requiring real AWS credentials. Synthetic CloudTrail fixtures are structurally normalised by the production normaliser, then processed by the production signature, behavioural, advanced-detection and correlation components. IAM path evaluation uses the existing known-vulnerable IAM snapshots and production graph/privesc engine.

## Scenarios

The harness includes compromised credentials, IAM privilege escalation, multi-hop AssumeRole, S3 exfiltration, defense evasion, trust-policy backdoor, and benign CI automation controls. Benign controls are retained to make false-positive measurement meaningful.

## Ground truth

Machine-readable expectations live under `evaluation/ground_truth/`. Ground truth declares expected rules, chain actions, and known IAM paths; the harness does not hard-code result scores.

## Metrics

P13 calculates rule-set precision/recall/F1, binary false-positive rate, correlation cohesion, order-aware chain accuracy, IAM path similarity, and safety invariant results. Processing time is measured directly. Analyst MTTI/MTTR must only be reported when real or explicitly simulated analyst timestamps exist.

## Safety

The harness verifies that non-auto-eligible actions remain human-gated, account-scoped and irreversible actions cannot auto-run, and mobile approval tokens reject invalid/replayed values. AI remains outside the AWS write path.

## Run

```powershell
python evaluation\run_evaluation.py
python evaluation\run_evaluation.py --scenario defense-evasion
python scripts\run_final_demo.py
pytest tests\evaluation -v
pytest -v
```

Reports are written to `evaluation/reports/` as JSON, CSV, HTML and ATT&CK coverage JSON.

## Interpretation

A scenario PASS means its declared required detections were produced by the real CloudHunt engines and no evaluated response-safety invariant failed. Extra detections are not hidden: they reduce rule-set precision and should be reviewed as possible false positives. The overall safety target is zero unsafe automatic actions.

## Optional attack ranges

CloudGoat/Stratus Red Team recordings may be converted to the same fixture shape and replayed through the harness. Run these tools only in a dedicated lab/sandbox account; they are not required for the offline P13 acceptance path.
