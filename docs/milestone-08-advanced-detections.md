# Milestone 8 — Advanced detection capabilities

Milestone 8 adds snapshot- and baseline-aware detectors **without UI work and without an AI assistant**. All findings use the existing `Detection` record, so they can be injected into `DetectionEngine.run(..., advanced_detections=...)` and correlated with the existing three-layer engine.

## 1. Least-privilege drift

### Granted-but-unused permissions

`detect_granted_but_unused()` compares Milestone 2 `EffectivePermissions` against CloudTrail actions observed during a configurable lookback (30 days by default). A grant is considered used when an observed `service:Action` matches one of its action patterns. Conditional grants are excluded by default because the offline evaluator cannot prove their runtime condition was satisfiable.

**ATT&CK:** T1548 (Abuse Elevation Control Mechanism). This mapping describes the security relevance of excessive privilege; an unused permission by itself is posture/drift evidence, not proof an adversary abused it.

**False-positive traps:** break-glass/DR privileges, incomplete CloudTrail/data-event coverage, seasonal jobs, and intentionally dormant operational permissions.

### Newly created privilege-escalation paths

`detect_new_privesc_paths()` fingerprints and diffs successive Milestone 3 `PrivEscPath` snapshots. Only paths that are present in the new snapshot and absent in the previous one fire.

**ATT&CK:** T1548.

**False-positive traps:** approved IAM deployments, incomplete snapshots, and condition-dependent graph edges that require runtime context.

## 2. Backdoor trust-policy detection

`detect_backdoor_trust_policy()` compares role trust documents and fires when the new policy:

- adds `Principal: "*"`;
- adds a principal from another AWS account (unless allowlisted); or
- removes a prior trust condition, including `sts:ExternalId` or MFA-related condition atoms.

Both dictionary and URL-encoded JSON policy documents are accepted.

**ATT&CK:** T1098 (Account Manipulation).

**False-positive traps:** sanctioned partner/vendor trusts, federation patterns protected by other controls, and IAM refactors that move an equivalent restriction elsewhere.

## 3. S3 exfiltration analytics

`S3BaselineModel.fit()` learns, per principal, daily `GetObject` count, byte volume (when enriched telemetry is present), and normal AWS regions. `detect_s3_exfiltration()` then flags:

- `GetObject` count spikes;
- byte-volume spikes;
- access from a region absent from the baseline; and
- public-access weakening (`DeletePublicAccessBlock`, permissive `PutPublicAccessBlock`, public ACLs, or wildcard bucket policies) on a bucket supplied in `sensitive_buckets`.

Anomaly thresholds use `mean + 3σ` plus an absolute floor, which prevents tiny baselines from producing noisy alerts. A principal without a baseline is not scored as anomalous.

**ATT&CK:** T1530 (Data from Cloud Storage) and T1537 (Transfer Data to Cloud Account). Sensitive-bucket public-access weakening is mapped to T1537 because it can enable transfer/exposure through another cloud identity/account.

**False-positive traps:** backup/export jobs, analytics, migrations, incident-response collection, disaster-recovery region changes, and intentional public datasets/static sites.

### Telemetry note

Standard CloudTrail S3 data events provide API activity and region, but byte volume may require enrichment (for example, object-size or transfer telemetry from another AWS log/source). The normaliser preserves `additionalEventData.bytesTransferred` when present; callers can also enrich `CloudEvent.params["bytesTransferred"]` before scoring.

## Tests

`tests/test_detect_advanced.py` uses fixtures under `tests/fixtures/m8/` and contains should-fire/should-not-fire cases for:

- used vs unused permissions;
- new vs unchanged privilege-escalation paths;
- trust condition removal, wildcard trust, unchanged trust, and allowlisted external trust;
- normal vs anomalous S3 volume, cross-region access, and sensitive vs non-sensitive public-access changes.
