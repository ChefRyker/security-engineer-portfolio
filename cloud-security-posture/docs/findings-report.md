# CIS AWS Findings Report

_Generated: 2025-06-01 14:32 UTC — example output from a real audit run_

**Pass:** 5  **Fail:** 2  **Total:** 7

| Control | Check | Status | Detail | Remediation |
|---------|-------|--------|--------|-------------|
| 1.4 | No root access keys | PASS | No root access keys found. | |
| 1.5 | Root account MFA enabled | PASS | Root MFA is active. | |
| 1.8-1.11 | IAM password policy | FAIL | Issues: minimum length < 14, passwords do not expire | Update password policy in IAM console to meet all CIS requirements. |
| 2.1.5 | S3 account public access block | PASS | All four S3 account public access block settings are enabled. | |
| 3.1 | CloudTrail multi-region enabled | PASS | 1 multi-region trail(s) active. | |
| 3.2 | CloudTrail log file validation | PASS | All trails have log file validation enabled. | |
| 3.9 | GuardDuty enabled | FAIL | No GuardDuty detector in us-east-1. | Enable GuardDuty in the GuardDuty console. |

## Remediation Priority

1. **[3.9] GuardDuty** — Enable immediately; no cost for 30-day trial. Provides real-time threat detection.
2. **[1.8-1.11] Password Policy** — Update minimum length to 14+ and enable expiry (90 days recommended).
