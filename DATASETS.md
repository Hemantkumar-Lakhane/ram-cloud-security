# RAM Cloud Security — Dataset Strategy & Empirical Evaluation

## 1. Dataset Strategy & Principles

1. **Synthetic Data Guardrail:** Synthetic fixtures (under `tests/fixtures/`) are strictly restricted to parser, ingestion, and unit tests. They are **never** used for model training, validation, research evaluation, or performance claims.
2. **Telemetry Alignment:** The primary dataset must consist of genuine AWS CloudTrail audit logs with realistic multi-service API activity, accurate timestamps, and representative user identities.
3. **Reproducibility & Open Licensing:** Datasets must possess clear provenance and open licenses (e.g. MIT, Apache 2.0).

---

## 2. Selected Real Dataset (Acquired & Validated in Phase 1.5)

### Stratus Red Team CloudTrail Attack Dataset (`invictus-ir/aws_dataset`)
- **Source & Provenance:** Published by Invictus Incident Response ([GitHub](https://github.com/invictus-ir/aws_dataset)). Generated via DataDog Stratus Red Team adversary emulation on live AWS infrastructure.
- **License:** MIT License.
- **Local Storage:** `data/raw/stratus_cloudtrail/CloudTrail/` (55 JSON log files, preserved unmodified).
- **Parity with Schema:** 2,900 / 2,900 events successfully normalized into `NormalizedEvent` (0 parsing errors).

### Empirical Summary (from EDA in `experiments/results/eda_summary.json`):
- **Total Events:** 2,900
- **Time Duration:** 2023-07-10 11:42:18 UTC to 12:37:50 UTC (55.5 minutes continuous session).
- **Service Breadth:** 29 distinct AWS services (`ec2`, `ssm`, `iam`, `s3`, `kms`, `secretsmanager`, `rds`, `sts`, `cloudtrail`, `guardduty`, `securityhub`, etc.).
- **Event Types:** 260 distinct API event names.
- **Identities:** 13 distinct IAM principals (2 IAM Users, 10 Assumed Roles, 1 AWS Service).
- **Activity Breakdown:**
  - Stratus Red Team Detonations: 1,146 events (39.52%)
  - Terraform Infrastructure Setup/Teardown: 1,938 events (66.83%)
  - Standard AWS Background Calls: 748 events (25.79%)
- **Error Profile:** 300 errors (10.34% error rate), including `ThrottlingException`, `UnauthorizedOperation`, and `AccessDenied`.

---

## 3. Attack Scenarios & Kill-Chain Mapping

The real dataset captures adversarial activity across multiple MITRE ATT&CK tactics:
- **Discovery (380+ events):** `DescribeRouteTables`, `DescribeParameters`, `DescribeAccountAttributes`, `DescribeInstanceInformation`, `DescribeDBInstances`, `DescribeSecurityGroups`, `DescribeTrails`, `GetCallerIdentity`, `ListAccessKeys`.
- **Credential Access (240+ events):** `GetPasswordData`, `GetSecretValue`, `GetParameter`, `Decrypt`, `PutSecretValue`.
- **Privilege Escalation & Persistence (100+ events):** `AttachUserPolicy` (`AdministratorAccess`), `PutRolePolicy`, `CreateAccessKey`, `CreateUser`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`, `AddRoleToInstanceProfile`.
- **Defense Evasion (25+ events):** `StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, `DeleteBucketPolicy`, `RevokeSecurityGroupEgress`.
- **Execution (10+ events):** `SendCommand` (SSM agent execution on EC2), `RunInstances`.

---

## 4. Leakage Risks & Engineering Guardrails

- **User-Agent Leakage:** Raw `userAgent` strings contain explicit indicators (`stratus-red-team`, `terraform`). Models must **never** be trained on raw user-agent string tokens.
- **Safe Feature Extraction:** Features must strictly rely on behavioral dynamics: API call rates, temporal burst entropy, failure ratios, privilege escalation transitions, and high-risk API frequencies.

---

## 5. Candidate Datasets for Future Benchmark Extensions

| Dataset | Telemetry Type | Purpose in Future Phases |
|---|---|---|
| **TON-IoT** | Network Flow / Host Telemetry | Reserved for multi-modal network flow & workload extension benchmarks |
| **DARPA OpTC** | Enterprise Endpoint Audit Logs | Reserved for host-level process lineage and relationship modeling |
| **CTU-SME-11** | Enterprise NetFlow / PCAP | Reserved for VPC Flow Log evaluation |
