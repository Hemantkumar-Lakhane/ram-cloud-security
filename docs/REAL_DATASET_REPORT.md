# Real Telemetry Dataset Report — AWS CloudTrail (Stratus Red Team Simulation)

## 1. Executive Summary & Provenance

- **Dataset Name:** Stratus Red Team CloudTrail Attack Dataset (`invictus-ir/aws_dataset`)
- **Primary Source:** [https://github.com/invictus-ir/aws_dataset](https://github.com/invictus-ir/aws_dataset)
- **Framework Grounding:** DataDog Stratus Red Team (open-source adversary emulation for AWS)
- **License:** MIT License (Copyright © 2023 Invictus Incident Response)
- **Local Storage:** `data/raw/stratus_cloudtrail/CloudTrail/` (55 JSON log files, preserved unmodified)
- **Normalization Parity:** 2,900 / 2,900 events successfully normalized into `NormalizedEvent` (0 parsing errors).

---

## 2. Dataset Dimensions & Temporal Scope

| Metric | Value |
|---|---|
| **Total Log Files** | 55 JSON files (standard AWS CloudTrail multi-record format) |
| **Total Raw Events** | 2,900 |
| **Time Range** | 2023-07-10 11:42:18 UTC to 2023-07-10 12:37:50 UTC |
| **Total Duration** | ~55.5 minutes (continuous session) |
| **Distinct AWS Services** | 29 services |
| **Distinct Event Names (APIs)** | 260 API actions |
| **Distinct IAM Principals** | 13 (2 IAM Users, 10 Assumed Roles, 1 AWS Service) |
| **Distinct Source IPs** | 16 |
| **AWS Regions** | 1 (`us-east-1`) |

---

## 3. Activity & Class Distribution

```
Total Events: 2,900
├── Terraform Setup/Teardown Activity: 1,938 events (66.83%)
├── Stratus Red Team Detonations:      1,146 events (39.52%)
└── Standard AWS Background Calls:       748 events (25.79%)
```
*Note: Overlaps occur where Terraform infrastructure orchestration was executed under automated runner sessions.*

---

## 4. Top Services & API Actions

### Top 10 AWS Services
1. `ec2.amazonaws.com`: 892 events (30.76%)
2. `ssm.amazonaws.com`: 488 events (16.83%)
3. `iam.amazonaws.com`: 398 events (13.72%)
4. `s3.amazonaws.com`: 271 events (9.34%)
5. `kms.amazonaws.com`: 240 events (8.28%)
6. `secretsmanager.amazonaws.com`: 233 events (8.03%)
7. `rds.amazonaws.com`: 150 events (5.17%)
8. `sts.amazonaws.com`: 64 events (2.21%)
9. `health.amazonaws.com`: 48 events (1.66%)
10. `cloudtrail.amazonaws.com`: 35 events (1.21%)

### Top 10 Most Frequent API Actions
1. `Decrypt` (KMS): 178
2. `DescribeRouteTables` (EC2): 163
3. `GetUser` (IAM): 130
4. `DescribeParameters` (SSM): 122
5. `ListTagsForResource` (SSM/IAM): 88
6. `GetParameter` (SSM): 82
7. `DeleteParameter` (SSM): 78
8. `PutParameter` (SSM): 67
9. `GetSecretValue` (SecretsManager): 60
10. `DescribeNatGateways` (EC2): 54

---

## 5. Attack Scenarios & MITRE ATT&CK Mapping

The Stratus Red Team execution captured in this dataset detonated multiple real attack techniques across the cloud kill chain:

| MITRE ATT&CK Tactic | Specific AWS API Actions in Dataset | Event Count |
|---|---|---|
| **Discovery** | `DescribeRouteTables`, `DescribeParameters`, `DescribeAccountAttributes`, `DescribeInstanceInformation`, `DescribeDBInstances`, `DescribeSecurityGroups`, `DescribeTrails`, `GetCallerIdentity`, `ListAccessKeys` | 380+ |
| **Credential Access** | `GetPasswordData`, `GetSecretValue`, `GetParameter`, `Decrypt`, `PutSecretValue` | 240+ |
| **Privilege Escalation** | `AttachUserPolicy` (`AdministratorAccess`), `PutRolePolicy`, `CreateAccessKey`, `CreateUser`, `CreateLoginProfile`, `UpdateAssumeRolePolicy` | 65+ |
| **Defense Evasion** | `StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, `DeleteBucketPolicy`, `RevokeSecurityGroupEgress` | 25+ |
| **Persistence** | `AddRoleToInstanceProfile`, `CreateInstanceProfile`, `CreateRole`, `CreateAccessKey` | 40+ |
| **Execution** | `SendCommand` (SSM agent execution on EC2), `RunInstances` | 10+ |

---

## 6. Error & Status Code Distribution

- **Total Errors Logged:** 300 events (10.34% overall error rate)
- **Top Error Codes:**
  - `ThrottlingException`: 102 (API rate-limiting during rapid detonation bursts)
  - `Client.UnauthorizedOperation`: 44 (EC2 permission probing)
  - `AccessDenied`: 16 (IAM permission denial)
  - `NoSuchBucketPolicy`: 14 (S3 policy discovery failure)
  - `Client.InvalidRouteTableID.NotFound`: 13
  - `NoSuchPublicAccessBlockConfiguration`: 12

---

## 7. Data Quality & Missing Value Analysis

| Field | Missing % | Handling Strategy in Normalizer |
|---|---|---|
| `event_id` | 0.0% | Uses CloudTrail `eventID` |
| `event_time` | 0.0% | Parsed to UTC ISO 8601 |
| `event_source` | 0.0% | Extracted directly |
| `event_name` | 0.0% | Extracted directly |
| `aws_region` | 0.0% | `us-east-1` across dataset |
| `account_id` | 0.0% | Extracted from `recipientAccountId` / `userIdentity` |
| `actor_name` | 2.62% | Populated from `userName`, `principalId`, or session issuer; None for AWSService calls |
| `actor_type` | 1.45% | `IAMUser`, `AssumedRole`, `AWSService` |
| `source_ip` | 0.0% | Client IP or AWS internal service domain |
| `user_agent` | 0.0% | Present on all records |
| `error_code` | 89.66% | None indicates successful API call (expected behavior) |

---

## 8. Target Leakage Risks & Engineering Guardrails

> [!WARNING]
> **CRITICAL DATA LEAKAGE RISK:**  
> The `userAgent` field in the raw data contains literal strings such as `stratus-red-team` and `terraform`.  
> If an ML model is trained with raw string tokens of `userAgent`, it will trivially overfit to the string `"stratus"` without learning genuine behavioral anomalies.

### Mandatory Feature Engineering Guardrails:
1. **Exclude Literal String Features:** Strip out explicit tool names from user-agent features.
2. **Use Behavioral Signals Only:**
   - User-Agent entropy / client category (e.g. SDK vs CLI vs Console).
   - High-risk API transition probabilities (e.g., `Describe*` followed immediately by `GetPasswordData` or `AttachUserPolicy`).
   - Burst frequency (API calls per second / sliding window).
   - Access failure ratio (`is_error` / total requests).
   - Privilege change count within sliding 5-minute windows.

---

## 9. Machine Learning Tasks Supported by this Dataset

Based on empirical data properties, this dataset directly supports:
1. **Unsupervised Anomaly Detection (Primary Baseline):**
   - Train baseline models (Isolation Forest, One-Class SVM) on benign/routine traffic profiles to identify outlier sequences (e.g., rapid credential dumps, defense evasion).
2. **Multi-Stage Threat Progression / Sequence Modeling:**
   - Modeling the progression of techniques (Discovery $\to$ Credential Access $\to$ Privilege Escalation $\to$ Defense Evasion) over time for an actor.
3. **Deterministic Rule Engine Benchmarking:**
   - Validating deterministic rules against clear policy violations (`StopLogging`, `AttachUserPolicy`, `DeleteFlowLogs`).
