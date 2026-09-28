# Dataset Label Audit & Baseline A Validation Report

## 1. Executive Summary & Audit Motivation

This audit independently investigates the provenance, semantics, and operational boundaries of the labels in the **Stratus Red Team CloudTrail Dataset** (`invictus-ir/aws_dataset`, 2,900 events across 29 AWS services).

### Key Audit Findings:
1. **Label Origin:** AWS CloudTrail logs **do not contain native ground-truth attack labels**. Ground truth is derived exclusively from the HTTP `User-Agent` header injected by DataDog Stratus Red Team during execution (`stratus-red-team_<UUID>`).
2. **Four Operational Activity Tiers Identified:**
   - **Tier 1 — Stratus Pure Detonations:** `214` events (7.38%) — Direct adversary API calls executing the attack.
   - **Tier 2 — Stratus Terraform Warmup/Cleanup:** `932` events (32.14%) — Prerequisite infrastructure setup/teardown by Stratus via Terraform.
   - **Tier 3 — Pure Terraform Operator:** `1,006` events (34.69%) — Lab environment management by the test engineer.
   - **Tier 4 — AWS Background & Internal:** `748` events (25.79%) — Internal service operations, KMS rotations, console sessions.
3. **The 1,146 "Attack" Count Composition:**
   - 1,146 events represents **all Stratus-associated activity** (Tier 1 + Tier 2).
   - Only **214 events** represent pure, direct attack executions; the remaining **932 events** are automated Terraform orchestration steps supporting the attack scenarios.
4. **The 1,754 "Benign" Count Composition:**
   - The 1,754 events were **not explicitly labelled "benign"** by the dataset creators. They represent all events that lacked the `stratus-red-team` token (Tier 3 Operator Terraform: 1,006 events + Tier 4 AWS Background: 748 events).
5. **False Positive Diagnosis:**
   - The 19 false positive findings emitted by Baseline A occurred entirely within Tier 3 (`PURE_TERRAFORM_OPERATOR`) when Terraform torn down test secrets (`DeleteSecret`, 17 alerts) and trails (`DeleteTrail`, 2 alerts).

---

## 2. Four-Tier Activity Breakdown & Overlap Analysis

```
Total Dataset: 2,900 Events
│
├── Stratus-Associated Activity (1,146 events / 39.52%)
│   ├── Tier 1: Pure Detonations (214 events / 7.38%)
│   │   └── Direct adversary API calls (e.g., StopLogging, GetPasswordData, AssumeRole, SendCommand)
│   └── Tier 2: Stratus + Terraform Warmup/Cleanup (932 events / 32.14%)
│       └── Infrastructure setup/teardown orchestrated by Stratus via Terraform Provider
│
└── Non-Stratus Activity (1,754 events / 60.48%) [Previously classified as "Benign"]
    ├── Tier 3: Pure Terraform Operator Activity (1,006 events / 34.69%)
    │   └── Lab operator environment management (non-Stratus tagged Terraform calls)
    └── Tier 4: AWS Background & Internal Activity (748 events / 25.79%)
        └── AWS Internal (418), SecretsManager rotation (116), S3Console (104), STS, Health, etc.
```

### Overlap Matrix:
| Activity Category | Has `stratus` Tag | Has `terraform` Tag | Event Count | % of Dataset |
|---|---|---|---|---|
| **Pure Detonation** | YES | NO | 214 | 7.38% |
| **Stratus Warmup/Cleanup** | YES | YES | 932 | 32.14% |
| **Operator Infrastructure** | NO | YES | 1,006 | 34.69% |
| **AWS Background/Internal**| NO | NO | 748 | 25.79% |
| **Total** | | | **2,900** | **100.0%** |

---

## 3. Breakdown of Attack Activity

### 3.1 Pure Detonation APIs (Tier 1: 214 events)
These represent the true core adversarial payloads:
- **Discovery (108 events):** `DescribeAccountAttributes` (34), `DescribeInstanceInformation` (27), `DescribeInstanceAttribute` (15), `DescribeParameters` (5), `GetParameters` (5), `ListAccessKeys` (2), `ListSecrets` (1), `GetCallerIdentity` (1).
- **Credential Access & Staging (49 events):** `GetPasswordData` (29), `GetSecretValue` (20).
- **Privilege Escalation & IAM Backdoors (32 events):** `AssumeRole` (23), `CreateAccessKey` (2), `UpdateAssumeRolePolicy` (2), `CreateLoginProfile` (1), `AttachUserPolicy` (1), `DetachUserPolicy` (1), `DeleteAccessKey` (2).
- **Defense Evasion & Impact (17 events):** `StopLogging` (3), `StartLogging` (3), `PutEventSelectors` (2), `DeleteFlowLogs` (1), `DeleteTrail` (1), `DeleteBucketPolicy` (1), `PutBucketPolicy` (1), `RevokeSecurityGroupIngress` (1), `AuthorizeSecurityGroupIngress` (1), `LeaveOrganization` (1), `DeleteBucketLifecycle` (1).
- **Execution & Compute (8 events):** `SendCommand` (2), `GetCommandInvocation` (2), `RunInstances` (2), `UpdateFunctionCode` (2).

### 3.2 Service & Identity Distribution
- **Top Services in Stratus Activity:** `ec2` (409), `ssm` (235), `iam` (169), `secretsmanager` (121), `s3` (84), `rds` (47), `sts` (30), `cloudtrail` (21), `lambda` (19).
- **Identities:** Primary actor `bert-jan` (1,098 events) + 6 assumed role sessions (`AROATFQR7NSC...`, 48 events).
- **Error Profile:** 1,008 successful calls, 44 `Client.UnauthorizedOperation`, 26 `ThrottlingException`, 14 `AccessDenied`, 7 `TrailNotFoundException`.

---

## 4. Multi-Ground-Truth Baseline A Evaluation Comparison

To maintain complete scientific transparency, Baseline A (Rules Only) is evaluated under three distinct ground-truth definitions:

| Metric | Definition 1: All Stratus-Associated (1,146 evts) | Definition 2: Pure Detonations Only (214 evts) | Definition 3: Technique-Run Level (83 Detonation Runs) |
|---|---|---|---|
| **Ground Truth Attack Units** | 1,146 events | 214 events | 83 detonation runs |
| **Ground Truth Benign Units** | 1,754 events | 2,686 events | N/A |
| **True Positives (TP)** | 23 | 13 | 17 runs detected |
| **False Positives (FP)** | 19 | 29 (10 warmup + 19 operator) | N/A |
| **False Negatives (FN)** | 1,123 | 201 | 66 runs missed |
| **Precision** | **54.76%** (0.5476) | **30.95%** (0.3095) | N/A |
| **Recall** | **2.01%** (0.0201) | **6.07%** (0.0607) | **20.48%** (0.2048) |
| **F1-Score** | **0.0387** | **0.1016** | N/A |

### Interpretation of Results:
1. **Event-Level Recall remains extremely low (< 7%) across all definitions.**
   - Under Definition 1, recall is **2.01%** because static rules miss the 932 setup/teardown events and reconnaissance calls.
   - Under Definition 2 (Pure Detonations only), recall is **6.07%** (13/214 detected). Static rules catch the explicit defense evasion calls (`StopLogging`, `DeleteFlowLogs`, `DeleteTrail`) but miss `GetPasswordData` (29), `GetSecretValue` (20), and `Describe*` reconnaissance (108 events).
2. **Technique-Level Recall is 20.48% (17 / 83 runs detected).**
   - Out of 83 discrete adversary technique detonations, static rules generated at least one finding for **17 techniques** (e.g. Stop CloudTrail Logging, Attach Admin Policy, Modify Trust Policy).
   - **66 techniques (79.52%) executed completely undetected** by static rules.
3. **Precision drops to 30.95% under Pure Detonations.**
   - Rules fired 10 times during automated Stratus warmup/cleanup (e.g. creating test IAM policies) and 19 times during operator teardown (deleting test secrets/trails).

---

## 5. Summary of Findings by Activity Tier

| Rule ID | Rule Name | Tier 1: Pure Detonations (TP) | Tier 2: Stratus Warmup (TP/Context) | Tier 3: Operator TF (FP) | Tier 4: Background (FP) | Total Findings |
|---|---|---|---|---|---|---|
| **`RULE-IAM-001`** | Admin Policy Attached | 1 | 1 | 0 | 0 | 2 |
| **`RULE-IAM-002`** | Inline Policy Injection | 0 | 5 | 0 | 0 | 5 |
| **`RULE-IAM-003`** | Access Key Created | 2 | 0 | 0 | 0 | 2 |
| **`RULE-IAM-004`** | Console Login Profile | 1 | 1 | 0 | 0 | 2 |
| **`RULE-IAM-005`** | Trust Policy Modified | 2 | 0 | 0 | 0 | 2 |
| **`RULE-CFG-001`** | CloudTrail Tampering | 4 | 0 | 2 | 0 | 6 |
| **`RULE-CFG-002`** | VPC Flow Logs Deleted | 1 | 0 | 0 | 0 | 1 |
| **`RULE-CFG-003`** | S3 Bucket Policy Deleted | 1 | 0 | 0 | 0 | 1 |
| **`RULE-CFG-004`** | Secret / Key Deletion | 0 | 0 | 17 | 0 | 17 |
| **`RULE-EXP-001`** | Open SG Ingress (0.0.0.0/0) | 1 | 1 | 0 | 0 | 2 |
| **`RULE-EXP-002`** | SG Egress Revoked | 0 | 2 | 0 | 0 | 2 |
| **Total** | | **13** | **10** | **19** | **0** | **42** |

---

## 6. Critical Takeaways for Phase 3 (Feature Engineering) & Phase 4 (ML)

1. **Labels are Behavioral & Contextual, Not Micro-Signatures:**
   - In real cloud environments, attackers execute legitimate APIs (`DescribeInstances`, `GetSecretValue`, `AssumeRole`) alongside malicious state modifications (`StopLogging`).
   - The ML feature extraction pipeline must compute entity baselines (call rates, burst velocity, error frequency, transition probabilities) across sliding temporal windows rather than trying to classify isolated API names.
2. **Anti-Leakage Mandate Re-confirmed:**
   - Because the User-Agent explicitly contains `stratus-red-team_<UUID>`, models must **strictly exclude** the literal `userAgent` string from training features.
3. **Multi-Stage Evaluation Framework Established:**
   - Future ML and Hybrid evaluations will report performance across both **Event-Level** (Definitions 1 & 2) and **Technique/Incident-Level** (Definition 3) to measure how effectively multi-stage attack progressions are detected.
