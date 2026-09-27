# Phase 2 Report: Deterministic Rule Baseline Experiment (Baseline A)

## 1. Executive Summary & Experimental Objectives

- **Experiment:** Baseline A — Deterministic Rules-Only Detection
- **Telemetry Source:** Real AWS CloudTrail logs from Stratus Red Team adversary emulation (`data/raw/stratus_cloudtrail/CloudTrail/`, 2,900 events across 29 AWS services).
- **Rule Engine Modules:**
  - IAM Security Rules (`src/detection/rules/iam_rules.py`)
  - Configuration & Defense Evasion Rules (`src/detection/rules/configuration_rules.py`)
  - Exposure & Network Boundary Rules (`src/detection/rules/exposure_rules.py`)
- **Key Finding:** Deterministic rules reliably flag explicit policy violations (e.g., `StopLogging`, `AttachUserPolicy (AdministratorAccess)`, open security groups) within **6.0 seconds**, but achieve an event recall of only **2.01%** (detecting 23/1,146 attack events), leaving 97.99% of adversarial actions (reconnaissance, credential dumps, and behavioral sequence shifts) completely undetected.

---

## 2. Quantitative Baseline A Performance

| Metric | Measured Value | Analysis & Significance |
|---|---|---|
| **Total Events Evaluated** | 2,900 | Complete continuous 55.5-minute CloudTrail dataset |
| **Ground Truth Attack Events** | 1,146 (39.52%) | Executed via Stratus Red Team adversary emulation |
| **Ground Truth Benign Events** | 1,754 (60.48%) | Terraform provisioning/teardown and background AWS calls |
| **Total Findings Generated** | 42 | Emitted as standardized `SecurityFinding` contracts |
| **True Positive Findings (TP)** | 23 | Detections on genuine attack actions |
| **False Positive Findings (FP)** | 19 | Alerts fired on benign Terraform lifecycle operations |
| **Event-Level Precision** | **54.76%** (0.5476) | Significant false alarm rate in automated CI/CD environments |
| **Event-Level Recall** | **2.01%** (0.0201) | Static rules miss 1,123 / 1,146 adversarial events |
| **F1-Score** | **0.0387** | Indicates heavy limitation of pure rule-based detection |
| **Time to First Detection** | **6.0 seconds** | Rapid detection when explicit violation occurs |

---

## 3. Breakdown by Detection Rule

| Rule ID | Name | Severity | MITRE ATT&CK | Findings Count | TP | FP |
|---|---|---|---|---|---|---|
| **`RULE-IAM-001`** | Admin Policy Attached to Principal | CRITICAL | T1098 | 2 | 2 | 0 |
| **`RULE-IAM-002`** | Inline IAM Policy Injection | CRITICAL/HIGH | T1098.001 | 5 | 5 | 0 |
| **`RULE-IAM-003`** | IAM Access Key Created | HIGH/MEDIUM | T1098 | 2 | 2 | 0 |
| **`RULE-IAM-004`** | Console Login Profile Created | HIGH | T1136.003 | 2 | 2 | 0 |
| **`RULE-IAM-005`** | IAM Role Trust Policy Modified | CRITICAL/HIGH | T1098 | 2 | 2 | 0 |
| **`RULE-CFG-001`** | CloudTrail Logging Disabled/Deleted | CRITICAL | T1562.001 | 6 | 4 | 2 |
| **`RULE-CFG-002`** | VPC Flow Logs Deleted | HIGH | T1562.001 | 1 | 1 | 0 |
| **`RULE-CFG-003`** | S3 Bucket Policy Deleted | HIGH | T1562.001 | 1 | 1 | 0 |
| **`RULE-CFG-004`** | KMS Key / Secret Deletion | HIGH | T1486 | 17 | 0 | 17 |
| **`RULE-EXP-001`** | Open Security Group Ingress (0.0.0.0/0) | CRITICAL | T1133 | 2 | 2 | 0 |
| **`RULE-EXP-002`** | Security Group Egress Revoked | MEDIUM | T1562 | 2 | 2 | 0 |
| **`RULE-EXP-003`** | S3 Bucket Public Policy Applied | CRITICAL | T1530 | 0 | 0 | 0 |

---

## 4. What Deterministic Rules Succeeded in Detecting

Deterministic rules proved highly effective at flagging explicit, unambiguous violations:
- **Defense Evasion:** `StopLogging` (3 events), `DeleteTrail` (1 event), `DeleteFlowLogs` (1 event), `DeleteBucketPolicy` (1 event).
- **Initial Exposure:** `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` (2 events).
- **Hard Privilege Escalation:** `AttachUserPolicy` with `AdministratorAccess` (1 event), `AttachRolePolicy` (1 event), `PutRolePolicy` (5 events).
- **Backdoor Persistence:** `CreateLoginProfile` (2 events), `CreateAccessKey` (2 events), `UpdateAssumeRolePolicy` (2 events).

---

## 5. Failure Analysis: Why Rules Missed 97.99% of Attack Events

The remaining 1,123 attack events were completely missed by static rules due to three fundamental limitations of signature-based detection:

### 1. Discovery & Enumeration Blindspot (380+ missed events)
- Attackers executed heavy reconnaissance: `DescribeRouteTables` (69), `GetUser` (57), `DescribeParameters` (48), `ListTagsForResource` (45), `DescribeAccountAttributes` (34), `DescribeNatGateways` (32), `DescribeInstanceInformation` (27), `DescribeDBInstances` (25).
- *Why Rules Fail:* Static rules cannot flag `Describe*` or `List*` calls because these APIs are essential for standard operations, monitoring tools, and CI/CD pipelines. Flagging them via rules causes massive alert fatigue.

### 2. Valid-Credential Data Access & Exfiltration (240+ missed events)
- Attackers accessed secrets and parameters: `GetSecretValue` (40), `GetParameter` (42), `GetPasswordData` (29), `PutParameter` (67), `PutSecretValue` (20), `Decrypt` (178).
- *Why Rules Fail:* The API calls used valid permissions. A rule engine inspecting individual events cannot distinguish between legitimate administrative retrieval and adversary credential dumps without behavioral baselining and entity profiling.

### 3. Context-Free False Positives (19 FP events)
- Automated Terraform infrastructure teardown scheduled deletion of temporary test secrets and keys (`ScheduleKeyDeletion`, `DeleteSecret`), triggering `RULE-CFG-004` (17 false positives).
- *Why Rules Fail:* Rules evaluate individual events in isolation without identity context, workload history, or intent correlation.

---

## 6. Research Conclusion & Path to Phase 3 / Phase 4

The empirical results from Phase 2 establish a rigorous baseline:
- **Baseline A (Rules Only) confirms that static rules are necessary for hard policy violations, but inherently insufficient for multi-stage cloud threat detection (Recall: 2.01%).**
- This provides direct experimental justification for:
  1. **Phase 3 (Feature Engineering):** Extracting behavioral features (burst rates, transition probabilities, error ratios, off-hour activity, entropy).
  2. **Phase 4 (ML Anomaly Detection - Baseline B):** Training behavioral models to catch stealthy reconnaissance and anomalous credential retrieval.
  3. **Phase 5 & 6 (Hybrid Integration & Evidence Fusion):** Combining rule triggers with ML anomaly scores, temporal reasoning, and identity context to detect the evolving attack chain while suppressing false positives.
