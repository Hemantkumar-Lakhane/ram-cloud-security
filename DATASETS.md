# RAM Cloud Security — Dataset Evaluation & Strategy

## 1. Dataset Strategy Principles

1. **No Blind Ingestion:** Do not download or force datasets before evaluating field availability, schema compatibility with AWS telemetry, and attack scenario realism.
2. **Telemetry Alignment:** The primary dataset must align with AWS CloudTrail audit logs, IAM events, and network/workload behavior.
3. **Realistic Class Imbalance:** Security datasets exhibit extreme skew (anomalies are rare). Models must be evaluated with precision, recall, and PR-AUC rather than raw accuracy.

---

## 2. Candidate Datasets Overview

| Dataset | Primary Telemetry | Suitability | Evaluation Status |
|---|---|---|---|
| **DataDog Grimoire (AWS CloudTrail)** | AWS CloudTrail Audit Logs & IAM activity | **Primary Candidate (Highest)** | Selected for Initial Evaluation |
| **TON-IoT** | Network Flow, OS logs, Telemetry | Secondary / Network Workload | Reserved for network anomaly benchmarking |
| **DARPA OpTC** | Host-level endpoint telemetry & audit logs | Secondary / Host Workload | Reserved for host execution anomalies |
| **CTU-SME-11** | NetFlow / PCAP enterprise traffic | Secondary / Network Flow | Reserved for VPC Flow Log extensions |

---

## 3. Detailed Inspection of Primary Candidate

### DataDog Grimoire / CloudTrail Audit Logs
- **Source:** Cloud security research and AWS audit log telemetry.
- **Key Fields Required for Ingestion:**
  - `eventTime`: Timestamp in ISO 8601 UTC format.
  - `eventSource`: AWS service generating the event (e.g. `iam.amazonaws.com`, `s3.amazonaws.com`, `ec2.amazonaws.com`).
  - `eventName`: API action executed (e.g. `CreateAccessKey`, `PutBucketPolicy`, `AuthorizeSecurityGroupIngress`).
  - `userIdentity`: Principal type (`IAMUser`, `AssumedRole`, `Root`), ARN, and account ID.
  - `sourceIPAddress`: Client IP address.
  - `userAgent`: Client caller signature (e.g. AWS CLI, boto3, Terraform, Browser).
  - `errorCode` / `errorMessage`: Access denial signals (e.g. `AccessDenied`).
  - `requestParameters` / `responseElements`: Contextual API parameters.
- **Evaluation Criteria:**
  - Presence of both baseline (benign operational activity) and realistic attack scenarios (credential exfiltration, privilege escalation, persistence, discovery).
  - Consistency of JSON formatting and schema compliance.
  - Absence of synthetic bias or trivial artifacts.

---

## 4. Evaluation Workflow

```
Candidate Dataset Selection
            │
            ▼
Schema & Field Inspection (Verify CloudTrail schema parity)
            │
            ▼
Data Quality & Completeness Audit (Missing values, time distribution)
            │
            ▼
Label & Scenario Analysis (Normal vs. Malicious event distribution)
            │
            ▼
Normalization to OCSF / NormalizedEvent Schema
            │
            ▼
Feature Matrix Generation & Model Training Pipeline
```

---

## 5. Next Action Items for Phase 1 & 2
- Construct sample synthetic CloudTrail fixtures for unit testing in `tests/fixtures/`.
- Download and inspect a bounded slice of the DataDog Grimoire dataset.
- Document exact field mappings in `docs/data_dictionary.md`.
