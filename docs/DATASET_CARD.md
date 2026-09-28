# Dataset Card: Stratus Red Team CloudTrail Attack Dataset

## 1. Dataset Overview & Provenance

| Attribute | Value |
|---|---|
| **Dataset Name** | Stratus Red Team CloudTrail Attack Dataset |
| **Publisher / Maintainer** | Invictus Incident Response (`invictus-ir`) |
| **Source Repository** | [https://github.com/invictus-ir/aws_dataset](https://github.com/invictus-ir/aws_dataset) |
| **License** | MIT License (Copyright © 2023 Invictus Incident Response) |
| **Telemetry Format** | Standard AWS CloudTrail JSON Multi-Record Logs (`{"Records": [...]}`) |
| **Local Storage Path** | `data/raw/stratus_cloudtrail/CloudTrail/` (55 JSON files, preserved unmodified) |
| **Normalization Parity** | 2,900 / 2,900 events (100% parsed into `NormalizedEvent` schema with 0 errors) |

---

## 2. Collection Methodology & Adversary Emulation

The dataset was generated in a dedicated AWS test account by detonating adversarial attack scenarios using **DataDog Stratus Red Team** (an open-source cloud adversary emulation tool).

During detonation:
1. **Prerequisite Warmup:** Stratus utilizes the Terraform AWS Provider to instantiate necessary target resources (e.g. creating test IAM roles, VPCs, S3 buckets, or EC2 instances).
2. **Attack Detonation:** Stratus executes the specific MITRE ATT&CK technique via direct AWS SDK/API calls while injecting a unique correlation token into the HTTP `User-Agent` (`stratus-red-team_<UUID>`).
3. **Prerequisite Cleanup:** Stratus tears down the created target resources via Terraform.
4. **Telemetry Capture:** CloudTrail management and data events were recorded continuously and exported into 55 JSON batch log files.

---

## 3. Dataset Dimensions & Scope

- **Total Log Files:** 55 JSON files
- **Total Events:** 2,900
- **Observation Window:** 2023-07-10 11:42:18 UTC to 2023-07-10 12:37:50 UTC (55.5 minutes continuous capture)
- **AWS Region:** `us-east-1`
- **Distinct AWS Services:** 29 services
- **Distinct API Event Names:** 260 actions
- **Distinct IAM Principals:** 13 (2 IAM users: `bert-jan`, `benjamin`; 10 assumed-role sessions; 1 AWS service)
- **Distinct Source IPs:** 16 IP addresses

---

## 4. Four-Tier Operational Activity Classification

CloudTrail logs do **not** possess native binary ground-truth labels. The events were audited and categorized into four operational tiers:

```
Total Events: 2,900
├── Stratus-Associated Activity (1,146 events / 39.52%)
│   ├── Tier 1: Pure Detonations (214 events / 7.38%) — Direct adversarial API execution
│   └── Tier 2: Stratus Warmup/Cleanup (932 events / 32.14%) — Terraform-orchestrated prerequisites
└── Non-Stratus Activity (1,754 events / 60.48%) [Previously classified as "Benign"]
    ├── Tier 3: Operator Infrastructure (1,006 events / 34.69%) — Lab environment management
    └── Tier 4: AWS Background/Internal (748 events / 25.79%) — Internal service operations & rotations
```

---

## 5. Attack Coverage & MITRE ATT&CK Mapping

The 214 pure detonation events cover multiple core tactics of the AWS threat matrix:
- **Discovery (108 events):** `DescribeAccountAttributes`, `DescribeInstanceInformation`, `DescribeInstanceAttribute`, `DescribeParameters`, `GetParameters`, `ListAccessKeys`, `ListSecrets`, `GetCallerIdentity`.
- **Credential Access & Exfiltration (49 events):** `GetPasswordData`, `GetSecretValue`.
- **Privilege Escalation & Persistence (32 events):** `AssumeRole`, `CreateAccessKey`, `UpdateAssumeRolePolicy`, `CreateLoginProfile`, `AttachUserPolicy`, `DetachUserPolicy`, `DeleteAccessKey`.
- **Defense Evasion & Impact (17 events):** `StopLogging`, `StartLogging`, `PutEventSelectors`, `DeleteFlowLogs`, `DeleteTrail`, `DeleteBucketPolicy`, `PutBucketPolicy`, `RevokeSecurityGroupIngress`, `AuthorizeSecurityGroupIngress`, `LeaveOrganization`, `DeleteBucketLifecycle`.
- **Execution & Compute (8 events):** `SendCommand`, `GetCommandInvocation`, `RunInstances`, `UpdateFunctionCode`.

---

## 6. Known Limitations & Target Leakage Risks

### 6.1 Critical Data Leakage Guardrail
> [!WARNING]
> The raw `userAgent` header contains explicit strings: `stratus-red-team_<UUID>` and `HashiCorp/1.0 Terraform/...`.
> **MANDATORY RULE:** Models must **never** ingest raw `userAgent` tokens. Doing so causes trivial target leakage. All ML features must strictly rely on behavioral, temporal, error, and sequence dynamics.

### 6.2 Operational Limitations
1. **Single-Account Focus:** Telemetry originated from one AWS account (`218007301253`) in `us-east-1`.
2. **Dense Attack Density:** Because detonations occurred in a rapid test session, attack prevalence (39.52% Stratus-associated) is higher than typical enterprise production environments (<0.1%).
3. **Label Semantics:** Non-Stratus activity reflects legitimate test infrastructure operations rather than enterprise multi-user production baseline.

---

## 7. Intended Use in this Project
- **Phase 1 & 1.5:** Data ingestion normalization and exploratory data analysis.
- **Phase 2:** Baseline A (Deterministic Rules-Only) evaluation.
- **Phase 3:** Behavioral feature extraction and sliding-window velocity modeling.
- **Phase 4 & 5:** Baseline B (ML Anomaly Detection) and Hybrid Rule+ML integration.
- **Phase 6:** Identity-aware, temporal evidence fusion experiments.
