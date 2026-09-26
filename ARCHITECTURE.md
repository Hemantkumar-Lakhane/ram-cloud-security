# RAM Cloud Security — System Architecture

## 1. Approved System Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                            CLOUD RESOURCES & SERVICES                             |
|                           (EC2, IAM, S3, VPC / Network)                           |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                           TELEMETRY & SECURITY SOURCES                            |
|       (AWS CloudTrail, CloudWatch, VPC Flow Logs, AWS Config, Amazon Inspector)   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     SECURITY DATA LAKE / NORMALIZATION LAYER                      |
|                  - Centralized security data stored in Amazon S3                  |
|                  - Normalized security-event representation                       |
|                  - OCSF-compatible structure where appropriate                    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        PROCESSING & FEATURE ENGINEERING                           |
|                  - Parse, Clean, Normalize, Correlate, Aggregate                  |
|                  - Extract ML features & entity activity vectors                  |
+-----------------------------------------------------------------------------------+
                                         |
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
+------------------------------------+     +----------------------------------------+
|            RULE ENGINE             |     |               ML ENGINE                |
|  - Deterministic checks            |     |  - Baseline behavioral models          |
|  - Configuration drift             |     |  - User/API behavior anomalies         |
|  - IAM policy violations           |     |  - Workload anomalies                  |
|  - Public exposure & CVEs          |     |  - Network anomalies                   |
|  - Compliance baselines            |     |  - Unsupervised / Supervised scoring   |
+------------------------------------+     +----------------------------------------+
                   |                                           |
                   +---------------------+---------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                          SECURITY CONTEXT & RISK ANALYSIS                         |
|   - Identity Context   | Asset Context   | Behavior Context | Vulnerability Context|
|   - Detection Confidence Integration                                              |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                               RISK PRIORITIZATION                                 |
|            - Unified Risk Score Calculation (NORMAL, SUSPICIOUS, HIGH-RISK)        |
+-----------------------------------------------------------------------------------+
                                         |
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
+------------------------------------+     +----------------------------------------+
|        SECURITY OPERATIONS         |     |         RESPONSE ORCHESTRATOR          |
|  - Analyst Dashboard               |     |  - Alert & Notification                |
|  - Security Findings Explorer      |     |  - Human Approval Workflow (Safe Mode) |
|  - Forensic Evidence Store         |     |  - Guardrailed Remediation & Rollback  |
+------------------------------------+     +----------------------------------------+
```

---

## 2. Component Responsibilities

### 2.1 Telemetry Ingestion (`src/ingestion/`)
- Ingests event streams from AWS telemetry services.
- Initial primary source: **AWS CloudTrail** (management, data, and insight events).
- Secondary sources (progressive integration): VPC Flow Logs, AWS Config snapshots, Amazon Inspector findings, CloudWatch log streams.
- Provides unified iterator interfaces for both offline replay (research/testing) and live AWS collection via `boto3`.

### 2.2 Data Lake & Normalization (`src/preprocessing/`)
- Ingests raw JSON/JSONL/gzip payloads and writes them immutably into partitioned S3/local data lake locations (`data/raw/`).
- Translates service-specific payloads into an internal OCSF-aligned schema (`NormalizedEvent`).
- Standardizes identity structures (`user_identity_arn`, `session_issuer`), timestamps (UTC), source IPs, user agents, and action verbs.

### 2.3 Feature Engineering (`src/features/`)
- Computes behavioral feature representations across multiple temporal sliding windows (1h, 24h, 7d).
- Generates statistical aggregates: API call rates, error codes (`AccessDenied`, `UnauthorizedOperation`), high-risk API frequencies, user agent entropy, new region access, and off-hour access ratios.

### 2.4 Rule Engine (`src/detection/rules/`)
- Performs deterministic, rule-based evaluations where ground truth is binary and non-probabilistic.
- **Sub-modules:**
  - `iam_rules.py`: Evaluates excessive permissions, privilege escalation paths, credential age, root usage.
  - `configuration_rules.py`: Evaluates resource settings (e.g., S3 server-side encryption, MFA delete).
  - `exposure_rules.py`: Detects unrestricted internet ingress (e.g., Security Groups with `0.0.0.0/0` on port 22/3389).
  - `vulnerability_rules.py`: Maps Inspector CVE findings and outdated software versions.

### 2.5 ML Engine (`src/detection/ml/`)
- Detects subtle, novel, or multi-step behavioral anomalies that evade static rules.
- **Principles:**
  - Baseline first: **Isolation Forest**, One-Class SVM, or Local Outlier Factor.
  - Explainable: Returns anomaly scores accompanied by top contributing features/signals.
  - Model lifecycle: Modular code for preprocessing, feature selection, training, inference, and evaluation metrics.

### 2.6 Security Finding Structure (`src/common/models.py`)
- Standardized data contract emitted by both Rule Engine and ML Engine.
- Structure:
  - `finding_id`: Unique identifier (UUID).
  - `timestamp`: UTC ISO 8601 timestamp.
  - `source`: Telemetry source (e.g., `cloudtrail`, `config`, `inspector`).
  - `detection_type`: `RULE` or `ML_ANOMALY` or `HYBRID`.
  - `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - `confidence`: Float between 0.0 and 1.0.
  - `resource`: Affected cloud resource ARN/ID.
  - `identity`: Acting IAM principal or assume-role identity.
  - `description`: Human-readable summary.
  - `evidence`: Dictionary of relevant raw events, rule triggers, or top ML feature attributions.
  - `rule_id` / `model_version`: Reference to triggering rule or model.
  - `anomaly_score`: Float between 0.0 and 1.0 (for ML findings).
  - `recommended_action`: Suggested containment/remediation step.
  - `status`: `OPEN`, `IN_REVIEW`, `RESOLVED`, `FALSE_POSITIVE`.

### 2.7 Security Context & Risk Layer (`src/risk/`)
- Combines findings with environmental context:
  - Asset criticality (production vs. development, data sensitivity).
  - Identity privilege level (admin vs. service account vs. temporary role).
  - Vulnerability posture and active threat correlation.
- Produces final prioritized risk categorization: `NORMAL`, `SUSPICIOUS`, `HIGH-RISK`.

### 2.8 Response Orchestrator (`src/response/`)
- Decoupled from detection.
- Enforces strict safety controls:
  - **Safe Mode / Dry Run:** Default during all development.
  - **Human-in-the-Loop:** Requires explicit confirmation before any state-modifying AWS API call.
  - Audit logging and automated rollback preparation.

---

## 3. Separation of Concerns & Guardrails

| Detection Type | Target Scenario | Engine | Justification |
|---|---|---|---|
| **Known Vulnerabilities** | CVEs on EC2 instances | Amazon Inspector / Rule Engine | Deterministic ground truth; ML is unnecessary and error-prone |
| **Configuration Drift** | S3 bucket made public | AWS Config / Rule Engine | Binary policy violation |
| **IAM Policy Flaws** | Wildcard `*` permissions | Rule Engine | Deterministic policy analysis |
| **Compromised Credentials** | Unusual API burst from new ASN | ML Engine | Behavioral deviation with valid permissions |
| **Reconnaissance / Lateral Movement** | Discovery API sequences at 3 AM | ML Engine | Sequential anomaly across multiple services |
