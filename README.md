# RAM Cloud Security (`ram-cloud-security`)

> **Project Title:** Development of a cloud security solution focusing on workload monitoring, identity and access security, cloud misconfiguration detection, vulnerability analysis, event monitoring, threat detection, and automated response.  
> **Target Platform:** AWS-First Cloud Security Architecture with Machine Learning Anomaly Detection.

---

## 1. Project Overview

**RAM Cloud Security** is an industry-oriented cloud security platform engineered for AWS environments. It combines deterministic rule-based security auditing with statistical and machine learning anomaly detection to deliver comprehensive workload monitoring, identity security, misconfiguration detection, and threat intelligence.

The platform processes telemetry from AWS native security and operational streams (starting with AWS CloudTrail) into a normalized data lake representation, performs feature engineering, and routes events into a **Hybrid Detection Engine**:
- **Rule Engine:** Deterministically catches known policy violations, public exposures, IAM misconfigurations, and compliance failures.
- **ML Engine:** Quantifies deviations in user/API activity, workload behavior, and network flow to detect zero-day or stealthy anomalous behavior.

Detected events are enriched with identity, asset, and vulnerability context to compute an explainable risk score before alerting security operations or triggering controlled response workflows.

---

## 2. Problem Statement

Modern cloud environments face dual security challenges:
1. **Misconfigurations & Compliance Drift:** Deterministic violations (e.g., world-readable S3 buckets, overly permissive IAM roles, disabled MFA) require immediate, deterministic rule detection without probabilistic guesswork.
2. **Behavioral Anomalies & Credential Abuse:** Compromised credentials, insider threats, and lateral movement often operate within valid permission bounds, generating valid API calls that evade static rules. These necessitate baseline-driven statistical and machine learning anomaly detection.

RAM Cloud Security bridges this gap by decoupling deterministic checks from behavioral analysis while combining their outputs into a single, unified context and risk prioritization pipeline.

---

## 3. Architecture Summary

```
AWS Telemetry Sources (CloudTrail, VPC Flow, Config, Inspector)
                           │
                           ▼
          Data Lake & Normalization Layer (S3 / OCSF)
                           │
                           ▼
          Processing & Feature Engineering Pipeline
                           │
           ┌───────────────┴───────────────┐
           ▼                               ▼
      Rule Engine                      ML Engine
  (Deterministic Checks)          (Behavioral Anomalies)
           │                               │
           └───────────────┬───────────────┘
                           ▼
          Security Context & Risk Prioritization
                           │
                           ▼
           ┌───────────────┴───────────────┐
           ▼                               ▼
   Security Operations            Response Orchestrator
   (Findings & Evidence)           (Alert / Safe Guardrails)
```

For complete technical specifications, see [ARCHITECTURE.md](file:///c:/Users/lakha/ml_ram_antivirous/ARCHITECTURE.md).

---

## 4. Current Development Status

- **Current Phase:** **PHASE 0 (Project Setup and Architecture Scaffolding Completed)**
- **Next Phase:** **PHASE 1 (Security Telemetry Ingestion - CloudTrail Focus)**

| Phase | Description | Status |
|---|---|---|
| **Phase 0** | Project Setup, Architecture Scaffolding & Foundational Contracts | **COMPLETED** |
| **Phase 1** | Security Telemetry Ingestion (AWS CloudTrail) | Planned (Next) |
| **Phase 2** | Data Storage & Normalization Layer | Planned |
| **Phase 3** | Feature Engineering Pipeline | Planned |
| **Phase 4** | Rule-Based Detection Engine | Planned |
| **Phase 5** | Machine Learning Anomaly Detection Engine | Planned |
| **Phase 6** | Hybrid Detection Integration | Planned |
| **Phase 7** | Context Enrichment & Risk Prioritization | Planned |
| **Phase 8** | Security Findings Presentation & Evidence Store | Planned |
| **Phase 9** | Controlled Response Orchestration (Safe Actions) | Planned |
| **Phase 10**| Evaluation, Benchmarking & Research Documentation | Planned |

See [PROJECT_PLAN.md](file:///c:/Users/lakha/ml_ram_antivirous/PROJECT_PLAN.md) for milestones and definitions of done.

---

## 5. Repository Structure

```
ram-cloud-security/
├── src/
│   ├── ingestion/       # Telemetry collectors (CloudTrail, CloudWatch, etc.)
│   ├── preprocessing/   # Event parsing, cleaning, and OCSF normalization
│   ├── features/        # Statistical and behavioral feature extraction
│   ├── detection/
│   │   ├── rules/       # Modular deterministic rule engine (IAM, Config, Exposure)
│   │   └── ml/          # ML anomaly detection (Isolation Forest, training, inference)
│   ├── risk/            # Asset/identity contextualization and risk scoring
│   ├── response/        # Alerting and controlled/safe response orchestrator
│   └── common/          # Shared models (SecurityFinding), configs, and logging
├── data/                # Data lake partitions (raw, processed, features) [Git-ignored]
├── experiments/         # ML experiments, notebook validation, and model benchmarks
├── tests/               # Unit, integration, and contract test suites
├── scripts/             # Operational and development utilities
├── docs/                # Architecture diagrams and technical notes
├── .env.example         # Environment template with safety flags
├── requirements.txt     # Locked production/development dependencies
├── README.md            # Project overview and index
├── PROJECT_PLAN.md      # Phased execution roadmap
├── ARCHITECTURE.md      # Approved system architecture specification
├── DATASETS.md          # Dataset evaluation strategy and criteria
└── DEVELOPMENT.md       # Developer setup and contribution guidelines
```

---

## 6. How to Run the Project

### Prerequisites
- Python 3.10+
- AWS CLI configured (optional for offline dataset processing)

### Setup
```bash
# 1. Clone or navigate to the repository
cd ram-cloud-security

# 2. Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
```

### Running Tests
```bash
pytest -v
```

For detailed developer instructions, see [DEVELOPMENT.md](file:///c:/Users/lakha/ml_ram_antivirous/DEVELOPMENT.md).
