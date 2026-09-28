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

- **Current Phase:** **PHASE 2 (Deterministic Rule Baseline Experiment — Baseline A Completed)**
- **Next Phase:** **PHASE 3 (Feature Engineering Pipeline)**

| Phase | Description | Status |
|---|---|---|
| **Phase 0** | Project Setup, Architecture Scaffolding & Foundational Contracts | **COMPLETED** |
| **Phase 1** | Security Telemetry Ingestion (AWS CloudTrail) | **COMPLETED** |
| **Phase 1.5** | Real Dataset Acquisition & Exploratory Data Analysis | **COMPLETED** |
| **Phase 2** | Deterministic Rule Baseline Engine (Baseline A: Rules Only) | **COMPLETED** |
| **Phase 3** | Feature Engineering Pipeline (Behavioral & Temporal Signals) | Planned (Next) |
| **Phase 4** | Machine Learning Anomaly Detection Engine (Baseline B: ML Only)| Planned |
| **Phase 5** | Hybrid Detection Integration (Rules + ML) | Planned |
| **Phase 6** | Identity Context, Temporal Reasoning & Evidence Fusion | Planned |
| **Phase 7** | Security Operations & Findings Dashboard | Planned |
| **Phase 8** | Controlled & Safe Response Orchestration | Planned |
| **Phase 9** | Research Evaluation & Benchmarks | Planned |
| **Phase 10**| Final Research Documentation & Demonstration | Planned |

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

### Running the Backend Tests
```bash
pytest -v
```

### Running the Frontend Console (React + TypeScript + Vite)
```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install dependencies (if not already installed)
npm install

# 3. Start local development server
npm run dev
# Live at: http://localhost:5173/

# 4. Build for production
npm run build
```

For complete technical documentation, UI design systems, and data contracts, see:
- [UI_SPECIFICATION.md](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_SPECIFICATION.md) — Master UI/UX Design Index
- [UI_INFORMATION_ARCHITECTURE.md](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_INFORMATION_ARCHITECTURE.md) — 7-Domain Route Map & Navigation
- [UI_DATA_CONTRACTS.md](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_DATA_CONTRACTS.md) — Real Telemetry & Metric Bindings
- [DEVELOPMENT.md](file:///c:/Users/lakha/ml_ram_antivirous/DEVELOPMENT.md) — Detailed developer setup guide.
