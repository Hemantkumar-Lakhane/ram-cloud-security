# RAM Cloud Security — Project Plan & Roadmap

## 1. Plan Overview

This roadmap defines the engineering and research execution plan for **RAM Cloud Security**. The platform is constructed incrementally to ensure high scientific validity, strict separation of concerns, and robust software architecture.

---

## 2. Phase Breakdown

### Phase 0: Project Setup & Architecture Scaffolding
- **Status:** **COMPLETED**
- **Objectives:**
  - Establish Python project structure, package layouts, and workspace cleanliness.
  - Implement common domain data models (e.g. `SecurityFinding`, `NormalizedEvent`).
  - Document system architecture, dataset strategy, and developer guidelines.
  - Set up testing harness and pre-commit security standards.
- **Deliverables:**
  - Core directory scaffolding (`src/`, `data/`, `tests/`, `experiments/`).
  - Standardized configuration (`.env.example`, `.gitignore`, `requirements.txt`).
  - Core documentation (`README.md`, `PROJECT_PLAN.md`, `ARCHITECTURE.md`, `DATASETS.md`, `DEVELOPMENT.md`).
  - Common models and test suite.

---

### Phase 1: Security Telemetry Ingestion (CloudTrail Focus)
- **Status:** **COMPLETED**
- **Objectives:**
  - Build concrete ingestion collector for **AWS CloudTrail**.
  - Support local offline files (single JSON, records envelopes, JSONL, gzip archives) and read-only AWS S3 streaming.
  - Parse and normalize raw events into the universal `NormalizedEvent` contract with payload sanitization.
  - Implement 100% offline-executable unit test suite with mock data.
- **Definition of Done (DoD) - Achieved:**
  - Synthetic fixtures (`normal_event.json`, `unusual_login.json`, `privilege_escalation.json`, `sensitive_access.json`, `sample_events.jsonl`) created in `tests/fixtures/cloudtrail/`.
  - `CloudTrailIngestion` implemented in `src/ingestion/cloudtrail.py`.
  - `CloudTrailParser` implemented in `src/preprocessing/parser.py`.
  - 18/18 test suite passing with full coverage of edge cases and S3 mocks.

---

### Phase 1.5: Real Dataset Acquisition & Exploratory Data Analysis
- **Status:** **COMPLETED**
- **Objectives:**
  - Acquire real CloudTrail dataset with multi-stage attack telemetry (`invictus-ir/aws_dataset`, 2,900 events across 29 AWS services).
  - Execute automated profiling and EDA workflow (`experiments/eda_cloudtrail.py`).
  - Document class distribution, error rates, MITRE tactics, and anti-leakage guardrails (`docs/REAL_DATASET_REPORT.md`).
- **Definition of Done (DoD) - Achieved:**
  - 100% normalization parity achieved (2,900/2,900 events, 0 errors).
  - Strict leakage guardrails established (no training on raw userAgent strings).

---

### Phase 2: Deterministic Rule Baseline Engine (Baseline A: Rules Only)
- **Status:** **COMPLETED**
- **Objectives:**
  - Implement modular deterministic detection rules across IAM (`src/detection/rules/iam_rules.py`), Configuration (`src/detection/rules/configuration_rules.py`), and Exposure (`src/detection/rules/exposure_rules.py`).
  - Build `RuleEngine` registry and evaluate against the real Stratus Red Team dataset (`experiments/evaluate_rule_baseline.py`).
  - Measure quantitative baseline: findings count, TP/FP, event-level precision, recall, F1-score, detection latency, and failure modes.
  - Document findings in `docs/PHASE2_RULE_BASELINE_REPORT.md`.
- **Definition of Done (DoD) - Achieved:**
  - 11 deterministic rules implemented and 100% unit-tested (25/25 tests passing).
  - Baseline A evaluated on real data: 42 findings, Precision: 54.76%, Recall: 2.01%, F1: 0.0387, Time-to-first-alert: 6.0s.
  - Failure analysis documented: rules catch hard violations but miss 97.99% of adversarial activity (discovery, credential access, lateral movement).

---

### Phase 3: Feature Engineering Pipeline (Next Target)
- **Status:** **PLANNED (Next Target)**
- **Objectives:**
  - Extract temporal, categorical, and behavioral features from normalized event streams.
  - Compute entity baselines: API call frequency, error rate ratios, high-risk API transition probabilities, privilege change count, and temporal burst entropy.
  - Enforce anti-leakage constraints (zero raw userAgent tokens).
  - Persist ML-ready feature matrices into `data/features/`.
- **Definition of Done (DoD):**
  - Deterministic feature pipeline transforms normalized events into numeric feature vectors without data leakage.

---

### Phase 4: Rule-Based Detection Engine
- **Status:** **PLANNED**
- **Objectives:**
  - Implement deterministic detection rules across modular security domains:
    - `iam_rules.py`: Overly permissive policies (`*:*`), root account usage, privilege escalation sequences.
    - `configuration_rules.py`: Unencrypted buckets, disabled logging, insecure VPC defaults.
    - `exposure_rules.py`: Open security groups (0.0.0.0/0 on sensitive ports like 22/3389).
    - `vulnerability_rules.py`: Known CVE bindings and high-severity vulnerability markers.
  - Produce standardized `SecurityFinding` objects with rule IDs and severity levels.
- **Definition of Done (DoD):**
  - All rules have accompanying unit tests simulating matching and non-matching telemetry.

---

### Phase 5: Machine Learning Anomaly & Threat Detection
- **Status:** **PLANNED**
- **Objectives:**
  - Establish a solid baseline anomaly detection model using proven techniques:
    - Isolation Forest
    - One-Class SVM / Local Outlier Factor (LOF)
  - Implement modular ML pipeline: `preprocessing.py`, `train.py`, `inference.py`, `evaluation.py`.
  - Provide explainability for every inference output by exposing top contributing features/signals.
  - If verified labelled attack data is available, benchmark against supervised classifiers.
- **Definition of Done (DoD):**
  - Baseline model trained and evaluated with precision, recall, F1, and AUC-ROC metrics.
  - Model artifacts versioned; inference produces anomaly score and feature importance contributions.

---

### Phase 6: Hybrid Rule + ML Detection Integration
- **Status:** **PLANNED**
- **Objectives:**
  - Combine deterministic findings and ML anomaly scores into a synchronized detection pipeline.
  - Correlate rule triggers with behavioral anomalies originating from the same identity or resource within sliding time windows.
- **Definition of Done (DoD):**
  - System executes both engines concurrently and emits unified detection streams.

---

### Phase 7: Security Context & Risk Prioritization
- **Status:** **PLANNED**
- **Objectives:**
  - Aggregate identity context, asset criticality, vulnerability posture, and ML confidence.
  - Compute unified, contextual risk scores (0–100 scale: Low, Medium, High, Critical).
  - Apply risk prioritization to eliminate alert fatigue.
- **Definition of Done (DoD):**
  - Deterministic risk calculator maps compound evidence to clear risk ratings with explicit rationale.

---

### Phase 8: Dashboard & Security Findings Store
- **Status:** **PLANNED**
- **Objectives:**
  - Implement storage and query interfaces for security findings and evidence artifacts.
  - Provide lightweight operational views/APIs for security analyst inspection.
- **Definition of Done (DoD):**
  - Findings can be queried by resource, identity, severity, detection type, and time window.

---

### Phase 9: Controlled Response Orchestration
- **Status:** **PLANNED**
- **Objectives:**
  - Implement safety-first response action framework (Notification, Quarantine, Credential Revocation).
  - Default to **Dry Run / Human Approval** modes; no automatic destructive actions during development.
  - Require explicit audit trails, safety checks, and rollback plans for all response actions.
- **Definition of Done (DoD):**
  - Dry-run verification passes; safety guardrails prevent execution without human confirmation.

---

### Phase 10: Evaluation, Experiments & Research Documentation
- **Status:** **PLANNED**
- **Objectives:**
  - Rigorously benchmark the hybrid detection architecture against security datasets (e.g. DataDog Grimoire).
  - Document comparative performance metrics (false positive rates, detection latency, anomaly sensitivity).
  - Compile final research report and operational security playbooks.
- **Definition of Done (DoD):**
  - Complete experimental documentation with reproducible training and evaluation scripts.
