# RAM Cloud Security — System Architecture Specification

## 1. End-to-End System Architecture

```
+-----------------------------------------------------------------------------------+
|                            AWS TELEMETRY SOURCES                                  |
|         AWS CloudTrail  |  AWS Config  |  VPC Flow Logs  |  Amazon Inspector      |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         INGESTION & RAW DATA LAKE                                 |
|             - Local JSON/JSONL/gzip readers & Read-Only S3 collectors             |
|             - Immutable storage under data/raw/                                   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     NORMALIZATION & OCSF INTERMEDIATE SCHEMA                      |
|                  - NormalizedEvent (timestamp, actor, source, API)                |
|                  - Payload sanitization & sensitive key redaction                 |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        PROCESSING & FEATURE PIPELINE                              |
|           - Temporal rolling windows (1m, 5m, 15m)                                |
|           - Velocity, error dynamics, cross-service dispersion                    |
+-----------------------------------------------------------------------------------+
                                         |
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
+------------------------------------+     +----------------------------------------+
|            RULE ENGINE             |     |               ML ENGINE                |
|     (Deterministic Detection)      |     |         (Behavioral Detection)         |
|  - IAM Policies (Admin, Inline)    |     |  - Unsupervised Anomaly (iForest, LOF) |
|  - Defense Evasion (StopLogging)   |     |  - API Velocity & Credential Outliers  |
|  - Exposure (0.0.0.0/0 Ingress)    |     |  - Behavioral Baseline Scoring         |
+------------------------------------+     +----------------------------------------+
                   |                                           |
                   +---------------------+---------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                   IDENTITY CONTEXT & TEMPORAL EVIDENCE FUSION                     |
|           - Correlate rule findings with ML anomaly scores per identity           |
|           - Track multi-stage attack progression over sliding timeline            |
|           - Calibrated composite risk confidence calculation                      |
+-----------------------------------------------------------------------------------+
                                         |
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
+------------------------------------+     +----------------------------------------+
|        SECURITY OPERATIONS         |     |         RESPONSE ORCHESTRATOR          |
|  - Research & Analyst Dashboard    |     |  - Alert & Notification                |
|  - Investigation Timeline          |     |  - Human Approval Workflow (Safe Mode) |
|  - Forensic Evidence Attribution   |     |  - Guardrailed Remediation & Rollback  |
+------------------------------------+     +----------------------------------------+
```

---

## 2. Component Implementation Status

| Component | Module Path | Current Status | Description |
|---|---|---|---|
| **Ingestion Engine** | `src/ingestion/cloudtrail.py` | **Implemented** | Local JSON, JSONL, gzip, and read-only S3 stream collector. |
| **Normalizer Parser** | `src/preprocessing/parser.py` | **Implemented** | CloudTrail parser into `NormalizedEvent` with sanitization. |
| **Rule Engine** | `src/detection/rules/` | **Implemented** | 11 deterministic rules (IAM, Configuration, Exposure). |
| **Feature Pipeline** | `src/features/` | Planned (Phase 3) | Behavioral, temporal velocity, and error dynamics extractors. |
| **ML Engine** | `src/detection/ml/` | Planned (Phase 4) | Isolation Forest and unsupervised anomaly models. |
| **Evidence Fusion** | `src/risk/` | Planned (Phase 6) | Multi-source context enrichment and temporal threat fusion. |
| **Response Orchestrator**| `src/response/` | Planned (Phase 8) | Policy-gated, safe dry-run response actions. |
