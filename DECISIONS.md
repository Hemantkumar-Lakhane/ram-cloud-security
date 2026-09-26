# RAM Cloud Security — Architectural & Research Decisions Log

## 1. Decision Framework
Every architectural, technical, or research direction decision is documented here with rationale, date, and impact.

---

## 2. Logged Decisions

### [DEC-001] AWS-First Architecture Foundation
- **Date:** 2026-09-27
- **Status:** APPROVED
- **Context:** The system needs a grounded telemetry ecosystem for research and industrial deployment.
- **Decision:** Target AWS native telemetry (CloudTrail, VPC Flow Logs, AWS Config, Amazon Inspector, CloudWatch) stored in an OCSF-aligned S3 / local data lake.
- **Consequences:** Eliminates generic abstractions; establishes real-world data schemas.

### [DEC-002] Decoupling Rule Engine from ML Engine
- **Date:** 2026-09-27
- **Status:** APPROVED
- **Context:** Certain cloud security conditions are binary/deterministic (e.g. open S3 bucket, CVE matches), whereas others are behavioral (e.g. unusual API volume, anomalous session duration).
- **Decision:** Never use ML to detect deterministic policy violations. Maintain separate `src/detection/rules/` and `src/detection/ml/` engines, merging their findings downstream via context and evidence fusion.
- **Consequences:** Prevents probabilistic guesswork for hard rules and reduces ML model false positives.

### [DEC-003] Safety Defaults for Response Orchestration
- **Date:** 2026-09-27
- **Status:** APPROVED
- **Context:** Automated remediation in cloud environments carries risks of operational outage and data loss.
- **Decision:** Default `DRY_RUN=True` and `SAFE_MODE=True`. Require explicit human approval tokens for any mutating AWS operation during development and testing.
- **Consequences:** Zero risk of unintended destructive operations in connected AWS environments.

### [DEC-004] Technology Stack Minimization
- **Date:** 2026-09-27
- **Status:** APPROVED
- **Context:** Avoid premature infrastructure complexity that obscures core ML research and detection logic.
- **Decision:** Exclude Kafka, Redis, Kubernetes, microservices, Node.js, and multi-agent LLM frameworks. Use pure Python 3.10+, `boto3`, `pandas`, `numpy`, `scikit-learn`, `pydantic`, and `pytest`.
- **Consequences:** High reproducibility, rapid test cycles, and clean experimental validity.

### [DEC-005] Research Direction Guardrails & Non-Novelty Explicit Definition
- **Date:** 2026-09-27
- **Status:** APPROVED
- **Context:** Commercial vendors and recent IEEE (2025–2026) papers already address CloudTrail GNNs, IAM graphs, attack paths, and cross-service correlation.
- **Decision:** Prohibit unverified claims of novelty regarding generic ML, GNNs, or alert correlation. Focus research on *Confidence-aware, identity-aware multi-source evidence fusion for cloud threat progression detection*.
- **Consequences:** Protects academic rigor and guides experimental benchmarking against clear baselines.

### [DEC-006] Phase 1 Scope: Security Telemetry Ingestion (CloudTrail Focus)
- **Date:** 2026-09-27
- **Status:** APPROVED
- **Context:** ML and fusion models require clean, deterministic, normalized data.
- **Decision:** Implement concrete `CloudTrailIngestion` supporting local JSON, JSONL, gzip archives, and read-only S3 log streaming, normalizing strictly into the `NormalizedEvent` schema with 100% offline test coverage.
- **Consequences:** Solidifies data foundation before starting feature extraction or model training.
