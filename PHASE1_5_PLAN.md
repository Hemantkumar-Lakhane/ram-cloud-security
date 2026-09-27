# RAM Cloud Security — Phase 1.5 Plan: Real Dataset Acquisition & EDA

## 1. Objective & Scope
Acquire, inspect, normalize, and profile a real, publicly available AWS CloudTrail security telemetry dataset before performing feature engineering, baseline rule development, or ML model training.

**Strict Mandate:** Synthetic fixtures in `tests/fixtures/` are strictly restricted to parser/unit tests and will NEVER be used for model training, evaluation, or research claims.

---

## 2. Dataset Selection & Evaluation Criteria

| Criterion | Requirement | Empirical Evaluation in Phase 1.5 |
|---|---|---|
| **Telemetry Alignment** | Genuine AWS CloudTrail audit logs | **Verified:** 2,900 standard CloudTrail JSON management and data events across 55 log files. |
| **Attack Realism** | Multi-stage adversarial behavior | **Verified:** Detonated using Stratus Red Team (DataDog adversary emulation framework), spanning MITRE ATT&CK tactics (Discovery, Privilege Escalation, Credential Access, Defense Evasion, Persistence). |
| **Time & Identity Fidelity** | Accurate timestamps and IAM actors | **Verified:** 55-minute continuous live AWS session with 13 distinct IAM principals and roles. |
| **Licensing & Provenance** | Clear open-source license | **Verified:** MIT License, published by Invictus Incident Response (`invictus-ir/aws_dataset`). |

---

## 3. Deliverables for Phase 1.5
- [x] Download raw data into `data/raw/stratus_cloudtrail/` without modification.
- [x] Run `CloudTrailIngestion` and `CloudTrailParser` against all 55 files (2,900 events, 0 parsing errors).
- [x] Implement EDA workflow in `experiments/eda_cloudtrail.py`.
- [x] Produce structured profiling metrics in `experiments/results/eda_summary.json`.
- [x] Create comprehensive dataset report in `docs/REAL_DATASET_REPORT.md`.
- [x] Update `DATASETS.md` and `RESEARCH_DIRECTION.md` with empirical grounding.

---

## 4. Definition of Done (DoD)
Phase 1.5 is complete when:
1. Real raw data is stored locally in `data/raw/` and tracked by `.gitignore`.
2. EDA profiling script is functional and reproducible.
3. Statistical profiling (dimensions, distributions, missing values, attack scenarios, leakage risks) is fully documented.
4. Feasible ML task definitions are established based on actual data structure.
5. All test suites pass.
