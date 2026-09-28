# RAM Cloud Security — Research Dataset Strategy & Candidate Roadmap

## 1. Dataset Strategy Principles

1. **Empirical Grounding First:** Every detection layer must be evaluated on real, reproducible telemetry before performance claims are formulated.
2. **Anti-Leakage Mandate:** Datasets generated via emulation tools (e.g. Stratus, Atomic Red Team) must have their explicit tool signatures masked from ML feature extractors.
3. **No Blind Multi-Dataset Ingestion:** Datasets must not be downloaded or integrated without prior schema, labeling, and suitability verification.

---

## 2. Current Primary Dataset (Acquired & Profiled)

### Stratus Red Team CloudTrail Dataset (`invictus-ir/aws_dataset`)
- **Telemetry:** Real AWS CloudTrail audit logs (2,900 events across 29 AWS services).
- **Role in Project:**
  - Exploratory Data Analysis & baseline profiling (Phase 1.5).
  - Deterministic Rule Engine evaluation — Baseline A (Phase 2).
  - Behavioral & velocity feature extraction research (Phase 3).
  - Baseline ML anomaly detection — Baseline B (Phase 4).
  - Multi-stage temporal and identity-aware evidence fusion (Phase 5 & 6).

---

## 3. Future External Validation Candidates (Documented for Extension)

| Candidate Dataset | Telemetry Types | Attack Scenarios | Compatibility & Role in Pipeline | Recommended Decision |
|---|---|---|---|---|
| **TON-IoT** | Network NetFlow, Linux/Windows OS logs, IoT telemetry | DoS, DDoS, Ransomware, Injection, Scanning, XSS | Validates multi-modal network flow & workload extension beyond CloudTrail. High class diversity. | **Hold for Phase 9:** Benchmarks network-level anomaly detection extensions. |
| **DARPA OpTC** | Host-level process execution, registry, file, network | Multi-stage APT campaigns, lateral movement, privilege escalation | Evaluates enterprise host-level entity graph modeling and process-lineage relationships. | **Hold for Phase 9:** Benchmarks host-level graph modeling if required. |
| **CTU-SME-11** | Enterprise NetFlow, PCAP, system logs | Malware infections, lateral scanning, botnet command & control | Evaluates VPC Flow Log and network anomaly correlation. | **Hold for Phase 9:** Benchmarks network telemetry integration. |

---

## 4. Dataset Progression Pipeline

```
Primary Dataset: Stratus CloudTrail (2,900 events)
├── Phase 1.5: Complete EDA & Label Audit [COMPLETED]
├── Phase 2:   Baseline A (Rules Only) [COMPLETED]
├── Phase 3:   Feature Engineering (Behavioral/Temporal) [NEXT]
├── Phase 4:   Baseline B (ML Anomaly Only) [PLANNED]
└── Phase 5-6: Proposed Evidence Fusion Pipeline [PLANNED]
                     │
                     ▼
Future External Validation (Phase 9):
├── TON-IoT (Network Flow Extension)
└── CTU-SME-11 (VPC Flow Telemetry)
```
